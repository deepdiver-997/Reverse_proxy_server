#include "quic_demux.h"
#include "quic_transport.h"
#include <spdlog/spdlog.h>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>

namespace ebpf_quic_proxy {

// ── shared helpers ────────────────────────────────────────

void to_sockaddr(const asio::ip::udp::endpoint& ep,
                 struct sockaddr_storage* sa) {
    std::memset(sa, 0, sizeof(*sa));
    if (ep.address().is_v4()) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(sa);
        sin->sin_family = AF_INET;
        sin->sin_port   = htons(ep.port());
        auto bytes = ep.address().to_v4().to_bytes();
        std::memcpy(&sin->sin_addr, bytes.data(), 4);
    } else {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(sa);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port   = htons(ep.port());
        auto bytes = ep.address().to_v6().to_bytes();
        std::memcpy(&sin6->sin6_addr, bytes.data(), 16);
    }
}

unsigned send_specs(int fd, const lsquic_out_spec* specs, unsigned count,
                    bool* blocked) {
    unsigned sent = 0;
    *blocked = false;
    for (unsigned i = 0; i < count; ++i) {
        const auto& spec = specs[i];
        // sendmsg (scatter-gather): all iovs in this spec go out as a single
        // UDP datagram, matching lsquic's expectation.
        struct msghdr hdr = {};
        hdr.msg_name    = const_cast<struct sockaddr*>(spec.dest_sa);
        hdr.msg_namelen = spec.dest_sa->sa_family == AF_INET
                              ? sizeof(struct sockaddr_in)
                              : sizeof(struct sockaddr_in6);
        hdr.msg_iov     = const_cast<struct iovec*>(spec.iov);
        hdr.msg_iovlen  = spec.iovlen;

        ssize_t n = sendmsg(fd, &hdr, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                spdlog::debug("QUIC sendmsg would block — will retry on writable");
                *blocked = true;
            } else {
                spdlog::debug("QUIC sendmsg failed: {} (errno={})",
                              strerror(errno), errno);
            }
        } else {
            ++sent;
        }
    }
    return sent;
}

std::string cid_key(const lsquic_cid_t* cid) {
    return std::string(reinterpret_cast<const char*>(cid->buf), cid->len);
}

// ── QuicPacketDemux ───────────────────────────────────────

QuicPacketDemux::QuicPacketDemux(asio::io_context& io, uint16_t port)
    : io_(io), socket_(io) {
    socket_.open(asio::ip::udp::v4());
    int on = 1;
    ::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on));
    socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port));
    raw_fd_ = socket_.native_handle();
    to_sockaddr(socket_.local_endpoint(), &local_sa_);
    spdlog::info("QUIC demux socket bound on port {}", port);
}

QuicPacketDemux::~QuicPacketDemux() = default;

int QuicPacketDemux::add_worker(asio::io_context& worker_io,
                                QuicServerEngine* engine) {
    int idx = static_cast<int>(workers_.size());
    workers_.push_back({&worker_io, engine});
    return idx;
}

void QuicPacketDemux::start() { do_recv(); }

void QuicPacketDemux::stop() {
    // Cancels the pending async_receive_from / async_wait; on_packet sees
    // operation_aborted and does not re-arm (already handled there).
    socket_.cancel();
}

void QuicPacketDemux::register_cid(const std::string& key, int worker_idx) {
    std::lock_guard lock(cid_mu_);
    cid_to_worker_[key] = worker_idx;
}

void QuicPacketDemux::remove_cid(const std::string& key) {
    std::lock_guard lock(cid_mu_);
    cid_to_worker_.erase(key);
}

void QuicPacketDemux::notify_tx_blocked() {
    // Called from a worker thread; the write-watch must be armed on the
    // demux's own io_context thread.
    asio::post(io_, [this] { arm_send_retry(); });
}

int QuicPacketDemux::route(const unsigned char* buf, std::size_t len,
                           const std::string& src_addr) {
    if (workers_.empty())
        return -1;
    uint8_t cid_len = 0;
    int off = lsquic_dcid_from_packet(buf, len, kServerCidLen, &cid_len);
    if (off < 0 || cid_len == 0) {
        // Version-negotiation / unparseable packet — drop.
        spdlog::debug("QUIC demux: {}B from {} — unparseable DCID, drop", len,
                      src_addr);
        return -1;
    }
    std::string key(reinterpret_cast<const char*>(buf + off), cid_len);

    {
        std::lock_guard lock(cid_mu_);
        auto it = cid_to_worker_.find(key);
        if (it != cid_to_worker_.end()) {
            spdlog::debug("QUIC demux: {}B CID(known) -> worker {}", len,
                          it->second);
            return it->second;
        }
    }

    // New connection: the DCID is client-chosen and unknown.  Hash the source
    // address.  Retransmitted Initial packets keep the same source, so they
    // land on the same worker; once the engine issues its SCID (ea_new_scids),
    // subsequent packets route by that SCID instead.
    uint64_t h = 0xcbf29ce484222325ull; // FNV-1a
    for (char c : src_addr) {
        h ^= static_cast<uint8_t>(c);
        h *= 0x100000001b3ull;
    }
    int w = static_cast<int>(h % static_cast<uint64_t>(workers_.size()));
    spdlog::debug("QUIC demux: {}B CID(new, len {}) -> hash worker {}", len,
                  cid_len, w);
    return w;
}

void QuicPacketDemux::do_recv() {
    socket_.async_receive_from(
        asio::buffer(recv_buf_), recv_endpoint_,
        [this](asio::error_code ec, std::size_t n) { on_packet(ec, n); });
}

void QuicPacketDemux::on_packet(asio::error_code ec, std::size_t n) {
    if (ec) {
        if (ec == asio::error::operation_aborted)
            return; // shutdown — do not re-arm
        spdlog::warn("QUIC demux UDP recv error: {} — re-arming",
                     ec.message());
        if (socket_.is_open())
            do_recv();
        return;
    }

    const int w = route(reinterpret_cast<const unsigned char*>(recv_buf_.data()),
                        n, recv_endpoint_.address().to_string());
    if (w < 0 || w >= static_cast<int>(workers_.size())) {
        do_recv();
        return;
    }

    // Copy the packet: the demux recv buffer is reused by the next datagram,
    // and the posted handler runs later on another thread.
    const auto* raw = reinterpret_cast<const unsigned char*>(recv_buf_.data());
    auto pkt = std::make_shared<std::vector<unsigned char>>(raw, raw + n);
    struct sockaddr_storage peer_sa;
    to_sockaddr(recv_endpoint_, &peer_sa);
    const struct sockaddr_storage local_sa = local_sa_;

    QuicServerEngine* engine = workers_[w].engine;
    asio::io_context& worker_io = *workers_[w].io;
    asio::post(worker_io, [engine, pkt, local_sa, peer_sa]() {
        engine->deliver_packet(pkt->data(), pkt->size(), local_sa, peer_sa);
    });

    do_recv();
}

void QuicPacketDemux::arm_send_retry() {
    if (send_retry_armed_ || !socket_.is_open())
        return;
    send_retry_armed_ = true;
    socket_.async_wait(
        asio::ip::udp::socket::wait_write,
        [this](asio::error_code ec) {
            send_retry_armed_ = false;
            if (ec)
                return;
            // Socket drained — have each worker flush its unsent packets.  The
            // engines are not thread-safe, so post to their owning threads.
            for (const auto& w : workers_) {
                QuicServerEngine* engine = w.engine;
                asio::io_context* worker_io = w.io;
                asio::post(*worker_io, [engine] {
                    engine->flush_unsent_packets();
                });
            }
            // If a flush hit EAGAIN again, that worker's on_packets_out calls
            // notify_tx_blocked() again, re-arming this watch.
        });
}

} // namespace ebpf_quic_proxy
