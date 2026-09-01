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

unsigned send_specs(int fd_v4, int fd_v6, const lsquic_out_spec* specs,
                    unsigned count, bool* blocked) {
    unsigned sent = 0;
    *blocked = false;
    for (unsigned i = 0; i < count; ++i) {
        const auto& spec = specs[i];
        // Pick the fd by the destination's family (a v4 socket can't send to
        // a v6 address).  A batch may mix families (different connections).
        const int fd = spec.dest_sa->sa_family == AF_INET ? fd_v4 : fd_v6;
        if (fd < 0) // family not available — leave the spec unsent
            continue;

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

QuicPacketDemux::QuicPacketDemux(asio::io_context& io, uint16_t port,
                                 bool dual_stack)
    : io_(io), socket_(io), socket6_(io) {
    socket_.open(asio::ip::udp::v4());
    int on = 1;
    ::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on));
    socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port));
    raw_fd_ = socket_.native_handle();
    to_sockaddr(socket_.local_endpoint(), &local_sa_);
    spdlog::info("QUIC demux socket bound on port {} (v4)", port);

    if (dual_stack) {
        // Second socket on the same port for IPv6.  V6ONLY=1 (default) — the
        // v4 socket already owns v4, so the v6 socket must never see
        // v4-mapped addresses (they'd confuse lsquic's source identity).
        asio::error_code ec;
        socket6_.open(asio::ip::udp::v6(), ec);
        if (!ec)
            socket6_.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), port),
                          ec);
        if (ec) {
            spdlog::warn("dual_stack: IPv6 QUIC bind failed ({}: {}) — "
                         "QUIC is IPv4-only; v6 clients will not connect",
                         ec.value(), ec.message());
            socket6_.close();
        } else {
            raw6_fd_ = socket6_.native_handle();
            to_sockaddr(socket6_.local_endpoint(), &local6_sa_);
            spdlog::info("QUIC demux socket bound on port {} (v6)", port);
        }
    }
}

QuicPacketDemux::~QuicPacketDemux() = default;

int QuicPacketDemux::add_worker(asio::io_context& worker_io,
                                QuicServerEngine* engine) {
    int idx = static_cast<int>(workers_.size());
    workers_.push_back({&worker_io, engine});
    return idx;
}

void QuicPacketDemux::start() {
    do_recv();
    if (socket6_.is_open())
        do_recv6();
}

void QuicPacketDemux::stop() {
    // Cancels the pending async_receive_from / async_wait; on_packet sees
    // operation_aborted and does not re-arm (already handled there).
    socket_.cancel();
    if (socket6_.is_open())
        socket6_.cancel();
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
        [this](asio::error_code ec, std::size_t n) {
            on_packet(ec, n, local_sa_);
        });
}

void QuicPacketDemux::do_recv6() {
    socket6_.async_receive_from(
        asio::buffer(recv6_buf_), recv6_endpoint_,
        [this](asio::error_code ec, std::size_t n) {
            on_packet(ec, n, local6_sa_);
        });
}

void QuicPacketDemux::on_packet(asio::error_code ec, std::size_t n,
                                const struct sockaddr_storage& local_sa) {
    const bool is_v6 = (local_sa.ss_family == AF_INET6);
    auto& socket = is_v6 ? socket6_ : socket_;
    auto& recv_buf = is_v6 ? recv6_buf_ : recv_buf_;
    auto& recv_ep = is_v6 ? recv6_endpoint_ : recv_endpoint_;

    if (ec) {
        if (ec == asio::error::operation_aborted)
            return; // shutdown — do not re-arm
        spdlog::warn("QUIC demux UDP recv error: {} — re-arming",
                     ec.message());
        if (socket.is_open()) {
            if (is_v6)
                do_recv6();
            else
                do_recv();
        }
        return;
    }

    const int w = route(reinterpret_cast<const unsigned char*>(recv_buf.data()),
                        n, recv_ep.address().to_string());
    if (w < 0 || w >= static_cast<int>(workers_.size())) {
        if (is_v6)
            do_recv6();
        else
            do_recv();
        return;
    }

    // Copy the packet: the demux recv buffer is reused by the next datagram,
    // and the posted handler runs later on another thread.
    const auto* raw = reinterpret_cast<const unsigned char*>(recv_buf.data());
    auto pkt = std::make_shared<std::vector<unsigned char>>(raw, raw + n);
    struct sockaddr_storage peer_sa;
    to_sockaddr(recv_ep, &peer_sa);
    const struct sockaddr_storage local = local_sa;

    QuicServerEngine* engine = workers_[w].engine;
    asio::io_context& worker_io = *workers_[w].io;
    asio::post(worker_io, [engine, pkt, local, peer_sa]() {
        engine->deliver_packet(pkt->data(), pkt->size(), local, peer_sa);
    });

    if (is_v6)
        do_recv6();
    else
        do_recv();
}

void QuicPacketDemux::arm_send_retry() {
    // Arm whichever socket(s) exist.  A blocked batch can't easily report which
    // family it blocked on, and EAGAIN is rare + self-correcting (a flush that
    // still fails re-arms via notify_tx_blocked), so arming both is fine.
    arm_write_watch(socket_, send_retry_armed_);
    if (socket6_.is_open())
        arm_write_watch(socket6_, send_retry6_armed_);
}

void QuicPacketDemux::arm_write_watch(asio::ip::udp::socket& s, bool& armed) {
    if (armed || !s.is_open())
        return;
    armed = true;
    s.async_wait(
        asio::ip::udp::socket::wait_write,
        [this, &s, &armed](asio::error_code ec) {
            armed = false;
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
