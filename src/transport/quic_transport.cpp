#include "quic_transport.h"
#include <spdlog/spdlog.h>
#include <cstring>
#include <sstream>

namespace ebpf_quic_proxy {

// ═══════════════════════════════════════════════════════════
// QuicTransportStream
// ═══════════════════════════════════════════════════════════

QuicTransportStream::QuicTransportStream(lsquic_stream_t* stream)
    : stream_(stream) {
    std::ostringstream oss;
    oss << "quic:" << lsquic_stream_id(stream);
    id_ = oss.str();
    // Store ourselves as stream context so callbacks can find us.
    lsquic_stream_set_ctx(
        stream_, reinterpret_cast<lsquic_stream_ctx_t*>(this));
}

QuicTransportStream::~QuicTransportStream() {
    if (stream_)
        lsquic_stream_set_ctx(stream_, nullptr);
}

void QuicTransportStream::async_read_some(asio::mutable_buffer buf,
                                           ReadCallback cb) {
    read_buf_ = buf;
    read_cb_ = std::move(cb);
    lsquic_stream_wantread(stream_, 1);
}

void QuicTransportStream::async_write_some(asio::const_buffer buf,
                                            WriteCallback cb) {
    auto data = std::make_shared<std::vector<char>>(
        static_cast<const char*>(buf.data()),
        static_cast<const char*>(buf.data()) + buf.size());
    write_queue_.push({std::move(data), std::move(cb)});
    pump_write();
}

void QuicTransportStream::async_shutdown(ShutdownCallback cb) {
    shutdown_cb_ = std::move(cb);
    int r = lsquic_stream_shutdown(stream_, 1); // SHUT_WR
    if (r == 0) {
        // Already shut down or will complete asynchronously.
        if (shutdown_cb_) {
            auto cb = std::move(shutdown_cb_);
            cb({});
        }
    }
    // If r != 0, the close callback will fire later.
}

std::string QuicTransportStream::stream_id() const { return id_; }

void QuicTransportStream::on_readable() {
    if (!read_cb_)
        return;

    auto* buf_ptr = static_cast<unsigned char*>(read_buf_.data());
    std::size_t buf_sz = read_buf_.size();
    ssize_t n = lsquic_stream_read(stream_, buf_ptr, buf_sz);
    lsquic_stream_wantread(stream_, 0);

    if (n >= 0) {
        auto cb = std::move(read_cb_);
        cb({}, static_cast<std::size_t>(n));
    } else if (n == -1) {
        // Error — treat as EOF for now.
        auto cb = std::move(read_cb_);
        cb(asio::error::eof, 0);
    }
    // n == -2 means no data yet (shouldn't happen if wantread signalled).
}

void QuicTransportStream::on_writeable() {
    writing_ = false;
    pump_write();
}

void QuicTransportStream::on_close() {
    // Fire pending callbacks with errors so they don't hang.
    if (read_cb_) {
        auto cb = std::move(read_cb_);
        cb(asio::error::eof, 0);
    }
    while (!write_queue_.empty()) {
        auto& op = write_queue_.front();
        op.cb(asio::error::eof, 0);
        write_queue_.pop();
    }
    if (shutdown_cb_) {
        auto cb = std::move(shutdown_cb_);
        cb({});
    }
    stream_ = nullptr;
}

void QuicTransportStream::pump_write() {
    if (writing_ || write_queue_.empty())
        return;

    auto& op = write_queue_.front();
    ssize_t n = lsquic_stream_write(
        stream_, reinterpret_cast<const unsigned char*>(op.data->data()),
        op.data->size());

    if (n >= 0) {
        auto cb = std::move(op.cb);
        write_queue_.pop();
        cb({}, static_cast<std::size_t>(n));
        // If more pending, will be pumped by on_writeable.
    } else if (n == -1) {
        // Error
        auto cb = std::move(op.cb);
        write_queue_.pop();
        cb(asio::error::eof, 0);
    } else {
        // n == -2: would block → enable write notification.
        writing_ = true;
        lsquic_stream_wantwrite(stream_, 1);
    }
}

// ═══════════════════════════════════════════════════════════
// QuicTransportSession
// ═══════════════════════════════════════════════════════════

QuicTransportSession::QuicTransportSession(lsquic_conn_t* conn,
                                           std::string remote_addr)
    : conn_(conn), remote_addr_(std::move(remote_addr)) {
    // Store ourselves as conn_ctx.
    lsquic_conn_set_ctx(
        conn_, reinterpret_cast<lsquic_conn_ctx_t*>(this));
}

QuicTransportSession::~QuicTransportSession() {
    if (conn_)
        lsquic_conn_set_ctx(conn_, nullptr);
}

void QuicTransportSession::set_new_stream_cb(NewStreamCallback cb) {
    new_stream_cb_ = std::move(cb);
}

ITransportStreamPtr QuicTransportSession::open_stream() {
    // lsquic_conn_make_stream() is asynchronous — the new stream arrives
    // via on_new_stream callback.  For Phase 2, return nullptr and
    // let the caller use set_new_stream_cb instead.
    //
    // TODO Phase 2+: implement a promise/future to bridge the async gap.
    if (conn_)
        lsquic_conn_make_stream(conn_);
    return nullptr;
}

void QuicTransportSession::close() {
    if (conn_ && !closed_) {
        closed_ = true;
        lsquic_conn_close(conn_);
    }
}

std::string QuicTransportSession::remote_addr() const { return remote_addr_; }

void QuicTransportSession::on_new_stream(lsquic_stream_t* lsquic_stream) {
    if (new_stream_cb_) {
        auto stream = std::make_shared<QuicTransportStream>(lsquic_stream);
        new_stream_cb_(std::move(stream));
    }
}

void QuicTransportSession::on_closed() {
    closed_ = true;
    conn_ = nullptr;
}

// ═══════════════════════════════════════════════════════════
// QuicTransportListener
// ═══════════════════════════════════════════════════════════

QuicTransportListener::QuicTransportListener(asio::io_context& io,
                                             uint16_t port,
                                             const std::string& cert_file,
                                             const std::string& key_file)
    : io_(io),
      socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)),
      tick_timer_(io) {

    // ── Build lsquic engine ───────────────────────────────
    struct lsquic_engine_api api = {};
    api.ea_packets_out     = on_packets_out_cb;
    api.ea_packets_out_ctx = this;

    // Stream callbacks.
    static struct lsquic_stream_if stream_if = {
        .on_new_conn    = on_new_conn_cb,
        .on_conn_closed = on_conn_closed_cb,
        .on_new_stream  = on_new_stream_cb,
        .on_read        = on_read_cb,
        .on_write       = on_write_cb,
        .on_close       = on_close_cb,
    };
    api.ea_stream_if     = &stream_if;
    api.ea_stream_if_ctx = this;

    // Server mode.
    unsigned flags = LSENG_SERVER;

    engine_ = lsquic_engine_new(flags, &api);
    if (!engine_)
        throw std::runtime_error("Failed to create lsquic engine");

    spdlog::info("QUIC listener created on port {}", port);
    // TODO: load cert/key for TLS.
    (void)cert_file;
    (void)key_file;
}

QuicTransportListener::~QuicTransportListener() {
    if (engine_) {
        lsquic_engine_destroy(engine_);
        engine_ = nullptr;
    }
}

void QuicTransportListener::set_new_session_cb(NewSessionCallback cb) {
    new_session_cb_ = std::move(cb);
}

void QuicTransportListener::start() {
    do_recv();
    schedule_tick();
}

// ── UDP receive loop ──────────────────────────────────────

void QuicTransportListener::do_recv() {
    socket_.async_receive_from(
        asio::buffer(recv_buf_), recv_endpoint_,
        [this](asio::error_code ec, std::size_t n) { on_packet(ec, n); });
}

void QuicTransportListener::on_packet(asio::error_code ec, std::size_t n) {
    if (ec) {
        spdlog::error("QUIC UDP recv error: {}", ec.message());
        return;
    }

    // Feed to lsquic.
    struct sockaddr_storage local_sa = {};
    struct sockaddr_storage peer_sa = {};
    // Build sockaddr from endpoints (simplified — works for IPv4).
    auto local_ep = socket_.local_endpoint();
    auto local_addr = local_ep.address().to_v4().to_uint();
    auto peer_addr = recv_endpoint_.address().to_v4().to_uint();
    auto* lsa = reinterpret_cast<struct sockaddr_in*>(&local_sa);
    auto* psa = reinterpret_cast<struct sockaddr_in*>(&peer_sa);
    lsa->sin_family = AF_INET;
    lsa->sin_port   = htons(local_ep.port());
    lsa->sin_addr.s_addr = htonl(local_addr);
    psa->sin_family = AF_INET;
    psa->sin_port   = htons(recv_endpoint_.port());
    psa->sin_addr.s_addr = htonl(peer_addr);

    int r = lsquic_engine_packet_in(
        engine_, reinterpret_cast<const unsigned char*>(recv_buf_.data()), n,
        reinterpret_cast<const struct sockaddr*>(&local_sa),
        reinterpret_cast<const struct sockaddr*>(&peer_sa),
        this, // conn_ctx for new connections
        0     // ecn
    );

    if (r < 0) {
        spdlog::warn("lsquic_engine_packet_in returned {}", r);
    }

    // Continue receiving.
    do_recv();
}

// ── Tick timer ────────────────────────────────────────────

void QuicTransportListener::schedule_tick() {
    int diff = 0;
    unsigned next = lsquic_engine_earliest_adv_tick(engine_, &diff);
    if (diff < 0) {
        // Immediate processing needed.
        tick_timer_.expires_after(std::chrono::milliseconds(0));
    } else if (next == 0 || (unsigned)diff > 500) {
        // No active connections or far future.
        tick_timer_.expires_after(std::chrono::milliseconds(500));
    } else {
        tick_timer_.expires_after(std::chrono::milliseconds(diff));
    }
    tick_timer_.async_wait([this](asio::error_code ec) { on_tick(ec); });
}

void QuicTransportListener::on_tick(asio::error_code ec) {
    if (ec)
        return;
    lsquic_engine_process_conns(engine_);
    schedule_tick();
}

// ── lsquic callbacks ──────────────────────────────────────

lsquic_conn_ctx_t*
QuicTransportListener::on_new_conn_cb(void* self, lsquic_conn_t* conn) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    char buf[INET6_ADDRSTRLEN] = {};
    const struct sockaddr *local, *peer;
    lsquic_conn_get_sockaddr(conn, &local, &peer);
    if (peer && peer->sa_family == AF_INET) {
        auto* sin = reinterpret_cast<const struct sockaddr_in*>(peer);
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    }
    std::string addr = buf[0] ? buf : "unknown";

    auto session = std::make_shared<QuicTransportSession>(conn, addr);
    auto* ctx = reinterpret_cast<lsquic_conn_ctx_t*>(session.get());
    listener->sessions_[ctx] = std::move(session);

    // Notify ProxyCore.
    if (listener->new_session_cb_)
        listener->new_session_cb_(listener->sessions_[ctx]);

    return ctx;
}

void QuicTransportListener::on_conn_closed_cb(lsquic_conn_t* conn) {
    auto* ctx = lsquic_conn_get_ctx(conn);
    if (!ctx)
        return;
    // We don't have a direct reference to the listener here.
    // The session will clean itself up.
    auto* session = reinterpret_cast<QuicTransportSession*>(ctx);
    session->on_closed();
}

lsquic_stream_ctx_t*
QuicTransportListener::on_new_stream_cb(void* self, lsquic_stream_t* stream) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    auto* conn = lsquic_stream_conn(stream);
    auto* session = listener->find_session(conn);
    if (session) {
        session->on_new_stream(stream);
        // Stream context is stored inside QuicTransportStream constructor.
        auto* ctx = lsquic_stream_get_ctx(stream);
        return reinterpret_cast<lsquic_stream_ctx_t*>(ctx);
    }
    return nullptr;
}

void QuicTransportListener::on_read_cb(lsquic_stream_t* stream,
                                        lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_readable();
}

void QuicTransportListener::on_write_cb(lsquic_stream_t* stream,
                                         lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_writeable();
}

void QuicTransportListener::on_close_cb(lsquic_stream_t* stream,
                                         lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_close();
}

int QuicTransportListener::on_packets_out_cb(void* self,
                                              const lsquic_out_spec* specs,
                                              unsigned count) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    for (unsigned i = 0; i < count; ++i) {
        auto& spec = specs[i];
        asio::ip::udp::endpoint dest;
        if (spec.dest_sa->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<const struct sockaddr_in*>(spec.dest_sa);
            dest.address(asio::ip::make_address_v4(ntohl(sin->sin_addr.s_addr)));
            dest.port(ntohs(sin->sin_port));
        }
        // Fire-and-forget: QUIC handles retransmission itself.
        // Each out_spec carries data in an iovec array.
        for (unsigned j = 0; j < spec.iovlen; ++j) {
            listener->socket_.async_send_to(
                asio::buffer(spec.iov[j].iov_base, spec.iov[j].iov_len),
                dest, [](asio::error_code, std::size_t) {});
        }
    }
    return 0;
}

// ── Lookup helpers ────────────────────────────────────────

QuicTransportSession*
QuicTransportListener::find_session(lsquic_conn_t* conn) {
    auto* ctx = lsquic_conn_get_ctx(conn);
    if (!ctx)
        return nullptr;
    auto it = sessions_.find(ctx);
    if (it != sessions_.end())
        return it->second.get();
    return nullptr;
}

QuicTransportStream*
QuicTransportListener::find_stream(lsquic_stream_t* stream) {
    auto* ctx = lsquic_stream_get_ctx(stream);
    return reinterpret_cast<QuicTransportStream*>(ctx);
}

} // namespace ebpf_quic_proxy
