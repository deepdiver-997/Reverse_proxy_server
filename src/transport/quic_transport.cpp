#include "quic_transport.h"
extern "C" {
#include <openssl/pem.h>
#include <openssl/ssl.h>
}
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>
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
    // Stream may already be closed (on_close fired) — fail fast rather than
    // deref the nulled handle.
    if (!stream_) {
        cb(asio::error::eof, 0);
        return;
    }
    read_buf_ = buf;
    read_cb_ = std::move(cb);
    lsquic_stream_wantread(stream_, 1);
}

void QuicTransportStream::async_write_some(asio::const_buffer buf,
                                            WriteCallback cb) {
    auto data = std::make_shared<std::vector<char>>(
        static_cast<const char*>(buf.data()),
        static_cast<const char*>(buf.data()) + buf.size());
    write_queue_.push({std::move(data), /*offset=*/0, std::move(cb)});
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
    // HTTP/3 (ADR-8): a pending header take has priority — the decoded header
    // set must be claimed (lsquic_stream_get_hset) before any body read.
    if (headers_cb_) {
        try_take_headers();
        return;
    }
    if (!read_cb_)
        return;

    auto* buf_ptr = static_cast<unsigned char*>(read_buf_.data());
    std::size_t buf_sz = read_buf_.size();
    ssize_t n = lsquic_stream_read(stream_, buf_ptr, buf_sz);
    lsquic_stream_wantread(stream_, 0);

    if (n >= 0) {
        // n == 0 means EOF (per lsquic_stream_read contract).
        auto cb = std::move(read_cb_);
        cb({}, static_cast<std::size_t>(n));
    } else if (n == -1) {
        // -1 carries the reason in errno.  Disambiguate so we don't report
        // "no data yet" or "peer reset" as a clean EOF.
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // No data actually available (wantread was a false alarm).
            // Keep the callback pending and re-arm.
            lsquic_stream_wantread(stream_, 1);
            return;
        }
        auto cb = std::move(read_cb_);
        if (errno == ECONNRESET)
            cb(asio::error::connection_reset, 0);
        else
            cb(asio::error::eof, 0);
    }
}

bool QuicTransportStream::async_take_headers(HeadersCallback cb) {
    if (!stream_ || headers_cb_)
        return false;
    headers_cb_ = std::move(cb);
    lsquic_stream_wantread(stream_, 1);
    try_take_headers(); // headers may already be decoded
    return true;
}

void QuicTransportStream::try_take_headers() {
    if (!headers_cb_ || !stream_)
        return;
    void* hset = lsquic_stream_get_hset(stream_);
    if (!hset)
        return; // not decoded yet — on_read will fire again
    auto* hs = static_cast<QuicH3HeaderSet*>(hset);

    // Hand the raw decoded header list to the codec (H3Codec interprets it
    // into request or response IR).  The header set is ours to free.
    HeaderList raw = std::move(hs->headers);
    delete hs;

    auto cb = std::move(headers_cb_);
    headers_cb_ = nullptr;
    cb({}, std::move(raw));
}

bool QuicTransportStream::async_send_headers(const HeaderList& headers,
                                             WriteCallback cb) {
    if (!stream_) {
        cb(asio::error::eof, 0);
        return false;
    }
    std::size_t total = 0;
    for (const auto& [k, v] : headers)
        total += k.size() + v.size();
    if (total > 64 * 1024) { // lsxpack limits a header block to 64 KB
        spdlog::warn("QUIC: header block too large ({} bytes)", total);
        cb(asio::error::message_size, 0);
        return true;
    }

    // Build name/value bytes + lsxpack_header array pointing into them.
    // HTTP/3 (RFC 9114 §4.2) mandates lowercase header field names.
    std::vector<char> name_vals;
    name_vals.reserve(total);
    std::vector<lsxpack_header> arr(headers.empty() ? 1 : headers.size());
    std::size_t off = 0;
    for (std::size_t i = 0; i < headers.size(); ++i) {
        const auto& [k, v] = headers[i];
        std::string lname(k);
        std::transform(lname.begin(), lname.end(), lname.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        name_vals.insert(name_vals.end(), lname.begin(), lname.end());
        name_vals.insert(name_vals.end(), v.begin(), v.end());
        lsxpack_header_set_offset2(&arr[i], name_vals.data(), off, lname.size(),
                                   off + lname.size(), v.size());
        off += lname.size() + v.size();
    }

    lsquic_http_headers_t hs = {
        .count   = static_cast<int>(headers.size()),
        .headers = arr.data(),
    };
    // send_headers encodes synchronously into the stream; the arrays only
    // need to outlive this call.  Flush afterwards: for a headers-only message
    // (e.g. a GET with no body, or a response with none) nothing else triggers
    // transmission — without this, the request never reaches the peer.
    int r = lsquic_stream_send_headers(stream_, &hs, 0);
    if (r == 0) {
        lsquic_stream_flush(stream_);
        cb({}, 0);
    } else {
        cb(asio::error::eof, 0);
    }
    return true;
}

void QuicTransportStream::on_writeable() {
    writing_ = false;
    pump_write();
}

void QuicTransportStream::on_close() {
    // Null the handle first: any async op re-entered from the EOF callbacks
    // below sees a closed stream and flushes immediately instead of touching
    // lsquic on a stream it is tearing down.
    stream_ = nullptr;
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
    writing_ = false;
    // Drop self-ownership.  The caller (on_close_cb) holds a keep-alive copy,
    // so the wrapper is destroyed only after this callback returns — which is
    // exactly when lsquic finishes with the stream.
    release_self();
}

void QuicTransportStream::on_reset(int how) {
    spdlog::debug("QUIC stream {} reset (how={})", id_, how);
    // The peer reset one or both directions.  Unblock any pending operations
    // so they don't hang waiting for on_close() (which follows later).
    if (how == 0 || how == 2) { // read side reset
        if (read_cb_) {
            auto cb = std::move(read_cb_);
            cb(asio::error::connection_reset, 0);
        }
    }
    if (how == 1 || how == 2) { // write side reset
        while (!write_queue_.empty()) {
            auto& op = write_queue_.front();
            op.cb(asio::error::connection_reset, 0);
            write_queue_.pop();
        }
        writing_ = false;
    }
}

void QuicTransportStream::pump_write() {
    // Stream may have been closed before we got here.
    if (!stream_) {
        // Flush pending callbacks with EOF.
        while (!write_queue_.empty()) {
            auto& op = write_queue_.front();
            op.cb(asio::error::eof, 0);
            write_queue_.pop();
        }
        return;
    }
    if (writing_ || write_queue_.empty())
        return;

    auto& op = write_queue_.front();
    const auto* base = op.data->data() + op.offset;
    std::size_t remaining = op.data->size() - op.offset;

    ssize_t n = lsquic_stream_write(
        stream_, reinterpret_cast<const unsigned char*>(base), remaining);

    if (n > 0) {
        op.offset += static_cast<std::size_t>(n);
        if (op.offset >= op.data->size()) {
            // Whole op accepted — complete it.
            auto cb = std::move(op.cb);
            std::size_t total = op.offset;
            write_queue_.pop();
            cb({}, total);
            // Remaining ops are pumped from on_writeable().
        } else {
            // Partial write: keep the tail queued, resume on on_writeable().
            writing_ = true;
            lsquic_stream_wantwrite(stream_, 1);
        }
    } else if (n == 0) {
        // Nothing accepted right now (buffer/flow-control full).
        writing_ = true;
        lsquic_stream_wantwrite(stream_, 1);
    } else {
        // Error. errno: ECONNRESET (reset), EBADF (write side closed),
        // EILSEQ (headers not sent yet in H3 mode).
        auto cb = std::move(op.cb);
        write_queue_.pop();
        auto ec = (errno == ECONNRESET)
                      ? asio::error_code(asio::error::connection_reset)
                      : asio::error_code(asio::error::eof);
        cb(ec, 0);
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

TransportProtocol QuicTransportSession::protocol() const {
    return TransportProtocol::QUIC;
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

void QuicTransportSession::async_open_stream(
    std::function<void(ITransportStreamPtr)> cb) {
    set_new_stream_cb(std::move(cb));
    if (conn_)
        lsquic_conn_make_stream(conn_);
    // The stream is delivered via on_new_stream — promptly for an established
    // conn, after the handshake for a fresh one.
}

void QuicTransportSession::close() {
    if (conn_ && !closed_) {
        closed_ = true;
        lsquic_conn_close(conn_);
    }
}

std::string QuicTransportSession::remote_addr() const { return remote_addr_; }

void QuicTransportSession::on_new_stream(lsquic_stream_t* lsquic_stream) {
    if (!new_stream_cb_)
        return;
    if (lsquic_stream) {
        auto stream = std::make_shared<QuicTransportStream>(lsquic_stream);
        stream->adopt_self(); // same self-ownership as the session
        new_stream_cb_(std::move(stream));
    } else {
        // lsquic calls on_new_stream with a NULL stream when the connection
        // is going away while a stream was requested (client role).  Pass the
        // NULL through so the pool can fail the pending open instead of hanging.
        new_stream_cb_(nullptr);
    }
}

void QuicTransportSession::on_closed() {
    closed_ = true;
    if (conn_) {
        // Clear the conn_ctx BEFORE lsquic destroys the connection — lsquic
        // asserts cn_conn_ctx == NULL in ietf_full_conn_ci_destroy (we saw
        // this abort once a connection was actually closed during a run).
        lsquic_conn_set_ctx(conn_, nullptr);
        conn_ = nullptr;
    }
    if (closed_cb_) {
        auto cb = std::move(closed_cb_);
        closed_cb_ = nullptr;
        cb(); // pool drops this connection from its reuse table
    }
}

// ═══════════════════════════════════════════════════════════
// Shared glue — role-agnostic helpers and lsquic callbacks
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// TLS contexts — created ONCE, externally held, injected into the engines
// ═══════════════════════════════════════════════════════════

void ensure_quic_global_init() {
    // std::call_once BLOCKS all callers until the first init finishes — a bare
    // "already started?" flag would let a second thread return before the
    // (multi-step) init completed.
    static std::once_flag s_once;
    std::call_once(s_once, [] {
        if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER |
                                    LSQUIC_GLOBAL_CLIENT)) {
            spdlog::error("QUIC: lsquic_global_init failed");
            throw std::runtime_error("lsquic_global_init");
        }
        spdlog::info("QUIC global init done (server + client)");
    });
}

SslCtxPtr make_server_ssl_ctx(const std::string& cert_file,
                              const std::string& key_file) {
    ensure_quic_global_init();
    if (cert_file.empty() || key_file.empty()) {
        spdlog::warn("QUIC: no cert/key configured, TLS won't work");
        return nullptr;
    }

    auto* raw = SSL_CTX_new(TLS_method());
    if (!raw) {
        spdlog::error("QUIC: SSL_CTX_new failed");
        return nullptr;
    }
    SslCtxPtr ctx(raw, SSL_CTX_free);

    if (SSL_CTX_use_certificate_chain_file(ctx.get(), cert_file.c_str()) != 1) {
        spdlog::error("QUIC: failed to load cert file: {}", cert_file);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), key_file.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        spdlog::error("QUIC: failed to load key file: {}", key_file);
        return nullptr;
    }

    // QUIC requires TLS 1.3.
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);

    // ALPN protocol list (length-prefixed wire format): H3 and H3-29.
    static const char kQuicAlpn[] = "\x02h3\x05h3-29";
    SSL_CTX_set_alpn_select_cb(
        ctx.get(),
        [](SSL*, const unsigned char** out, unsigned char* outlen,
           const unsigned char* in, unsigned int inlen, void*) {
            static const unsigned char kAlpn[] = "\x02h3\x05h3-29";
            int r = SSL_select_next_proto(
                const_cast<unsigned char**>(out), outlen, in, inlen, kAlpn,
                sizeof(kAlpn) - 1);
            if (r == OPENSSL_NPN_NEGOTIATED)
                return SSL_TLSEXT_ERR_OK;
            spdlog::warn("QUIC: no supported ALPN from {:.{}}",
                         reinterpret_cast<const char*>(in), inlen);
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        },
        nullptr);
    spdlog::info("QUIC server TLS ctx ready: {}", cert_file);
    return ctx;
}

SslCtxPtr make_client_ssl_ctx() {
    ensure_quic_global_init();
    auto* raw = SSL_CTX_new(TLS_method());
    if (!raw) {
        spdlog::error("QUIC: client SSL_CTX_new failed");
        return nullptr;
    }
    SslCtxPtr ctx(raw, SSL_CTX_free);
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
    // No cert verification: ea_verify_cert stays NULL (the curl -k equivalent).
    return ctx;
}

namespace {

// ── address helpers ───────────────────────────────────────

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

std::string conn_peer_addr(lsquic_conn_t* conn) {
    const struct sockaddr *local, *peer;
    lsquic_conn_get_sockaddr(conn, &local, &peer);
    if (!peer)
        return "unknown";
    char buf[INET6_ADDRSTRLEN] = {};
    if (peer->sa_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(peer)
                                ->sin_addr,
                  buf, sizeof(buf));
    } else if (peer->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6*>(peer)
                                ->sin6_addr,
                  buf, sizeof(buf));
    }
    return buf[0] ? buf : "unknown";
}

// ── UDP send ──────────────────────────────────────────────

/// Send a batch of lsquic out-specs as UDP datagrams on `fd`.  Returns how
/// many were sent; `*blocked` is set if any hit EAGAIN — lsquic retains the
/// unsent packets and expects lsquic_engine_send_unsent_packets() once the
/// socket drains.
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
        // msg_control, msg_controllen left as 0 — no ancillary data.

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

// ── HTTP/3 header-set interface (HSI, ADR-8) ──────────────
// Shared by both engines: the server decodes request headers, the client
// decodes response headers, into the same QuicH3HeaderSet.

void* hsi_create(void*, lsquic_stream_t*, int) {
    return new QuicH3HeaderSet();
}

struct lsxpack_header* hsi_prepare_decode(void* hset,
                                          struct lsxpack_header* hdr,
                                          size_t space) {
    auto* hs = static_cast<QuicH3HeaderSet*>(hset);
    if (hdr) {
        // We don't grow the decode buffer — fail the decode.
        return nullptr;
    }
    if (hs->have_xhdr)
        hs->decode_off += lsxpack_header_get_dec_size(&hs->xhdr);
    else
        hs->have_xhdr = true;
    if (hs->decode_off + space > hs->decode_buf.size()) {
        spdlog::warn("QUIC HSI: decode buffer too small (need {}, have {})",
                     space, hs->decode_buf.size() - hs->decode_off);
        return nullptr;
    }
    lsxpack_header_prepare_decode(&hs->xhdr, hs->decode_buf.data(),
                                  hs->decode_off,
                                  hs->decode_buf.size() - hs->decode_off);
    return &hs->xhdr;
}

int hsi_process(void* hset, struct lsxpack_header* hdr) {
    auto* hs = static_cast<QuicH3HeaderSet*>(hset);
    if (!hdr)
        return 0; // header set complete
    const char* name = lsxpack_header_get_name(hdr);
    const char* value = lsxpack_header_get_value(hdr);
    if (!name || !value)
        return -1;
    // Keep every field, pseudo-headers included, in wire order.  Pseudo-header
    // interpretation (request vs response, what they mean) is the codec's job,
    // not the transport's.
    hs->headers.emplace_back(std::string(name, hdr->name_len),
                             std::string(value, hdr->val_len));
    return 0;
}

void hsi_discard(void* hset) {
    delete static_cast<QuicH3HeaderSet*>(hset);
}

const struct lsquic_hset_if kHsiIf = {
    .hsi_create_header_set  = hsi_create,
    .hsi_prepare_decode     = hsi_prepare_decode,
    .hsi_process_header     = hsi_process,
    .hsi_discard_header_set = hsi_discard,
    .hsi_flags              = (enum lsquic_hsi_flag)0,
};

// ── stream / conn callbacks (role-agnostic) ───────────────

lsquic_stream_ctx_t* new_stream_cb(void*, lsquic_stream_t* stream) {
    auto* conn = lsquic_stream_conn(stream);
    spdlog::debug("QUIC on_new_stream (stream={})",
                  reinterpret_cast<void*>(stream));
    // conn_ctx IS the QuicTransportSession (server or client role) — no
    // registry lookup needed.
    auto* session = reinterpret_cast<QuicTransportSession*>(
        lsquic_conn_get_ctx(conn));
    if (session) {
        session->on_new_stream(stream);
        // Stream context is stored inside the QuicTransportStream ctor.
        return reinterpret_cast<lsquic_stream_ctx_t*>(
            lsquic_stream_get_ctx(stream));
    }
    return nullptr;
}

void conn_closed_cb(lsquic_conn_t* conn) {
    auto* ctx = lsquic_conn_get_ctx(conn);
    if (!ctx)
        return;
    auto* session = reinterpret_cast<QuicTransportSession*>(ctx);
    // This is lsquic's LAST callback for this connection: after it returns
    // the conn is freed and the ctx is never handed back again.  Keep a copy
    // of the self-referential shared_ptr across on_closed()/release_self()
    // so the session is not destroyed while still inside its own member
    // function — the copy is dropped as this callback returns.
    auto keep_alive = session->shared_from_this();
    session->on_closed();    // mark closed + notify the pool's closed_cb
    session->release_self(); // drop self-ownership; destroyed once keep_alive goes away
}

void read_cb(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_readable();
}

void write_cb(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_writeable();
}

void close_cb(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (!qstream)
        return;
    // on_close() releases the stream's self-reference; keep a copy so the
    // wrapper is not destroyed while still inside its own member function.
    auto keep_alive = qstream->shared_from_this();
    qstream->on_close();
}

void reset_cb(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx, int how) {
    auto* qstream = reinterpret_cast<QuicTransportStream*>(ctx);
    if (qstream)
        qstream->on_reset(how);
}

/// Client-only: handshake completed (or failed).  Informational for now — the
/// pool learns a connection is usable because its first stream arrives via
/// on_new_stream once the handshake is done.
void hsk_done_cb(lsquic_conn_t* conn, enum lsquic_hsk_status status) {
    spdlog::info("QUIC handshake done (conn={}, status={})",
                 reinterpret_cast<void*>(conn), static_cast<int>(status));
}

} // namespace

// ── per-role stream interfaces ─────────────────────────────

static const struct lsquic_stream_if kServerStreamIf = {
    .on_new_conn    = QuicTransportListener::on_new_conn_cb,
    .on_conn_closed = conn_closed_cb,
    .on_new_stream  = new_stream_cb,
    .on_read        = read_cb,
    .on_write       = write_cb,
    .on_close       = close_cb,
    .on_reset       = reset_cb,
    .on_hsk_done    = hsk_done_cb,
};

static const struct lsquic_stream_if kClientStreamIf = {
    .on_new_conn    = QuicClientEngine::on_new_conn_cb,
    .on_conn_closed = conn_closed_cb,
    .on_new_stream  = new_stream_cb,
    .on_read        = read_cb,
    .on_write       = write_cb,
    .on_close       = close_cb,
    .on_reset       = reset_cb,
    .on_hsk_done    = hsk_done_cb,
};

// ═══════════════════════════════════════════════════════════
// QuicTransportListener
// ═══════════════════════════════════════════════════════════

QuicTransportListener::QuicTransportListener(asio::io_context& io,
                                             uint16_t port,
                                             SslCtxPtr ssl_ctx)
    : io_(io),
      socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)),
      tick_timer_(io),
      raw_fd_(socket_.native_handle()),
      ssl_ctx_(std::move(ssl_ctx)) {

    ensure_quic_global_init();

    struct lsquic_engine_api api = {};
    api.ea_hsi_if          = &kHsiIf;
    api.ea_hsi_ctx         = nullptr;
    api.ea_packets_out     = on_packets_out_cb;
    api.ea_packets_out_ctx = this;
    api.ea_stream_if       = &kServerStreamIf;
    api.ea_stream_if_ctx   = this;
    api.ea_lookup_cert     = lookup_cert_cb;
    api.ea_cert_lu_ctx     = this;
    api.ea_get_ssl_ctx     = get_ssl_ctx_cb;

    // Engine settings — use defaults.
    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_SERVER | LSENG_HTTP);
    api.ea_settings = &settings;

    unsigned flags = LSENG_SERVER | LSENG_HTTP;

    engine_ = lsquic_engine_new(flags, &api);
    if (!engine_)
        throw std::runtime_error("Failed to create lsquic engine");

    spdlog::info("QUIC listener created on port {}", port);
}

QuicTransportListener::~QuicTransportListener() {
    if (engine_) {
        lsquic_engine_destroy(engine_);
        engine_ = nullptr;
    }
    // ssl_ctx_ is a shared_ptr — released here (last holder frees the SSL_CTX).
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
        if (ec == asio::error::operation_aborted) {
            spdlog::debug("QUIC UDP recv stopped (socket closing)");
            return; // shutdown — do not re-arm
        }
        // Transient error (e.g. ENETDOWN).  Re-arm so the listener survives;
        // otherwise one bad packet kills the whole receive loop.
        spdlog::warn("QUIC UDP recv error: {} — re-arming", ec.message());
        if (socket_.is_open())
            do_recv();
        return;
    }

    spdlog::debug("QUIC UDP recv {} bytes from {}", n,
                  recv_endpoint_.address().to_string());

    struct sockaddr_storage local_sa, peer_sa;
    to_sockaddr(socket_.local_endpoint(), &local_sa);
    to_sockaddr(recv_endpoint_, &peer_sa);

    int r = lsquic_engine_packet_in(
        engine_, reinterpret_cast<const unsigned char*>(recv_buf_.data()), n,
        reinterpret_cast<const struct sockaddr*>(&local_sa),
        reinterpret_cast<const struct sockaddr*>(&peer_sa),
        this, // conn_ctx -> the conn's peer_ctx; get_ssl_ctx_cb reads it back
        0     // ecn
    );

    if (r < 0) {
        spdlog::warn("lsquic_engine_packet_in returned {}", r);
    }

    // Process connections immediately after receiving a packet.
    // This flushes outgoing packets (e.g. TLS Handshake) that the
    // engine needs to send as part of the QUIC handshake.
    lsquic_engine_process_conns(engine_);
    schedule_tick();

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

// ── lsquic callbacks (server-role) ────────────────────────

lsquic_conn_ctx_t*
QuicTransportListener::on_new_conn_cb(void* self, lsquic_conn_t* conn) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    std::string addr = conn_peer_addr(conn);

    spdlog::debug("QUIC on_new_conn from {} (conn={})", addr,
                  reinterpret_cast<void*>(conn));

    // The session owns itself via a self shared_ptr (see QuicTransportSession):
    // after adopt_self() it stays alive until on_conn_closed releases it.
    auto session = std::make_shared<QuicTransportSession>(conn, addr);
    session->adopt_self();
    auto* ctx = reinterpret_cast<lsquic_conn_ctx_t*>(session.get());

    // Notify ProxyCore (passes a shared_ptr copy — the app may retain it).
    if (listener->new_session_cb_) {
        spdlog::debug("QUIC notifying ProxyCore of new session");
        listener->new_session_cb_(session);
    }

    return ctx;
}

int QuicTransportListener::on_packets_out_cb(void* self,
                                             const lsquic_out_spec* specs,
                                             unsigned count) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    spdlog::debug("QUIC packets_out: {} specs", count);

    bool blocked = false;
    unsigned sent = send_specs(listener->raw_fd_, specs, count, &blocked);
    if (blocked)
        listener->arm_send_retry();
    return static_cast<int>(sent); // tell lsquic how many were actually sent
}

void QuicTransportListener::arm_send_retry() {
    if (send_retry_armed_ || !socket_.is_open())
        return;
    send_retry_armed_ = true;
    socket_.async_wait(
        asio::ip::udp::socket::wait_write,
        [this](asio::error_code ec) {
            send_retry_armed_ = false;
            if (ec)
                return;
            // Socket drained — flush whatever lsquic has queued up.
            if (engine_)
                lsquic_engine_send_unsent_packets(engine_);
            // If the flush itself hit EAGAIN again, re-arm for the next
            // writable edge.
            if (engine_ && lsquic_engine_has_unsent_packets(engine_))
                arm_send_retry();
        });
}

// ── TLS lookups (server role) ─────────────────────────────
// The SSL_CTX is created ONCE by make_server_ssl_ctx and injected; these
// callbacks only hand it to lsquic.  lookup_cert_cb reaches the listener via
// `self` (ea_cert_lu_ctx); get_ssl_ctx_cb has no self pointer, so it reaches
// the listener through the connection's peer_ctx — we pass `this` as the
// conn_ctx to lsquic_engine_packet_in (see on_packet).

struct ssl_ctx_st*
QuicTransportListener::lookup_cert_cb(void* self,
                                       const struct sockaddr* /*local*/,
                                       const char* sni) {
    auto* listener = static_cast<QuicTransportListener*>(self);
    spdlog::debug("QUIC lookup_cert_cb sni={} ssl_ctx={}",
                  sni ? sni : "(null)",
                  static_cast<void*>(listener->ssl_ctx_.get()));
    return listener->ssl_ctx_.get();
}

struct ssl_ctx_st*
QuicTransportListener::get_ssl_ctx_cb(void* peer_ctx,
                                       const struct sockaddr* /*local*/) {
    auto* listener = static_cast<QuicTransportListener*>(peer_ctx);
    spdlog::debug("QUIC get_ssl_ctx_cb ssl_ctx={}",
                  static_cast<void*>(listener->ssl_ctx_.get()));
    return listener->ssl_ctx_.get();
}

// ═══════════════════════════════════════════════════════════
// QuicClientEngine
// ═══════════════════════════════════════════════════════════

QuicClientEngine::QuicClientEngine(asio::io_context& io, SslCtxPtr ssl_ctx)
    : io_(io),
      socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)),
      tick_timer_(io),
      raw_fd_(socket_.native_handle()),
      ssl_ctx_(std::move(ssl_ctx)) {

    ensure_quic_global_init();

    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    struct lsquic_engine_api api = {};
    api.ea_settings         = &settings;
    api.ea_stream_if        = &kClientStreamIf;
    api.ea_stream_if_ctx    = this;
    api.ea_hsi_if           = &kHsiIf;   // decode response headers via QPACK
    api.ea_packets_out      = on_packets_out_cb;
    api.ea_packets_out_ctx  = this;
    api.ea_get_ssl_ctx      = get_ssl_ctx_cb;
    // ea_verify_cert NOT set → skip server-cert verification.

    engine_ = lsquic_engine_new(LSENG_HTTP, &api);
    if (!engine_)
        throw std::runtime_error("Failed to create QUIC client engine");

    spdlog::info("QUIC client engine created (local port {})",
                 socket_.local_endpoint().port());
}

QuicClientEngine::~QuicClientEngine() {
    if (engine_) {
        lsquic_engine_destroy(engine_);
        engine_ = nullptr;
    }
    // ssl_ctx_ is a shared_ptr — released here (last holder frees the SSL_CTX).
}

void QuicClientEngine::set_new_session_cb(NewClientSessionCallback cb) {
    new_session_cb_ = std::move(cb);
}

void QuicClientEngine::start() {
    do_recv();
    schedule_tick();
}

bool QuicClientEngine::connect(const BackendEndpoint& ep) {
    if (!engine_)
        return false;
    if (!started_) { // lazy start: arm the recv loop before the handshake can
        start();     // produce packets
        started_ = true;
    }

    // Resolve the upstream host.  A short blocking resolve on the event-loop
    // thread is acceptable here (same as the TCP pool's connect path).
    asio::ip::udp::resolver resolver(io_);
    asio::error_code ec;
    auto results = resolver.resolve(ep.host, std::to_string(ep.port), ec);
    if (ec || results.empty()) {
        spdlog::warn("QUIC client: resolve {}:{} failed: {}", ep.host,
                     ep.port, ec.message());
        return false;
    }
    asio::ip::udp::endpoint peer = *results.begin();

    struct sockaddr_storage local_sa, peer_sa;
    to_sockaddr(socket_.local_endpoint(), &local_sa);
    to_sockaddr(peer, &peer_sa);

    // Stash the endpoint so the SYNCHRONOUS on_new_conn (fires inside
    // lsquic_engine_connect) can attach it to the session.
    current_connect_ep_ = ep;
    lsquic_conn_t* conn = lsquic_engine_connect(
        engine_, N_LSQVER,                                // let the engine pick version
        reinterpret_cast<const struct sockaddr*>(&local_sa),
        reinterpret_cast<const struct sockaddr*>(&peer_sa),
        this,                 // peer_ctx — get_ssl_ctx_cb reads it back
        nullptr,              // conn_ctx — on_new_conn's return value becomes it
        ep.host.c_str(),      // hostname → TLS SNI (required for HTTP)
        0,                    // base_plpmtu — auto
        nullptr, 0,           // sess_resume
        nullptr, 0);          // token
    if (!conn) {
        spdlog::warn("QUIC client: lsquic_engine_connect failed for {}:{}",
                     ep.host, ep.port);
        current_connect_ep_ = {};
        return false;
    }

    // Flush the ClientHello (and any other handshake packets).
    lsquic_engine_process_conns(engine_);
    schedule_tick();
    return true;
}

// ── UDP receive loop ──────────────────────────────────────

void QuicClientEngine::do_recv() {
    socket_.async_receive_from(
        asio::buffer(recv_buf_), recv_endpoint_,
        [this](asio::error_code ec, std::size_t n) { on_packet(ec, n); });
}

void QuicClientEngine::on_packet(asio::error_code ec, std::size_t n) {
    if (ec) {
        if (ec == asio::error::operation_aborted)
            return;
        spdlog::warn("QUIC client UDP recv error: {} — re-arming", ec.message());
        if (socket_.is_open())
            do_recv();
        return;
    }

    spdlog::debug("QUIC[client] UDP recv {} bytes from {}", n,
                  recv_endpoint_.address().to_string());

    struct sockaddr_storage local_sa, peer_sa;
    to_sockaddr(socket_.local_endpoint(), &local_sa);
    to_sockaddr(recv_endpoint_, &peer_sa);

    int r = lsquic_engine_packet_in(
        engine_, reinterpret_cast<const unsigned char*>(recv_buf_.data()), n,
        reinterpret_cast<const struct sockaddr*>(&local_sa),
        reinterpret_cast<const struct sockaddr*>(&peer_sa),
        nullptr, 0);
    if (r < 0)
        spdlog::warn("QUIC client packet_in returned {}", r);

    lsquic_engine_process_conns(engine_);
    schedule_tick();
    do_recv();
}

// ── Tick timer ────────────────────────────────────────────

void QuicClientEngine::schedule_tick() {
    int diff = 0;
    unsigned next = lsquic_engine_earliest_adv_tick(engine_, &diff);
    if (diff < 0) {
        tick_timer_.expires_after(std::chrono::milliseconds(0));
    } else if (next == 0 || (unsigned)diff > 500) {
        tick_timer_.expires_after(std::chrono::milliseconds(500));
    } else {
        tick_timer_.expires_after(std::chrono::milliseconds(diff));
    }
    tick_timer_.async_wait([this](asio::error_code ec) { on_tick(ec); });
}

void QuicClientEngine::on_tick(asio::error_code ec) {
    if (ec)
        return;
    lsquic_engine_process_conns(engine_);
    schedule_tick();
}

// ── lsquic callbacks (client-role) ────────────────────────

lsquic_conn_ctx_t*
QuicClientEngine::on_new_conn_cb(void* self, lsquic_conn_t* conn) {
    auto* engine = static_cast<QuicClientEngine*>(self);
    // The endpoint was stashed before lsquic_engine_connect (synchronous).
    BackendEndpoint ep = std::move(engine->current_connect_ep_);

    auto session = std::make_shared<QuicTransportSession>(conn,
                                                          conn_peer_addr(conn));
    session->set_endpoint(ep);
    session->adopt_self();
    auto* ctx = reinterpret_cast<lsquic_conn_ctx_t*>(session.get());

    if (engine->new_session_cb_) {
        spdlog::debug("QUIC client conn to {}:{} (conn={})", ep.host, ep.port,
                      reinterpret_cast<void*>(conn));
        engine->new_session_cb_(session);
    }
    return ctx;
}

int QuicClientEngine::on_packets_out_cb(void* self,
                                        const lsquic_out_spec* specs,
                                        unsigned count) {
    auto* engine = static_cast<QuicClientEngine*>(self);
    spdlog::debug("QUIC[client] packets_out: {} specs", count);
    bool blocked = false;
    unsigned sent = send_specs(engine->raw_fd_, specs, count, &blocked);
    if (blocked)
        engine->arm_send_retry();
    return static_cast<int>(sent);
}

void QuicClientEngine::arm_send_retry() {
    if (send_retry_armed_ || !socket_.is_open())
        return;
    send_retry_armed_ = true;
    socket_.async_wait(
        asio::ip::udp::socket::wait_write,
        [this](asio::error_code ec) {
            send_retry_armed_ = false;
            if (ec)
                return;
            if (engine_)
                lsquic_engine_send_unsent_packets(engine_);
            if (engine_ && lsquic_engine_has_unsent_packets(engine_))
                arm_send_retry();
        });
}

struct ssl_ctx_st*
QuicClientEngine::get_ssl_ctx_cb(void* peer_ctx, const struct sockaddr*) {
    // peer_ctx is `this` — passed to lsquic_engine_connect (see connect()).
    auto* engine = static_cast<QuicClientEngine*>(peer_ctx);
    return engine->ssl_ctx_.get();
}

} // namespace ebpf_quic_proxy
