#pragma once

#include "config.h"
#include "itransport_stream.h"
#include "itransport_session.h"
#include "quic_demux.h"
extern "C" {
#include <lsquic.h>
}
#include <lsxpack_header.h>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

// The OpenSSL/BoringSSL SSL_CTX — forward-declared at GLOBAL scope so
// `struct ssl_ctx_st` inside the namespace resolves to the same type that
// lsquic.h and the TLS APIs use (a namespace-scoped declaration would be a
// different, incompatible type).
struct ssl_ctx_st;

namespace ebpf_quic_proxy {

// ── TLS contexts (thread-safe one-time setup, externally held + injected) ──

/// Shared TLS context.  An SSL_CTX is immutable after setup and safe to share
/// across threads for NEW connections (OpenSSL/BoringSSL standard model);
/// ownership is shared so multiple engines (Model B: one per thread) can hold
/// the same context.  Created ONCE at startup and injected — never a static.
using SslCtxPtr = std::shared_ptr<struct ssl_ctx_st>;

/// One-time lsquic global init — thread-safe (std::call_once blocks callers
/// until the first init completes; a bare atomic "already started?" flag would
/// let a second thread return before init finished).
void ensure_quic_global_init();

/// Build the server TLS context: TLS 1.3 + cert chain + key + H3 ALPN.
/// Returns nullptr (logged) when the cert/key can't be loaded.  The makers run
/// ensure_quic_global_init() internally, so order is safe.
SslCtxPtr make_server_ssl_ctx(const std::string& cert_file,
                              const std::string& key_file);

/// Build the client TLS context (TLS 1.3, no cert verification —
/// ea_verify_cert stays NULL, the curl -k equivalent).
SslCtxPtr make_client_ssl_ctx();

// ── QuicH3HeaderSet ───────────────────────────────────────

/// Per-request HTTP/3 header set allocated by the HSI (`hsi_create_header_set`)
/// and filled by lsquic's QPACK decoder via `hsi_prepare_decode` /
/// `hsi_process_header`.  Handed back to us by `lsquic_stream_get_hset()`.
struct QuicH3HeaderSet {
    std::array<char, 64 * 1024> decode_buf{};   // lsxpack decoder buffer
    // ALL decoded fields — pseudo-headers (":method", ":path", ":scheme",
    // ":authority", ":status") included — in wire order.  The transport only
    // decodes; the codec interprets them into a request or response IR
    // (H3Codec::async_parse_request / async_parse_response).
    std::vector<std::pair<std::string, std::string>> headers;
    struct lsxpack_header xhdr {};
    std::size_t decode_off = 0;
    bool have_xhdr = false;
};

// ── QuicTransportStream ───────────────────────────────────

/// ITransportStream backed by an lsquic stream.
class QuicTransportStream final
    : public ITransportStream,
      public std::enable_shared_from_this<QuicTransportStream> {
public:
    QuicTransportStream(lsquic_stream_t* stream);
    ~QuicTransportStream() override;

    void async_read_some(asio::mutable_buffer buf,
                         ReadCallback cb) override;
    void async_write_some(asio::const_buffer buf,
                          WriteCallback cb) override;
    void async_shutdown(ShutdownCallback cb) override;
    std::string stream_id() const override;

    // Called by the glue layer when data is available.
    void on_readable();
    void on_writeable();
    void on_close();
    void on_reset(int how); // how: 0=read, 1=write, 2=both (shutdown(2) style)

    // Self-ownership — same pattern as QuicTransportSession: the wrapper
    // holds a shared_ptr to itself so it lives exactly as long as the
    // underlying lsquic stream (deterministic, independent of whether the
    // app retained a reference).
    //   adopt_self()  — called by QuicTransportSession::on_new_stream after
    //                   make_shared.
    //   release_self()— called at the end of on_close(); on_close_cb holds a
    //                   keep-alive copy so destruction happens after the
    //                   last lsquic callback for the stream returns.
    void adopt_self() { self_ = shared_from_this(); }
    void release_self() { self_.reset(); }

    // HTTP/3 (lsquic native, ADR-8): request the lsquic-decoded header set as
    // an IR head. Must be called before reading the body. Returns false if
    // unsupported or a take is already pending.
    bool async_take_headers(HeadersCallback cb) override;

    // HTTP/3: send a header block via lsquic_stream_send_headers before the
    // body. Pseudo-headers (e.g. ":status") must be first.
    bool async_send_headers(const HeaderList& headers, WriteCallback cb) override;

private:
    lsquic_stream_t* stream_;
    std::string id_;

    // Pending read callback.
    ReadCallback read_cb_;
    asio::mutable_buffer read_buf_{};

    // HTTP/3: pending "give me the decoded request headers" callback.
    HeadersCallback headers_cb_;

    // Try to claim the decoded H3 header set; fires headers_cb_ when ready.
    void try_take_headers();

    // Pending write callback + queue.
    // `offset` tracks how much of `data` has already been handed to lsquic:
    // lsquic_stream_write() may accept fewer bytes than requested, so the
    // remaining tail stays queued until on_writeable() lets us continue.
    struct WriteOp {
        std::shared_ptr<std::vector<char>> data;
        std::size_t offset = 0;
        WriteCallback cb;
    };
    std::queue<WriteOp> write_queue_;
    bool writing_ = false;

    // Pending shutdown callback.
    ShutdownCallback shutdown_cb_;

    std::shared_ptr<QuicTransportStream> self_; // cyclic self-ownership

    void pump_write();
};

// ── QuicTransportSession ──────────────────────────────────

/// ITransportSession backed by an lsquic connection.
class QuicTransportSession final
    : public ITransportSession,
      public std::enable_shared_from_this<QuicTransportSession> {
public:
    QuicTransportSession(lsquic_conn_t* conn,
                         std::string remote_addr);
    ~QuicTransportSession() override;

    TransportProtocol protocol() const override;
    void set_new_stream_cb(NewStreamCallback cb) override;
    ITransportStreamPtr open_stream() override;
    void close() override;
    std::string remote_addr() const override;

    /// The underlying lsquic connection — used by the server engine for
    /// graceful shutdown (GOAWAY / CONNECTION_CLOSE).
    lsquic_conn_t* conn() const { return conn_; }

    // Called by the glue layer.
    void on_new_stream(lsquic_stream_t* lsquic_stream);
    void on_closed();

    // ── client-role hooks (used by the QUIC upstream pool) ──
    /// Which upstream endpoint this connection is for (set by the client
    /// engine's on_new_conn; unused for server sessions).
    void set_endpoint(const BackendEndpoint& ep) { endpoint_ = ep; }
    const BackendEndpoint& endpoint() const { return endpoint_; }

    /// Open one outbound request stream on this connection.  `cb` fires with
    /// the stream once the handshake is done (or nullptr if the connection is
    /// going away).  For a client conn the stream is delivered via
    /// on_new_stream after the handshake; for an established conn, promptly.
    void async_open_stream(std::function<void(ITransportStreamPtr)> cb);

    /// Fired from on_closed() — lets the pool drop this connection from its
    /// reuse table.  The callback must NOT capture the session shared_ptr
    /// (that would recreate the cycle we deliberately break).
    void set_closed_cb(std::function<void()> cb) { closed_cb_ = std::move(cb); }

    // Self-ownership: the session holds a shared_ptr to itself for the whole
    // connection lifetime (a deliberate, breakable cycle — NOT a leak).
    //   adopt_self()  — called by on_new_conn_cb right after make_shared.
    //   release_self()— called by on_conn_closed_cb (after a keep-alive copy
    //                   is taken) to drop the self-reference; the last ref
    //                   then releases and the session is destroyed only after
    //                   the last lsquic callback for that conn has returned.
    void adopt_self() { self_ = shared_from_this(); }
    void release_self() { self_.reset(); }

private:
    lsquic_conn_t* conn_;
    std::string remote_addr_;
    NewStreamCallback new_stream_cb_;
    BackendEndpoint endpoint_; // client-role: which upstream this conn targets
    std::function<void()> closed_cb_;
    bool closed_ = false;
    std::shared_ptr<QuicTransportSession> self_; // cyclic self-ownership
};

using QuicTransportSessionPtr = std::shared_ptr<QuicTransportSession>;

// ── QuicServerEngine ───────────────────────────────────────

/// Server-role QUIC engine for ONE worker.  This is a pure engine: it owns NO
/// UDP socket and runs NO recv loop — the demux posts packets to it via
/// deliver_packet() on this worker's io_context thread.  It owns the lsquic
/// server engine, the shared server TLS context, and the tick timer; outgoing
/// packets are sent synchronously on the demux's shared fd.
class QuicServerEngine {
public:
    using NewSessionCallback =
        std::function<void(QuicTransportSessionPtr)>;

    /// `demux` is the shared QUIC ingress: we send on its fd, and register /
    /// unregister our server SCIDs with it so inbound packets route here.
    QuicServerEngine(asio::io_context& io, SslCtxPtr ssl_ctx,
                     QuicPacketDemux* demux);
    ~QuicServerEngine();

    QuicServerEngine(const QuicServerEngine&) = delete;
    QuicServerEngine& operator=(const QuicServerEngine&) = delete;

    /// Register callback for new QUIC sessions.
    void set_new_session_cb(NewSessionCallback cb);

    /// Begin ticking.  Inbound delivery starts once the demux routes to us.
    void start();

    /// Worker index assigned by the demux (add_worker).  The SCID callbacks use
    /// it to tell the demux which worker owns a given server SCID.
    void set_worker_idx(int idx) { worker_idx_ = idx; }

    /// Called by the demux (via io_context::post) with one inbound datagram.
    /// Runs on this worker's thread.
    void deliver_packet(const unsigned char* buf, std::size_t len,
                        const struct sockaddr_storage& local_sa,
                        const struct sockaddr_storage& peer_sa);

    /// Called by the demux (via post) once the shared socket is writable.
    void flush_unsent_packets();

    /// Graceful QUIC shutdown (server stopping): send GOAWAY on every live
    /// connection — clients stop issuing new requests, in-flight H3 streams
    /// keep running.  Flushes the GOAWAY frames synchronously.  MUST run on
    /// this engine's worker thread (call from ProxyCore's posted lambda).
    void graceful_shutdown();

    /// Final step: force CONNECTION_CLOSE on every remaining live connection
    /// and flush synchronously so the frames actually leave before the worker
    /// io_context stops.  MUST run on this engine's worker thread.
    void force_close_all();

    // Referenced by the file-scope kServerStreamIf (quic_transport.cpp).
    static lsquic_conn_ctx_t* on_new_conn_cb(void* self, lsquic_conn_t* conn);

private:
    asio::io_context& io_;
    asio::steady_timer tick_timer_;
    lsquic_engine_t* engine_ = nullptr;
    NewSessionCallback new_session_cb_;
    QuicPacketDemux* demux_ = nullptr;
    int worker_idx_ = -1;

    // TLS context — externally created (make_server_ssl_ctx) and injected;
    // immutable after setup, shared read-only across threads.  Callbacks reach
    // it via `self` (lookup_cert_cb) or the conn's peer_ctx (get_ssl_ctx_cb).
    SslCtxPtr ssl_ctx_;
    static struct ssl_ctx_st* lookup_cert_cb(void* self,
                                              const struct sockaddr* local,
                                              const char* sni);
    static struct ssl_ctx_st* get_ssl_ctx_cb(void* peer_ctx,
                                              const struct sockaddr* local);

    /// Live server sessions, tracked for graceful shutdown.  Weak — a session
    /// removes itself by dying; the on_conn_closed → closed_cb erases the entry
    /// (and graceful_shutdown/force_close_all prune expired ones).  Only ever
    /// touched on this worker's thread.
    std::set<std::weak_ptr<QuicTransportSession>,
             std::owner_less<std::weak_ptr<QuicTransportSession>>>
        live_sessions_;

    void schedule_tick();
    void on_tick(asio::error_code ec);

    // ── lsquic callbacks (stream/conn callbacks are shared free functions in
    // quic_transport.cpp) ──
    static int on_packets_out_cb(void* self, const lsquic_out_spec* specs,
                                 unsigned count);
    static void on_new_scids_cb(void* ctx, void** peer_ctx,
                                const lsquic_cid_t* cids, unsigned n_cids);
    static void on_old_scids_cb(void* ctx, void** peer_ctx,
                                const lsquic_cid_t* cids, unsigned n_cids);

    // ── HTTP/3 header-set interface (HSI, ADR-8) ──────────
    // (Implemented as shared free functions in quic_transport.cpp — both the
    // server and the client engine use the same QPACK decoding machinery.)
};

// ── QuicClientEngine ───────────────────────────────────────

/// Client-role QUIC engine: initiates outbound HTTP/3 connections to upstream
/// servers.  lsquic forbids a single engine playing both roles, so this is a
/// second engine with its own UDP socket + drive loop; it shares the stream /
/// session classes and the HTTP/3 header-set interface (HSI) with the server.
///
/// The pool drives it: connect() → (synchronously) on_new_conn → a
/// QuicTransportSession is made and delivered via new_session_cb; the session
/// is then reused by opening a new stream per request (multiplexing).
class QuicClientEngine {
public:
    using NewClientSessionCallback =
        std::function<void(QuicTransportSessionPtr)>;

    /// `ssl_ctx` is the shared client TLS context (make_client_ssl_ctx),
    /// externally held and injected — never a static.
    QuicClientEngine(asio::io_context& io, SslCtxPtr ssl_ctx);
    ~QuicClientEngine();

    /// Register callback for new outbound QUIC sessions (the pool).
    void set_new_session_cb(NewClientSessionCallback cb);

    /// Begin listening (start UDP recv + timer loop).
    void start();

    /// Initiate an outbound connection to `ep`.  On success, the session is
    /// delivered synchronously via new_session_cb (with endpoint() set) before
    /// this returns.  Returns false if the engine refused the connect.
    bool connect(const BackendEndpoint& ep);

    // Referenced by the file-scope kClientStreamIf (quic_transport.cpp), so it
    // must be public.
    static lsquic_conn_ctx_t* on_new_conn_cb(void* self, lsquic_conn_t* conn);

private:
    asio::io_context& io_;
    asio::ip::udp::socket socket_;      // IPv4, bound to an ephemeral port
    asio::ip::udp::socket socket6_;     // IPv6, lazily opened on first v6 connect
    asio::steady_timer tick_timer_;
    int raw_fd_ = -1;                   // native fd for synchronous sendto (v4)
    int raw6_fd_ = -1;                  // ... and v6 (-1 when unavailable)
    lsquic_engine_t* engine_ = nullptr;
    NewClientSessionCallback new_session_cb_;
    bool started_ = false;              // recv/tick loop armed on first connect

    // Client TLS context (TLS1.3, no cert verification) — externally created
    // (make_client_ssl_ctx) and injected; shared read-only across threads.
    SslCtxPtr ssl_ctx_;

    // Receiving (one buffer/endpoint per family — each socket has its own
    // pending recv).
    std::array<char, 65536> recv_buf_{};
    asio::ip::udp::endpoint recv_endpoint_;
    std::array<char, 65536> recv6_buf_{};
    asio::ip::udp::endpoint recv6_endpoint_;
    void do_recv();
    void do_recv6();
    void on_packet(asio::error_code ec, std::size_t n, bool is_v6);
    bool ensure_v6_socket();            // open+bind+arm recv for a v6 upstream
    void schedule_tick();
    void on_tick(asio::error_code ec);
    void arm_send_retry();
    void arm_write_watch(asio::ip::udp::socket& s, bool& armed);
    bool send_retry_armed_ = false;
    bool send_retry6_armed_ = false;

    // Stashed before lsquic_engine_connect, consumed by the synchronous
    // on_new_conn — safe because on_new_conn fires inside connect().
    BackendEndpoint current_connect_ep_;

    static struct ssl_ctx_st* get_ssl_ctx_cb(void* peer_ctx,
                                             const struct sockaddr* local);
    static int on_packets_out_cb(void* self, const lsquic_out_spec* specs,
                                 unsigned count);
};

} // namespace ebpf_quic_proxy
