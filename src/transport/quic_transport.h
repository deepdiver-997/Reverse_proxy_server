#pragma once

#include "itransport_stream.h"
#include "itransport_session.h"
extern "C" {
#include <lsquic.h>
}
#include <lsxpack_header.h>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

namespace ebpf_quic_proxy {

// ── QuicH3HeaderSet ───────────────────────────────────────

/// Per-request HTTP/3 header set allocated by the HSI (`hsi_create_header_set`)
/// and filled by lsquic's QPACK decoder via `hsi_prepare_decode` /
/// `hsi_process_header`.  Handed back to us by `lsquic_stream_get_hset()`.
struct QuicH3HeaderSet {
    std::array<char, 64 * 1024> decode_buf{};   // lsxpack decoder buffer
    std::vector<std::pair<std::string, std::string>> headers; // name, value
    std::string method, path, authority, scheme;
    int status_code = 0;
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

    // Called by the glue layer.
    void on_new_stream(lsquic_stream_t* lsquic_stream);
    void on_closed();

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
    bool closed_ = false;
    std::shared_ptr<QuicTransportSession> self_; // cyclic self-ownership
};

using QuicTransportSessionPtr = std::shared_ptr<QuicTransportSession>;

// ── QuicTransportListener ─────────────────────────────────

/// Manages a UDP socket + lsquic engine.
/// Does NOT inherit ITransportListener — QUIC connections arrive as callbacks,
/// not via accept().
class QuicTransportListener {
public:
    using NewSessionCallback =
        std::function<void(QuicTransportSessionPtr)>;

    /// Create a QUIC listener bound to `port`.
    /// Requires TLS cert/key for QUIC handshake.
    QuicTransportListener(asio::io_context& io, uint16_t port,
                          const std::string& cert_file,
                          const std::string& key_file);
    ~QuicTransportListener();

    /// Register callback for new QUIC sessions.
    void set_new_session_cb(NewSessionCallback cb);

    /// Begin listening (start UDP recv + timer loop).
    void start();

private:
    asio::io_context& io_;
    asio::ip::udp::socket socket_;
    asio::steady_timer tick_timer_;
    int raw_fd_ = -1; // native fd for synchronous sendto
    lsquic_engine_t* engine_ = nullptr;
    NewSessionCallback new_session_cb_;

    // TLS — loaded once, shared by all QUIC connections.
    struct ssl_ctx_st* ssl_ctx_ = nullptr; // SSL_CTX*
    static inline struct ssl_ctx_st* s_ssl_ctx_ = nullptr;
    std::string cert_file_, key_file_;
    void load_tls_cert();
    static struct ssl_ctx_st* lookup_cert_cb(void* self,
                                              const struct sockaddr* local,
                                              const char* sni);
    static struct ssl_ctx_st* get_ssl_ctx_cb(void* peer_ctx,
                                              const struct sockaddr* local);

    // Receiving.
    std::array<char, 65536> recv_buf_{};
    asio::ip::udp::endpoint recv_endpoint_;

    void do_recv();
    void on_packet(asio::error_code ec, std::size_t n);
    void schedule_tick();
    void on_tick(asio::error_code ec);

    // Sending: when on_packets_out hits EAGAIN, arm a writability watch and
    // flush lsquic's unsent packets once the socket drains.
    void arm_send_retry();
    bool send_retry_armed_ = false;

    // ── lsquic callbacks ──────────────────────────────────
    static lsquic_conn_ctx_t* on_new_conn_cb(void* self, lsquic_conn_t* conn);
    static void on_conn_closed_cb(lsquic_conn_t* conn);
    static lsquic_stream_ctx_t* on_new_stream_cb(void* self,
                                                  lsquic_stream_t* stream);
    static void on_read_cb(lsquic_stream_t* stream,
                           lsquic_stream_ctx_t* ctx);
    static void on_write_cb(lsquic_stream_t* stream,
                            lsquic_stream_ctx_t* ctx);
    static void on_close_cb(lsquic_stream_t* stream,
                            lsquic_stream_ctx_t* ctx);
    static void on_reset_cb(lsquic_stream_t* stream,
                            lsquic_stream_ctx_t* ctx, int how);
    static int on_packets_out_cb(void* self,
                                 const lsquic_out_spec* specs,
                                 unsigned count);

    // ── HTTP/3 header-set interface (HSI, ADR-8) ──────────
    static void* hsi_create(void* ctx, lsquic_stream_t* stream,
                            int is_push_promise);
    static struct lsxpack_header* hsi_prepare_decode(void* hset,
                                                     struct lsxpack_header* hdr,
                                                     size_t space);
    static int hsi_process(void* hset, struct lsxpack_header* hdr);
    static void hsi_discard(void* hset);

    // Lookup helpers.
    QuicTransportSession* find_session(lsquic_conn_t* conn);
    QuicTransportStream* find_stream(lsquic_stream_t* stream);
};

} // namespace ebpf_quic_proxy
