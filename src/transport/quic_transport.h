#pragma once

#include "itransport_stream.h"
#include "itransport_session.h"
extern "C" {
#include <lsquic.h>
}
#include <asio.hpp>
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>

namespace ebpf_quic_proxy {

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

private:
    lsquic_stream_t* stream_;
    std::string id_;

    // Pending read callback.
    ReadCallback read_cb_;
    asio::mutable_buffer read_buf_{};

    // Pending write callback + queue.
    struct WriteOp {
        std::shared_ptr<std::vector<char>> data;
        WriteCallback cb;
    };
    std::queue<WriteOp> write_queue_;
    bool writing_ = false;

    // Pending shutdown callback.
    ShutdownCallback shutdown_cb_;

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

private:
    lsquic_conn_t* conn_;
    std::string remote_addr_;
    NewStreamCallback new_stream_cb_;
    bool closed_ = false;
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

    // Active sessions (conn_ctx → QuicTransportSession).
    // We use the conn_ctx pointer as key since lsquic gives it back in
    // callbacks.
    std::unordered_map<lsquic_conn_ctx_t*, QuicTransportSessionPtr> sessions_;

    void do_recv();
    void on_packet(asio::error_code ec, std::size_t n);
    void schedule_tick();
    void on_tick(asio::error_code ec);

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
    static int on_packets_out_cb(void* self,
                                 const lsquic_out_spec* specs,
                                 unsigned count);

    // Lookup helpers.
    QuicTransportSession* find_session(lsquic_conn_t* conn);
    QuicTransportStream* find_stream(lsquic_stream_t* stream);
};

} // namespace ebpf_quic_proxy
