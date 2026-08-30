#pragma once

#include "config.h"
#include "transport/itransport_stream.h"
#include "transport/quic_transport.h"
#include <asio.hpp>
#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

/// Manages backend endpoints and connections to them.
/// Phase 1: round-robin, lazy-connect.  Step 2: keep-alive pool — idle
/// connections are returned via release() and reused on the next checkout.
/// H3 upstreams (endpoint.protocol == QUIC) are reached through a
/// QuicClientEngine whose established connections are reused by opening a new
/// stream per request (multiplexing) instead of serialized TCP keep-alive.
class UpstreamPool {
public:
    /// Connect callback.  `endpoint` is the chosen backend endpoint;
    /// `from_pool` is true when an idle pooled connection was reused (the
    /// caller may want to retry once on a fresh connection if it proves stale).
    using ConnectCallback =
        std::function<void(asio::error_code, ITransportStreamPtr,
                           const BackendEndpoint&, bool from_pool)>;

    /// `client_ssl_ctx` is the shared client TLS context (make_client_ssl_ctx),
    /// externally held and injected into any QUIC client engine we create.
    explicit UpstreamPool(asio::io_context& io, SslCtxPtr client_ssl_ctx);

    void add_backend(const BackendEndpoint& be);

    /// Open (or check out an idle) connection to a backend in `backend_id`
    /// group.  Round-robins among that group's endpoints; TCP uses the
    /// keep-alive pool, QUIC (protocol == QUIC) opens a stream on a reused
    /// client connection.
    void async_connect(const std::string& backend_id, ConnectCallback cb);

    /// Connect to a specific endpoint, always fresh (skips the idle queue).
    /// Used to retry after a pooled connection turned out stale.
    void async_connect_fresh(const BackendEndpoint& endpoint,
                             ConnectCallback cb);

    /// Return an idle keep-alive connection to the pool for reuse.
    /// Drops the connection if the per-endpoint idle limit is reached.
    /// No-op for QUIC endpoints — H3 streams are one-shot; the connection
    /// stays pooled on its own.
    void release(const BackendEndpoint& endpoint, ITransportStreamPtr stream);

private:
    struct EndpointEntry {
        BackendEndpoint be;
        std::deque<ITransportStreamPtr> idle; // idle keep-alive connections
    };

    void connect_fresh_to(const BackendEndpoint& target, ConnectCallback cb);

    // ── QUIC (H3 upstream) path ───────────────────────────
    void quic_connect(const BackendEndpoint& ep, ConnectCallback cb);
    void quic_connect_fresh(const BackendEndpoint& ep, ConnectCallback cb);
    /// Called synchronously from QuicClientEngine::connect's on_new_conn:
    /// `session` just arrived; open its first stream.
    void on_client_conn(QuicTransportSessionPtr session);
    void open_quic_stream(QuicTransportSessionPtr session,
                          const BackendEndpoint& ep, bool from_pool,
                          ConnectCallback cb);
    void remove_quic_conn(const BackendEndpoint& ep,
                          QuicTransportSession* raw);

    struct PendingQuic {
        BackendEndpoint endpoint;
        ConnectCallback cb;
    };

    std::unique_ptr<QuicClientEngine> quic_engine_;
    SslCtxPtr client_ssl_ctx_; // shared client TLS ctx, injected into the engine
    std::optional<PendingQuic> pending_quic_; // consumed by on_client_conn
    /// Established client connections per upstream (key "host:port").
    std::map<std::string, std::deque<QuicTransportSessionPtr>> quic_conns_;

    asio::io_context& io_;
    std::vector<EndpointEntry> endpoints_;
    std::mutex mutex_;
    std::atomic<std::size_t> rr_index_ = 0;

    static constexpr std::size_t kMaxIdlePerEndpoint = 8;
};

} // namespace ebpf_quic_proxy
