#pragma once

#include "config.h"
#include "transport/itransport_stream.h"
#include <asio.hpp>
#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace ebpf_quic_proxy {

/// Manages backend endpoints and connections to them.
/// Phase 1: round-robin, lazy-connect.  Step 2: keep-alive pool — idle
/// connections are returned via release() and reused on the next checkout.
class UpstreamPool {
public:
    /// Connect callback.  `endpoint` is the chosen backend endpoint;
    /// `from_pool` is true when an idle pooled connection was reused (the
    /// caller may want to retry once on a fresh connection if it proves stale).
    using ConnectCallback =
        std::function<void(asio::error_code, ITransportStreamPtr,
                           const BackendEndpoint&, bool from_pool)>;

    explicit UpstreamPool(asio::io_context& io);

    void add_backend(const BackendEndpoint& be);

    /// Open (or check out an idle) TCP connection to a backend in
    /// `backend_id` group.  Round-robins among that group's endpoints.
    void async_connect(const std::string& backend_id, ConnectCallback cb);

    /// Connect to a specific endpoint, always fresh (skips the idle queue).
    /// Used to retry after a pooled connection turned out stale.
    void async_connect_fresh(const BackendEndpoint& endpoint,
                             ConnectCallback cb);

    /// Return an idle keep-alive connection to the pool for reuse.
    /// Drops the connection if the per-endpoint idle limit is reached.
    void release(const BackendEndpoint& endpoint, ITransportStreamPtr stream);

private:
    struct EndpointEntry {
        BackendEndpoint be;
        std::deque<ITransportStreamPtr> idle; // idle keep-alive connections
    };

    void connect_fresh_to(const BackendEndpoint& target, ConnectCallback cb);

    asio::io_context& io_;
    std::vector<EndpointEntry> endpoints_;
    std::mutex mutex_;
    std::atomic<std::size_t> rr_index_ = 0;

    static constexpr std::size_t kMaxIdlePerEndpoint = 8;
};

} // namespace ebpf_quic_proxy
