#pragma once

#include "config.h"
#include "transport/itransport_stream.h"
#include <asio.hpp>
#include <functional>
#include <atomic>
#include <mutex>
#include <vector>

namespace ebpf_quic_proxy {

/// Manages backend endpoints and creates connections to them.
/// Phase 1: round-robin, lazy-connect (no connection pool).
class UpstreamPool {
public:
    using ConnectCallback =
        std::function<void(asio::error_code, ITransportStreamPtr)>;

    explicit UpstreamPool(asio::io_context& io);

    void add_backend(const BackendEndpoint& be);

    /// Open a new TCP connection to a backend in `backend_id` group.
    void async_connect(const std::string& backend_id, ConnectCallback cb);

private:
    asio::io_context& io_;
    std::vector<BackendEndpoint> endpoints_;
    std::mutex mutex_;
    std::atomic<std::size_t> rr_index_ = 0;
};

} // namespace ebpf_quic_proxy
