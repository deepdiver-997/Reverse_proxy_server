#include "upstream_pool.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

UpstreamPool::UpstreamPool(asio::io_context& io) : io_(io) {}

void UpstreamPool::add_backend(const BackendEndpoint& be) {
    std::lock_guard lock(mutex_);
    endpoints_.push_back(be);
}

void UpstreamPool::async_connect(const std::string& backend_id,
                                  ConnectCallback cb) {
    // Find all endpoints for this backend_id.
    std::vector<BackendEndpoint> candidates;
    {
        std::lock_guard lock(mutex_);
        for (const auto& ep : endpoints_) {
            if (ep.backend_id == backend_id)
                candidates.push_back(ep);
        }
    }

    if (candidates.empty()) {
        cb(asio::error::not_found, nullptr);
        return;
    }

    // Round-robin pick.
    // Can be replaced with atomic fetch_add if we want to avoid the mutex, but this is simpler for the mvp
    std::size_t idx = rr_index_.fetch_add(1) % candidates.size();
    const auto& target = candidates[idx];

    spdlog::debug("connecting to backend {} at {}:{}", backend_id, target.host,
                  target.port);

    // Resolve + connect.
    asio::ip::tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(target.host, std::to_string(target.port));

    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    asio::async_connect(
        *socket, endpoints,
        [socket, cb = std::move(cb)](asio::error_code ec,
                                       auto /*endpoint*/) mutable {
            if (ec) {
                spdlog::warn("backend connect failed: {}", ec.message());
                cb(ec, nullptr);
                return;
            }
            auto stream =
                std::make_shared<TcpTransportStream>(std::move(*socket));
            cb({}, stream);
        });
}

} // namespace ebpf_quic_proxy
