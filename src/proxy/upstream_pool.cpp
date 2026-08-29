#include "upstream_pool.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

UpstreamPool::UpstreamPool(asio::io_context& io) : io_(io) {}

void UpstreamPool::add_backend(const BackendEndpoint& be) {
    std::lock_guard lock(mutex_);
    endpoints_.push_back(EndpointEntry{be, {}});
}

void UpstreamPool::async_connect(const std::string& backend_id,
                                 ConnectCallback cb) {
    // Find all endpoints for this backend_id.
    std::vector<EndpointEntry*> candidates;
    {
        std::lock_guard lock(mutex_);
        for (auto& e : endpoints_)
            if (e.be.backend_id == backend_id)
                candidates.push_back(&e);
    }

    if (candidates.empty()) {
        cb(asio::error::not_found, nullptr, {}, false);
        return;
    }

    // Round-robin pick among the group's endpoints.
    std::size_t idx = rr_index_.fetch_add(1) % candidates.size();
    auto* entry = candidates[idx];

    // Prefer a pooled idle connection over a fresh handshake.
    ITransportStreamPtr idle;
    {
        std::lock_guard lock(mutex_);
        if (!entry->idle.empty()) {
            idle = std::move(entry->idle.front());
            entry->idle.pop_front();
        }
    }
    if (idle) {
        spdlog::debug("reusing idle backend connection to {}:{}",
                      entry->be.host, entry->be.port);
        cb({}, std::move(idle), entry->be, /*from_pool=*/true);
        return;
    }

    connect_fresh_to(entry->be, std::move(cb));
}

void UpstreamPool::async_connect_fresh(const BackendEndpoint& endpoint,
                                       ConnectCallback cb) {
    connect_fresh_to(endpoint, std::move(cb));
}

void UpstreamPool::connect_fresh_to(const BackendEndpoint& target,
                                    ConnectCallback cb) {
    spdlog::debug("connecting to backend {} at {}:{}", target.backend_id,
                  target.host, target.port);

    // Resolve + connect.
    asio::ip::tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(target.host, std::to_string(target.port));

    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    asio::async_connect(
        *socket, endpoints,
        [socket, cb = std::move(cb),
         target](asio::error_code ec, auto /*endpoint*/) mutable {
            if (ec) {
                spdlog::warn("backend connect failed: {}", ec.message());
                cb(ec, nullptr, target, false);
                return;
            }
            auto stream =
                std::make_shared<TcpTransportStream>(std::move(*socket));
            cb({}, std::move(stream), target, /*from_pool=*/false);
        });
}

void UpstreamPool::release(const BackendEndpoint& endpoint,
                           ITransportStreamPtr stream) {
    std::lock_guard lock(mutex_);
    for (auto& e : endpoints_) {
        if (e.be.backend_id == endpoint.backend_id &&
            e.be.host == endpoint.host && e.be.port == endpoint.port) {
            if (e.idle.size() < kMaxIdlePerEndpoint)
                e.idle.push_back(std::move(stream));
            // else: drop — the shared_ptr release closes the socket.
            return;
        }
    }
    // Unknown endpoint — dropping the ref closes the connection.
}

} // namespace ebpf_quic_proxy
