#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

struct BackendEndpoint {
    std::string backend_id;
    std::string host;
    uint16_t port;
    int weight = 1;
};

struct RouteRule {
    std::string host_match; // "*" for default
    std::string backend_id;
};

struct ProxyConfig {
    std::string listen_addr = "0.0.0.0";
    uint16_t listen_port = 8080;
    int num_threads = 1;

    std::vector<BackendEndpoint> backends;
    std::vector<RouteRule> routes;
};

/// Load ProxyConfig from a TOML file.
ProxyConfig load_config(const std::string& path);

} // namespace ebpf_quic_proxy
