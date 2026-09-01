#pragma once

#include "transport/itransport_session.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

struct BackendEndpoint {
    std::string backend_id;
    std::string host;
    uint16_t port;
    int weight = 1;
    /// How the proxy reaches this backend: TCP = HTTP/1.1, QUIC = HTTP/3
    /// (config: `protocol = "h1"` default, `"h3"` for an HTTP/3 upstream).
    TransportProtocol protocol = TransportProtocol::TCP;
};

struct RouteRule {
    std::string host_match; // "*" for default
    std::string backend_id;
};

struct ProxyConfig {
    std::string listen_addr = "0.0.0.0";
    uint16_t listen_port = 8080;
    int num_threads = 1;

    /// Idle timeout in seconds for a client connection (0 = disabled).  A
    /// relay that has been silent for this long is torn down, freeing the
    /// session / fd / backend port.  Reset on relay-visible activity.
    int idle_timeout_secs = 30;

    /// Listen on both IPv4 and IPv6 for the frontends (TCP acceptor binds
    /// `::` with IPV6_V6ONLY=0; the QUIC demux opens a second IPv6 UDP
    /// socket).  If IPv6 is unavailable the bind fails and the server logs a
    /// loud warning and falls back to IPv4-only — it never silently degrades.
    bool dual_stack = false;

    // QUIC (HTTP/3) support — disabled when quic_port == 0.
    uint16_t quic_port = 0;
    std::string quic_cert_file = "certs/cert.pem";
    std::string quic_key_file = "certs/key.pem";

    std::vector<BackendEndpoint> backends;
    std::vector<RouteRule> routes;
};

/// Load ProxyConfig from a TOML file.
ProxyConfig load_config(const std::string& path);

} // namespace ebpf_quic_proxy
