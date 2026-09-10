#include "stats.h"

namespace ebpf_quic_proxy {

std::string ProxyStats::render() const {
    const auto up = std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - started).count();
    std::string s;
    s.reserve(512);
    s += "proxy_uptime_seconds " + std::to_string(up) + "\n";
    s += "proxy_tcp_connections_total " + std::to_string(tcp_conns) + "\n";
    s += "proxy_quic_connections_total " + std::to_string(quic_conns) + "\n";
    s += "proxy_requests_total " + std::to_string(requests) + "\n";
    s += "proxy_responses_ok_total " + std::to_string(resp_ok) + "\n";
    s += "proxy_responses_error_total " + std::to_string(resp_err) + "\n";
    s += "proxy_backend_connects_total " + std::to_string(backend_connects) + "\n";
    s += "proxy_backend_latency_us_sum " + std::to_string(lat_us_total) + "\n";
    s += "proxy_backend_latency_us_count " + std::to_string(lat_count) + "\n";
    return s;
}

} // namespace ebpf_quic_proxy
