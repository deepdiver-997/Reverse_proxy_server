#include "config.h"
#include "proxy/reverse_proxy_server.h"
#include <spdlog/spdlog.h>
#include <string>

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    std::string config_path = "proxy.toml";
    if (argc >= 2)
        config_path = argv[1];

    ebpf_quic_proxy::ProxyConfig cfg;
    try {
        cfg = ebpf_quic_proxy::load_config(config_path);
    } catch (const std::exception& e) {
        spdlog::error("config error: {}", e.what());
        return 1;
    }

    // Blocks until SIGINT/SIGTERM, then drains in-flight work and exits 0.
    ebpf_quic_proxy::ReverseProxyServer server(std::move(cfg));
    return server.run();
}
