#include "config.h"
#include "proxy/proxy_core.h"
#include <asio.hpp>
#include <csignal>
#include <iostream>
#include <spdlog/spdlog.h>
#include <thread>


int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

    std::string config_path = "proxy.toml";
    if (argc >= 2) {
        config_path = argv[1];
    }

    ebpf_quic_proxy::ProxyConfig cfg;
    try {
        cfg = ebpf_quic_proxy::load_config(config_path);
    } catch (const std::exception& e) {
        spdlog::error("config error: {}", e.what());
        return 1;
    }

    asio::io_context io;

    // Signal handling for graceful shutdown.
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&io](asio::error_code, int sig) {
        spdlog::info("received signal {}, shutting down", sig);
        io.stop();
    });

    ebpf_quic_proxy::ProxyCore proxy(io, cfg);
    proxy.start();

    spdlog::info("starting event loop...");

    // Run on the configured number of threads.
    std::vector<std::thread> threads;
    for (int i = 1; i < cfg.num_threads; ++i) {
        threads.emplace_back([&io] { io.run(); });
    }
    io.run();

    for (auto& t : threads)
        t.join();

    spdlog::info("proxy stopped");
    return 0;
}
