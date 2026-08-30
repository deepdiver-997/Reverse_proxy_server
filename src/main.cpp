#include "config.h"
#include "proxy/proxy_core.h"
#include <asio.hpp>
#include <algorithm>
#include <csignal>
#include <memory>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>


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

    // Model B: `num_threads` is the number of fully independent proxy units.
    // Each unit owns its io_context + thread + listeners + upstream pool (its
    // own QUIC engines).  With more than one unit, listeners set SO_REUSEPORT
    // and the kernel distributes connections by 4-tuple — so a connection's
    // packets always reach the same unit, and no engine is shared across
    // threads (lsquic engines are not thread-safe).
    const int n = std::max(1, cfg.num_threads);
    const bool reuse_port = n > 1;

    // asio::io_context is not movable, so hold them via unique_ptr.
    std::vector<std::unique_ptr<asio::io_context>> ios;
    for (int i = 0; i < n; ++i)
        ios.push_back(std::make_unique<asio::io_context>());

    std::vector<std::unique_ptr<ebpf_quic_proxy::ProxyCore>> cores;
    for (int i = 0; i < n; ++i)
        cores.push_back(std::make_unique<ebpf_quic_proxy::ProxyCore>(
            *ios[i], cfg, reuse_port));

    // Graceful shutdown: SIGINT/SIGTERM stops EVERY unit's io_context.  The
    // signal_set runs on unit 0's thread; io_context::stop() is thread-safe.
    asio::signal_set signals(*ios[0], SIGINT, SIGTERM);
    signals.async_wait([&ios](asio::error_code, int sig) {
        spdlog::info("received signal {}, shutting down", sig);
        for (auto& io : ios)
            io->stop();
    });

    for (int i = 0; i < n; ++i) {
        cores[i]->start_tcp();
        if (cfg.quic_port > 0) {
            cores[i]->start_quic(cfg.quic_port, cfg.quic_cert_file,
                                 cfg.quic_key_file, reuse_port);
        }
    }

    spdlog::info("starting {} proxy unit(s)...", n);
    std::vector<std::thread> threads;
    for (int i = 0; i < n; ++i)
        threads.emplace_back([&ios, i] { ios[i]->run(); });

    for (auto& t : threads)
        t.join();

    spdlog::info("proxy stopped");
    return 0;
}
