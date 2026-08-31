#include "config.h"
#include "proxy/proxy_core.h"
#include "transport/quic_demux.h"
#include "transport/quic_transport.h"
#include <asio.hpp>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <functional>
#include <memory>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
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

    // Thread layout: 1 ingress thread (TCP acceptor + QUIC demux) + N worker
    // threads.  Each worker is one io_context thread hosting frontend sockets,
    // its QUIC server engine, the relay, and its private backend pool.  The
    // only cross-thread hand-off is ingress → worker; after that a request
    // lives and dies on the same worker (see docs/design-quic-demux.md).
    const int n = std::max(1, cfg.num_threads);

    // asio::io_context is not movable, so hold them via unique_ptr.
    auto ingress_io = std::make_unique<asio::io_context>();
    std::vector<std::unique_ptr<asio::io_context>> worker_ios;
    for (int i = 0; i < n; ++i)
        worker_ios.push_back(std::make_unique<asio::io_context>());

    // QUIC demux (shared UDP socket + CID routing), if enabled.
    std::unique_ptr<ebpf_quic_proxy::QuicPacketDemux> demux;
    ebpf_quic_proxy::SslCtxPtr server_ssl;
    if (cfg.quic_port > 0) {
        demux = std::make_unique<ebpf_quic_proxy::QuicPacketDemux>(
            *ingress_io, cfg.quic_port);
        // ONE shared server TLS context — immutable after setup, safe to share
        // read-only across the worker engines.
        server_ssl = ebpf_quic_proxy::make_server_ssl_ctx(cfg.quic_cert_file,
                                                          cfg.quic_key_file);
        if (!server_ssl) {
            spdlog::error("QUIC: no usable server TLS ctx — QUIC disabled");
        }
    }

    // Workers.
    std::vector<std::unique_ptr<ebpf_quic_proxy::ProxyCore>> cores;
    for (int i = 0; i < n; ++i) {
        cores.push_back(
            std::make_unique<ebpf_quic_proxy::ProxyCore>(*worker_ios[i], cfg));
        if (cfg.quic_port > 0 && server_ssl)
            cores[i]->start_quic(demux.get(), server_ssl);
    }

    // Graceful shutdown: SIGINT/SIGTERM stops EVERY io_context (ingress +
    // workers).  io_context::stop() is thread-safe.
    asio::signal_set signals(*ingress_io, SIGINT, SIGTERM);
    signals.async_wait([&](asio::error_code, int sig) {
        spdlog::info("received signal {}, shutting down", sig);
        ingress_io->stop();
        for (auto& io : worker_ios)
            io->stop();
    });

    // ── TCP ingress: accept → hand the fd to a worker ─────
    auto listen_ep = asio::ip::tcp::endpoint(
        asio::ip::make_address(cfg.listen_addr), cfg.listen_port);
    asio::ip::tcp::acceptor acceptor(*ingress_io);
    acceptor.open(listen_ep.address().is_v6() ? asio::ip::tcp::v6()
                                              : asio::ip::tcp::v4());
    int on = 1;
    ::setsockopt(acceptor.native_handle(), SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on));
    acceptor.bind(listen_ep);
    acceptor.listen();

    std::atomic<std::size_t> rr{0}; // round-robin worker pick
    std::function<void()> do_accept = [&]() {
        acceptor.async_accept(
            [&](asio::error_code ec, asio::ip::tcp::socket peer) {
                if (ec) {
                    if (ec != asio::error::operation_aborted) {
                        spdlog::warn("accept error: {} — re-arming",
                                     ec.message());
                        do_accept();
                    }
                    return;
                }
                const int w =
                    static_cast<int>(rr.fetch_add(1) % cores.size());
                const bool v6 = peer.remote_endpoint().address().is_v6();
                // release() detaches the fd so `peer`'s destructor doesn't
                // close it; the worker re-attaches it via assign().
                const int fd = peer.release();
                asio::post(*worker_ios[w], [fd, v6, w, &cores, &worker_ios]() {
                    asio::ip::tcp::socket s(*worker_ios[w]);
                    s.assign(v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4(),
                             fd);
                    cores[w]->on_new_tcp_socket(std::move(s));
                });
                do_accept();
            });
    };
    do_accept();

    // ── QUIC ingress ──────────────────────────────────────
    if (demux)
        demux->start();

    // ── Run ───────────────────────────────────────────────
    spdlog::info("starting {} worker(s) + 1 ingress thread", n);
    std::vector<std::thread> threads;
    threads.emplace_back([&ingress_io] { ingress_io->run(); });
    for (int i = 0; i < n; ++i)
        threads.emplace_back([&worker_ios, i] { worker_ios[i]->run(); });

    for (auto& t : threads)
        t.join();

    spdlog::info("proxy stopped");
    return 0;
}
