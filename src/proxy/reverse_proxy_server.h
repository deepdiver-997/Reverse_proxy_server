#pragma once

#include "config.h"
#include "transport/quic_demux.h"
#include "transport/quic_transport.h"
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace ebpf_quic_proxy {

class ProxyCore;

/// The whole proxy as one object — resource orchestration for Model A:
/// 1 ingress thread (TCP accept + QUIC demux) + N worker threads, each worker
/// a co-located io_context thread hosting frontend sockets, its QUIC engine,
/// the relay and its private backend pool.  Only cross-thread hand-off is
/// ingress → worker (see docs/design-quic-demux.md).
///
/// Lifecycle — two styles, pick one:
///   self-contained:   run() — installs SIGINT/SIGTERM, starts, blocks until a
///                           signal, drains in-flight work, shuts down cleanly.
///   embeddable:       start() → wait(), then stop() from any other thread.
///                           start() returns immediately; stop() initiates a
///                           graceful drain; wait() joins all threads.
///
/// Graceful shutdown (see stop()): stop accepting → FIN + drain frontend TCP
/// connections (shutdown_send, then read to EOF so close() never RSTs) → let
/// in-flight requests finish → after `grace` hard-stop every io_context.
class ReverseProxyServer {
public:
    explicit ReverseProxyServer(ProxyConfig cfg);
    ~ReverseProxyServer();

    ReverseProxyServer(const ReverseProxyServer&) = delete;
    ReverseProxyServer& operator=(const ReverseProxyServer&) = delete;

    /// Blocking entry point: installs SIGINT/SIGTERM, calls start(), then
    /// wait().  Returns 0 after a signal-triggered graceful shutdown.
    int run();

    /// Spawn ingress + worker threads.  Returns immediately; idempotent.
    void start();

    /// Join all threads (blocks until they exit).
    void wait();

    /// Thread-safe: begin graceful shutdown.  Safe to call from any thread;
    /// repeated calls are no-ops.  Idle frontend TCP clients get FIN immediately,
    /// in-flight exchanges get `grace` to finish, then everything hard-stops.
    void stop();

    /// Grace period for in-flight requests before the hard stop.
    std::chrono::milliseconds grace = std::chrono::milliseconds(5000);

private:
    void accept_loop();
    void begin_shutdown();   // runs on the ingress thread (posted from stop())
    void finalize();         // after grace: force QUIC CONNECTION_CLOSE + beat
    void hard_stop();        // stop every io_context — ends the run() loops

    ProxyConfig cfg_;
    int n_ = 1;

    // io_contexts first, then guards referencing them (member order matters).
    // Guards can't be default-constructed (and work_guard has no assignment),
    // so hold the ingress one by pointer — it is set in start() once its
    // io_context exists.
    std::unique_ptr<asio::io_context> ingress_io_;
    std::vector<std::unique_ptr<asio::io_context>> worker_ios_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>
        ingress_guard_;
    std::vector<asio::executor_work_guard<asio::io_context::executor_type>>
        worker_guards_;

    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::unique_ptr<asio::steady_timer> grace_timer_;
    std::unique_ptr<asio::signal_set> signals_;
    std::size_t rr_ = 0; // round-robin worker pick for accepted fds

    std::unique_ptr<QuicPacketDemux> demux_;
    SslCtxPtr server_ssl_;
    std::vector<std::unique_ptr<ProxyCore>> cores_;

    std::vector<std::thread> threads_;
    std::atomic<bool> started_{false};
    std::atomic<bool> stopping_{false};
};

} // namespace ebpf_quic_proxy
