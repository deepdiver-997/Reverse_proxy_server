#include "reverse_proxy_server.h"
#include "proxy_core.h"
#include <spdlog/spdlog.h>
#include <sys/socket.h>

namespace ebpf_quic_proxy {

ReverseProxyServer::ReverseProxyServer(ProxyConfig cfg) : cfg_(std::move(cfg)) {}

ReverseProxyServer::~ReverseProxyServer() {
    if (started_.load()) {
        stop();
        wait();
    }
}

void ReverseProxyServer::start() {
    if (started_.exchange(true))
        return;

    // Thread layout: 1 ingress thread (TCP acceptor + QUIC demux) + N worker
    // threads.  Each worker is one io_context thread hosting frontend sockets,
    // its QUIC server engine, the relay, and its private backend pool.
    n_ = std::max(1, cfg_.num_threads);

    // asio::io_context is not movable, so hold them via unique_ptr.
    ingress_io_ = std::make_unique<asio::io_context>();
    worker_ios_.reserve(n_);
    for (int i = 0; i < n_; ++i)
        worker_ios_.push_back(std::make_unique<asio::io_context>());

    // Keep every io_context alive even when idle.  io_context::run() returns
    // immediately when there is no pending work; a worker no longer owns an
    // acceptor/QUIC timer, so without a work guard an idle worker thread would
    // exit and never process a posted hand-off (TCP fd / QUIC packet) from the
    // ingress (see design-quic-demux.md §3 / §15).
    ingress_guard_ =
        std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            asio::make_work_guard(*ingress_io_));
    for (auto& io : worker_ios_)
        worker_guards_.emplace_back(asio::make_work_guard(*io));

    // QUIC demux (shared UDP socket + CID routing), if enabled.
    if (cfg_.quic_port > 0) {
        demux_ = std::make_unique<QuicPacketDemux>(*ingress_io_, cfg_.quic_port);
        // ONE shared server TLS context — immutable after setup, safe to share
        // read-only across the worker engines.
        server_ssl_ = make_server_ssl_ctx(cfg_.quic_cert_file,
                                          cfg_.quic_key_file);
        if (!server_ssl_) {
            spdlog::error("QUIC: no usable server TLS ctx — QUIC disabled");
        }
    }

    // Workers.
    cores_.reserve(n_);
    for (int i = 0; i < n_; ++i) {
        cores_.push_back(std::make_unique<ProxyCore>(*worker_ios_[i], cfg_));
        if (cfg_.quic_port > 0 && server_ssl_)
            cores_[i]->start_quic(demux_.get(), server_ssl_);
    }

    // TCP ingress: accept → hand the fd to a worker (round-robin).
    auto listen_ep = asio::ip::tcp::endpoint(
        asio::ip::make_address(cfg_.listen_addr), cfg_.listen_port);
    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(*ingress_io_);
    acceptor_->open(listen_ep.address().is_v6() ? asio::ip::tcp::v6()
                                                : asio::ip::tcp::v4());
    int on = 1;
    ::setsockopt(acceptor_->native_handle(), SOL_SOCKET, SO_REUSEADDR, &on,
                 sizeof(on));
    acceptor_->bind(listen_ep);
    acceptor_->listen();
    accept_loop();

    grace_timer_ = std::make_unique<asio::steady_timer>(*ingress_io_);

    if (demux_)
        demux_->start();

    // Run.  Workers block in io_context::run() until hard_stop().
    spdlog::info("starting {} worker(s) + 1 ingress thread", n_);
    threads_.emplace_back([this] { ingress_io_->run(); });
    for (int i = 0; i < n_; ++i)
        threads_.emplace_back([this, i] { worker_ios_[i]->run(); });
}

void ReverseProxyServer::accept_loop() {
    acceptor_->async_accept(
        [this](asio::error_code ec, asio::ip::tcp::socket peer) {
            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    spdlog::warn("accept error: {} — re-arming", ec.message());
                    accept_loop();
                }
                return;
            }
            const int w = static_cast<int>(rr_++ % cores_.size());
            const bool v6 = peer.remote_endpoint().address().is_v6();
            // release() detaches the fd so `peer`'s destructor doesn't close
            // it; the worker re-attaches it via assign().
            const int fd = peer.release();
            asio::post(*worker_ios_[w],
                       [this, w, fd, v6]() {
                           asio::ip::tcp::socket s(*worker_ios_[w]);
                           s.assign(v6 ? asio::ip::tcp::v6()
                                       : asio::ip::tcp::v4(), fd);
                           cores_[w]->on_new_tcp_socket(std::move(s));
                       });
            accept_loop();
        });
}

int ReverseProxyServer::run() {
    start();
    signals_ = std::make_unique<asio::signal_set>(*ingress_io_, SIGINT,
                                                  SIGTERM);
    signals_->async_wait([this](asio::error_code ec, int) {
        if (ec)
            return;
        spdlog::info("shutdown signal received");
        stop();
    });
    wait();
    return 0;
}

void ReverseProxyServer::wait() {
    for (auto& t : threads_)
        if (t.joinable())
            t.join();
}

void ReverseProxyServer::stop() {
    if (!started_.load() || stopping_.exchange(true))
        return;
    // Serialize the shutdown sequence onto the ingress thread (acceptor, demux
    // and grace timer all live there; calling from the signal handler on that
    // same thread is fine — the post runs after the handler returns).
    asio::post(*ingress_io_, [this] { begin_shutdown(); });
}

void ReverseProxyServer::begin_shutdown() {
    spdlog::info("graceful shutdown: stop accepting, drain active connections");
    if (acceptor_)
        acceptor_->cancel();            // no new TCP connections
    if (demux_)
        demux_->stop();                 // no new QUIC datagrams (see §6/§15)
    for (auto& core : cores_)
        core->graceful_shutdown();      // FIN + drain frontend TCP (per-worker)

    // In-flight requests get `grace` to finish (GOAWAY already told QUIC
    // clients to stop issuing new ones), then finalize: force CONNECTION_CLOSE
    // on any remaining QUIC connections and hard-stop.
    grace_timer_->expires_after(grace);
    grace_timer_->async_wait([this](asio::error_code) { finalize(); });
}

void ReverseProxyServer::finalize() {
    spdlog::info("grace period over — sending final QUIC CONNECTION_CLOSE");
    for (auto& core : cores_)
        core->force_close_quic(); // posts to each worker; flushes the frames

    // One short beat so the workers actually run the close + flush before the
    // io_contexts stop (a posted handler never runs once stopped).
    grace_timer_->expires_after(std::chrono::milliseconds(200));
    grace_timer_->async_wait([this](asio::error_code) { hard_stop(); });
}

void ReverseProxyServer::hard_stop() {
    spdlog::info("stopping all io_contexts");
    ingress_io_->stop();
    for (auto& io : worker_ios_)
        io->stop();
}

} // namespace ebpf_quic_proxy
