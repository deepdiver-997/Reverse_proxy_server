#include "proxy_core.h"
#include "codec/h1_codec.h"
#include "codec/h3_codec.h"
#include "relay_session.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {


ProxyCore::ProxyCore(asio::io_context& io, const ProxyConfig& cfg)
    : io_(io),
      h1_codec_(std::make_unique<H1Codec>()),
      h3_codec_(std::make_unique<H3Codec>()),
      upstream_pool_(io, make_client_ssl_ctx()) {

    // Build router.
    for (const auto& r : cfg.routes)
        router_.add_rule(r.host_match, r.backend_id);

    // Build upstream pool (per-worker: keep-alive pool + its own QUIC client
    // engine, lazily created when the first h3 backend is added).
    for (const auto& be : cfg.backends)
        upstream_pool_.add_backend(be);

    spdlog::info("proxy worker ready");
    spdlog::info("  routes: {}", cfg.routes.size());
    spdlog::info("  backends: {}", cfg.backends.size());
}

void ProxyCore::on_new_tcp_socket(asio::ip::tcp::socket socket) {
    auto session = std::make_shared<TcpTransportSession>(std::move(socket));
    spdlog::debug("new session from {}", session->remote_addr());
    on_session(std::move(session));
}

void ProxyCore::start_quic(QuicPacketDemux* demux, SslCtxPtr ssl_ctx) {
    quic_engine_ =
        std::make_unique<QuicServerEngine>(io_, std::move(ssl_ctx), demux);

    int worker_idx = demux->add_worker(io_, quic_engine_.get());
    quic_engine_->set_worker_idx(worker_idx);

    quic_engine_->set_new_session_cb(
        [this](QuicTransportSessionPtr session) {
            spdlog::debug("new QUIC session from {}", session->remote_addr());
            on_session(std::move(session));
        });

    quic_engine_->start();
    spdlog::info("QUIC server engine started (worker {})", worker_idx);
}

void ProxyCore::on_session(ITransportSessionPtr session) {
    // Pick the right codec based on transport protocol.
    auto* codec =
        (session->protocol() == TransportProtocol::QUIC)
            ? static_cast<ICodec*>(h3_codec_.get())
            : static_cast<ICodec*>(h1_codec_.get());

    // When the session has a new stream, hand it off.
    // TCP: fires synchronously inside set_new_stream_cb.
    session->set_new_stream_cb(
        [this, codec](ITransportStreamPtr stream) {
            on_stream(std::move(stream), codec);
        });
}

void ProxyCore::on_stream(ITransportStreamPtr stream, ICodec* codec) {
    spdlog::debug("new stream {}", stream->stream_id());

    // The RelaySession owns the rest of this client stream's lifecycle:
    // parse request → route → connect backend → relay → loop (H1 keep-alive)
    // or teardown.  It injects router + upstream pool + codecs.
    auto session = std::make_shared<RelaySession>(
        std::move(stream), codec, h1_codec_.get(), h3_codec_.get(), &router_,
        &upstream_pool_);
    live_relays_.insert(session); // pruned when the relay dies / at shutdown
    session->start();
}

void ProxyCore::graceful_shutdown() {
    // Must run on this worker's thread (live_relays_ + the relays are worker-
    // confined).  Safe to call from any thread.
    asio::post(io_, [this] {
        int live = 0;
        for (auto it = live_relays_.begin(); it != live_relays_.end();) {
            if (auto relay = it->lock()) {
                relay->graceful_close();
                ++live;
                ++it;
            } else {
                it = live_relays_.erase(it);
            }
        }
        spdlog::debug("graceful_shutdown: {} live relay(s) closed", live);
        // QUIC: GOAWAY every live server connection (H3 graceful shutdown).
        if (quic_engine_)
            quic_engine_->graceful_shutdown();
    });
}

void ProxyCore::force_close_quic() {
    asio::post(io_, [this] {
        if (quic_engine_)
            quic_engine_->force_close_all(); // CONNECTION_CLOSE, flushed now
    });
}

} // namespace ebpf_quic_proxy
