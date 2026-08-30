#include "proxy_core.h"
#include "codec/h1_codec.h"
#include "codec/h3_codec.h"
#include "relay_session.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {


ProxyCore::ProxyCore(asio::io_context& io, const ProxyConfig& cfg,
                     bool reuse_port)
    : io_(io),
      h1_codec_(std::make_unique<H1Codec>()),
      h3_codec_(std::make_unique<H3Codec>()),
      upstream_pool_(io, make_client_ssl_ctx()) {

    // Build TCP listener.
    auto ep = asio::ip::tcp::endpoint(
        asio::ip::make_address(cfg.listen_addr), cfg.listen_port);
    tcp_listener_ =
        std::make_shared<TcpTransportListener>(io, ep, reuse_port);

    // Build router.
    for (const auto& r : cfg.routes)
        router_.add_rule(r.host_match, r.backend_id);

    // Build upstream pool.
    for (const auto& be : cfg.backends)
        upstream_pool_.add_backend(be);

    spdlog::info("proxy listening on {}:{}", cfg.listen_addr, cfg.listen_port);
    spdlog::info("  routes: {}", cfg.routes.size());
    spdlog::info("  backends: {}", cfg.backends.size());
}

void ProxyCore::start_tcp() { do_accept(); }

void ProxyCore::start_quic(uint16_t port, const std::string& cert_file,
                            const std::string& key_file, bool reuse_port) {
    // Server TLS ctx: created ONCE here (single-threaded startup) and injected
    // — immutable after setup, safe to share read-only across listener threads.
    auto ssl_ctx = make_server_ssl_ctx(cert_file, key_file);
    quic_listener_ = std::make_unique<QuicTransportListener>(
        io_, port, std::move(ssl_ctx), reuse_port);

    quic_listener_->set_new_session_cb(
        [this](QuicTransportSessionPtr session) {
            spdlog::debug("new QUIC session from {}", session->remote_addr());
            on_session(std::move(session));
        });

    quic_listener_->start();
    spdlog::info("QUIC listener started on port {}", port);
}

void ProxyCore::do_accept() {
    tcp_listener_->async_accept(
        [this](ITransportSessionPtr session) {
            if (!session) {
                spdlog::error("accept failed, stopping");
                return;
            }
            spdlog::debug("new session from {}", session->remote_addr());
            on_session(std::move(session));
            // Accept the next connection.
            do_accept();
        });
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
    session->start();
}

} // namespace ebpf_quic_proxy
