#include "proxy_core.h"
#include "codec/h1_codec.h"
#include "codec/h3_codec.h"
#include "relay_session.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

namespace {

// Write an error response to `stream` through `codec`, then shut it down.
// Goes through the codec so the response is correctly framed for the client's
// protocol (H1 or H3).
void write_error(ICodec* codec, ITransportStreamPtr stream, HttpStatus status,
                 const std::string& msg) {
    HttpResponseHead resp;
    resp.status_code = static_cast<int>(status);
    resp.reason = status_reason(status);
    resp.headers.set("content-type", "text/plain");
    resp.headers.set("content-length", std::to_string(msg.size()));
    codec->async_write_response(
        std::move(stream), std::move(resp),
        std::make_shared<BufferBodySource>(msg),
        [](asio::error_code) {});
}

} // namespace


ProxyCore::ProxyCore(asio::io_context& io, const ProxyConfig& cfg)
    : io_(io),
      h1_codec_(std::make_unique<H1Codec>()),
      h3_codec_(std::make_unique<H3Codec>()),
      upstream_pool_(io) {

    // Build TCP listener.
    auto ep = asio::ip::tcp::endpoint(
        asio::ip::make_address(cfg.listen_addr), cfg.listen_port);
    tcp_listener_ =
        std::make_shared<TcpTransportListener>(io, ep);

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
                            const std::string& key_file) {
    quic_listener_ = std::make_unique<QuicTransportListener>(
        io_, port, cert_file, key_file);

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

    // Parse the request.
    codec->async_parse_request(
        stream, [this, stream, codec](asio::error_code ec,
                                      HttpRequestHead head,
                                      BodySourcePtr body) mutable {
            if (ec) {
                spdlog::debug("parse error on {}: {}", stream->stream_id(),
                              ec.message());
                return;
            }

            spdlog::info("{} {} {} from {}", head.method, head.path,
                         head.headers.get("host").value_or("-"),
                         stream->stream_id());

            // Route.
            auto backend_id = router_.route(head);
            if (backend_id.empty()) {
                spdlog::warn("no route for host={}",
                             head.headers.get("host").value_or("-"));
                write_error(codec, stream, HttpStatus::ServiceUnavailable,
                            "no route for host\n");
                return;
            }

            forward_request(std::move(stream), codec, std::move(head),
                            std::move(body), std::move(backend_id));
        });
}

void ProxyCore::forward_request(ITransportStreamPtr client_stream,
                                ICodec* client_codec, HttpRequestHead head,
                                BodySourcePtr body,
                                const std::string& backend_id) {
    upstream_pool_.async_connect(
        backend_id,
        [this, client_stream, client_codec, head = std::move(head),
         body = std::move(body),
         backend_id](asio::error_code ec,
                     ITransportStreamPtr upstream_stream) mutable {
            if (ec) {
                spdlog::warn("upstream connect failed: {}", ec.message());
                write_error(client_codec, std::move(client_stream),
                            HttpStatus::BadGateway, "upstream unreachable\n");
                return;
            }

            // Both sides are now connected — hand off to a RelaySession which
            // serializes the request to the backend (backend codec), parses the
            // backend response, and serializes it back to the client (client
            // codec).  Response direction now goes through the codec.
            std::string method = head.method; // save before moving head
            auto session = std::make_shared<RelaySession>(
                std::move(client_stream), std::move(upstream_stream),
                client_codec, h1_codec_.get());
            session->forward(std::move(head), std::move(body), method);
        });
}

} // namespace ebpf_quic_proxy
