#include "proxy_core.h"
#include "codec/h1_codec.h"
#include "codec/h3_codec.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {


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
    auto* raw = stream.get();
    codec->async_parse_request(
        stream, [this, stream](asio::error_code ec,
                                HttpRequestHead head, BodySourcePtr body) {
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
                auto err_body = std::make_shared<std::string>(
                    make_error_response(HttpStatus::ServiceUnavailable,
                                        "no route for host\n"));
                stream->async_write_some(
                    asio::buffer(*err_body),
                    [stream, err_body](auto, auto) {
                        stream->async_shutdown([](auto) {});
                    });
                return;
            }

            forward_request(stream, std::move(head), std::move(body),
                            std::move(backend_id));
        });
}

void ProxyCore::forward_request(ITransportStreamPtr client_stream,
                                 HttpRequestHead head, BodySourcePtr body,
                                 const std::string& backend_id) {
    upstream_pool_.async_connect(
        backend_id,
        [this, client_stream, head = std::move(head), body = std::move(body),
         backend_id](asio::error_code ec,
                      ITransportStreamPtr upstream_stream) mutable {
            if (ec) {
                spdlog::warn("upstream connect failed: {}", ec.message());
                auto err_body = std::make_shared<std::string>(
                    make_error_response(HttpStatus::BadGateway,
                                        "upstream unreachable\n"));
                client_stream->async_write_some(
                    asio::buffer(*err_body),
                    [client_stream, err_body](auto, auto) {
                        client_stream->async_shutdown([](auto) {});
                    });
                return;
            }

            // Forward the request to upstream.
            // Build the HTTP/1.1 request line + headers.
            std::string req_line = head.method + " " + head.path + " HTTP/1.1";
            std::string req_hdrs = head.headers.to_wire();
            std::string req_block = req_line + "\r\n" + req_hdrs + "\r\n";

            auto req_data = std::make_shared<std::string>(std::move(req_block));

            upstream_stream->async_write_some(
                asio::buffer(*req_data),
                [upstream_stream, body = std::move(body),
                 client_stream](asio::error_code ec,
                                 std::size_t) mutable {
                    if (ec) {
                        spdlog::warn("write request failed: {}", ec.message());
                        auto err_body = std::make_shared<std::string>(
                            make_error_response(HttpStatus::BadGateway,
                                                "backend write error\n"));
                        client_stream->async_write_some(
                            asio::buffer(*err_body),
                            [client_stream, err_body](auto, auto) {
                                client_stream->async_shutdown([](auto) {});
                            });
                        return;
                    }

                    // Pump body if present.
                    if (!body) {
                        // No body — read response immediately.
                        // Phase 1: just read response into a buffer and
                        // forward.  A real implementation would stream this.
                        auto resp_buf =
                            std::make_shared<std::vector<char>>(8192);
                        upstream_stream->async_read_some(
                            asio::buffer(*resp_buf),
                            [client_stream, upstream_stream,
                             resp_buf](asio::error_code ec,
                                        std::size_t n) mutable {
                                if (ec && ec != asio::error::eof) {
                                    spdlog::warn("read response failed: {}",
                                                 ec.message());
                                    return;
                                }
                                // Forward raw response back to client.
                                client_stream->async_write_some(
                                    asio::buffer(resp_buf->data(), n),
                                    [client_stream, upstream_stream,
                                     resp_buf](auto, auto) {
                                        // Shutdown to signal end of response.
                                        client_stream->async_shutdown(
                                            [](auto) {});
                                    });
                            });
                        return;
                    }

                    // Has body — pump it (Phase 1: simple recursive pump).
                    auto pump = std::make_shared<std::function<void()>>();
                    auto buf = std::make_shared<std::array<char, 8192>>();
                    *pump = [body, upstream_stream, client_stream, pump,
                             buf]() mutable {
                        body->async_read_some(
                            asio::buffer(*buf),
                            [upstream_stream, client_stream, pump,
                             buf](asio::error_code ec,
                                   std::size_t n) mutable {
                                if (ec || n == 0) {
                                    // Body done — read response.
                                    auto resp_buf =
                                        std::make_shared<std::vector<char>>(
                                            8192);
                                    upstream_stream->async_read_some(
                                        asio::buffer(*resp_buf),
                                        [client_stream, upstream_stream,
                                         resp_buf](auto ec, auto n) mutable {
                                            if (ec && ec != asio::error::eof)
                                                return;
                                            client_stream->async_write_some(
                                                asio::buffer(resp_buf->data(),
                                                              n),
                                                [client_stream, upstream_stream,
                                                 resp_buf](auto, auto) {
                                                    client_stream
                                                        ->async_shutdown(
                                                            [](auto) {});
                                                });
                                        });
                                    return;
                                }
                                upstream_stream->async_write_some(
                                    asio::buffer(buf->data(), n),
                                    [pump](auto ec, auto) mutable {
                                        if (ec) return;
                                        (*pump)();
                                    });
                            });
                    };
                    (*pump)();
                });
        });
}

} // namespace ebpf_quic_proxy
