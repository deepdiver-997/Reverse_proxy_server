#include "relay_session.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

RelaySession::RelaySession(ITransportStreamPtr client, ICodec* client_codec,
                           ICodec* backend_codec, Router* router,
                           UpstreamPool* pool)
    : client_(std::move(client)),
      client_codec_(client_codec),
      backend_codec_(backend_codec),
      router_(router),
      pool_(pool) {}

void RelaySession::start() { request_phase(); }

void RelaySession::request_phase() {
    auto self = shared_from_this();
    client_codec_->async_parse_request(
        client_,
        [this, self](asio::error_code ec, HttpRequestHead head,
                     BodySourcePtr body, bool keep_alive) {
            if (ec) {
                // EOF = client closed; a parse error is a broken client —
                // either way, nothing more to relay on this connection.
                spdlog::debug("relay: client parse/EOF on {}: {}",
                              client_->stream_id(), ec.message());
                teardown();
                return;
            }
            client_keep_alive_ = keep_alive;
            request_method_ = head.method;

            spdlog::info("{} {} {} from {}", head.method, head.path,
                         head.headers.get("host").value_or("-"),
                         client_->stream_id());

            auto backend_id = router_->route(head);
            if (backend_id.empty()) {
                spdlog::warn("no route for host={}",
                             head.headers.get("host").value_or("-"));
                write_error(HttpStatus::ServiceUnavailable, "no route for host\n");
                return;
            }

            pool_->async_connect(
                backend_id,
                [this, self, head = std::move(head),
                 body = std::move(body)](asio::error_code ec,
                                         ITransportStreamPtr upstream) mutable {
                    if (ec) {
                        spdlog::warn("upstream connect failed: {}", ec.message());
                        write_error(HttpStatus::BadGateway, "upstream unreachable\n");
                        return;
                    }
                    backend_ = std::move(upstream);
                    send_backend_request(std::move(head), std::move(body));
                });
        });
}

void RelaySession::send_backend_request(HttpRequestHead head, BodySourcePtr body) {
    auto self = shared_from_this();
    backend_codec_->async_write_request(
        backend_, std::move(head), std::move(body),
        [this, self](asio::error_code ec) {
            if (ec) {
                spdlog::warn("relay: backend request write failed: {}",
                             ec.message());
                close_backend();
                write_error(HttpStatus::BadGateway, "backend write error\n");
                return;
            }
            response_phase();
        });
}

void RelaySession::response_phase() {
    auto self = shared_from_this();
    backend_codec_->async_parse_response(
        backend_,
        [this, self](asio::error_code ec, HttpResponseHead resp,
                     BodySourcePtr resp_body, bool /*backend_keep_alive*/) {
            if (ec) {
                spdlog::warn("relay: backend response parse failed: {}",
                             ec.message());
                close_backend();
                write_error(HttpStatus::BadGateway, "backend response error\n");
                return;
            }
            // HEAD request: the response's Content-Length is a would-be
            // length — no body follows, suppress it to avoid hanging.
            if (request_method_ == "HEAD")
                resp_body = nullptr;
            client_codec_->async_write_response(
                client_, std::move(resp), std::move(resp_body),
                [this, self](asio::error_code) {
                    close_backend();
                    after_client_response();
                });
        });
}

void RelaySession::close_backend() {
    if (backend_) {
        backend_->async_shutdown([](asio::error_code) {});
        backend_.reset();
    }
}

void RelaySession::after_client_response() {
    // Step 1: the backend connection is closed per request; only the client
    // connection may persist (H1 keep-alive). Step 2 will return the backend
    // to a pool instead of closing it.
    if (client_keep_alive_ && !done_)
        request_phase(); // loop: parse the next request on this connection
    else
        teardown();
}

void RelaySession::write_error(HttpStatus status, const std::string& msg) {
    auto self = shared_from_this();
    HttpResponseHead resp;
    resp.status_code = static_cast<int>(status);
    resp.reason = status_reason(status);
    resp.headers.set("content-type", "text/plain");
    resp.headers.set("content-length", std::to_string(msg.size()));
    client_codec_->async_write_response(
        client_, std::move(resp), std::make_shared<BufferBodySource>(msg),
        [this, self](asio::error_code) { after_client_response(); });
}

void RelaySession::teardown() {
    if (done_)
        return;
    done_ = true;
    spdlog::debug("relay: tearing down {}", client_->stream_id());
    client_->async_shutdown([](asio::error_code) {});
    close_backend();
}

} // namespace ebpf_quic_proxy
