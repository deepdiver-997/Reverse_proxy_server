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
                                         ITransportStreamPtr upstream,
                                         const BackendEndpoint& endpoint,
                                         bool from_pool) mutable {
                    if (ec) {
                        spdlog::warn("upstream connect failed: {}", ec.message());
                        write_error(HttpStatus::BadGateway, "upstream unreachable\n");
                        return;
                    }
                    backend_ = std::move(upstream);
                    backend_endpoint_ = endpoint;
                    backend_from_pool_ = from_pool;
                    pending_head_ =
                        std::make_shared<HttpRequestHead>(std::move(head));
                    pending_body_ = std::move(body);
                    send_backend_request(/*retry_allowed=*/true);
                });
        });
}

void RelaySession::send_backend_request(bool retry_allowed) {
    auto self = shared_from_this();
    backend_codec_->async_write_request(
        backend_, *pending_head_, pending_body_,
        [this, self, retry_allowed](asio::error_code ec) {
            if (ec) {
                spdlog::warn("relay: backend request write failed: {}",
                             ec.message());
                // A pooled connection may be stale (backend closed it while
                // idle).  Retry once on a fresh connection — but only with no
                // request body, since a partially-consumed body can't replay.
                if (retry_allowed && backend_from_pool_ && !pending_body_) {
                    spdlog::debug("relay: pooled backend stale — reconnecting fresh");
                    reconnect_backend_fresh();
                    return;
                }
                close_backend();
                write_error(HttpStatus::BadGateway, "backend write error\n");
                return;
            }
            pending_head_.reset();
            pending_body_.reset();
            response_phase();
        });
}

void RelaySession::reconnect_backend_fresh() {
    auto self = shared_from_this();
    close_backend();
    pool_->async_connect_fresh(
        backend_endpoint_,
        [this, self](asio::error_code ec, ITransportStreamPtr upstream,
                     const BackendEndpoint& endpoint, bool) {
            if (ec) {
                write_error(HttpStatus::BadGateway, "upstream unreachable\n");
                return;
            }
            backend_ = std::move(upstream);
            backend_endpoint_ = endpoint;
            backend_from_pool_ = false;
            send_backend_request(/*retry_allowed=*/false); // one retry only
        });
}

void RelaySession::response_phase() {
    auto self = shared_from_this();
    backend_codec_->async_parse_response(
        backend_,
        [this, self](asio::error_code ec, HttpResponseHead resp,
                     BodySourcePtr resp_body, bool backend_keep_alive) {
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
                [this, self, backend_keep_alive](asio::error_code) {
                    finish_backend(backend_keep_alive);
                    after_client_response();
                });
        });
}

void RelaySession::finish_backend(bool keep_alive) {
    pending_head_.reset();
    pending_body_.reset();
    if (!backend_)
        return;
    if (keep_alive) {
        spdlog::debug("relay: returning backend {}:{} to pool",
                      backend_endpoint_.host, backend_endpoint_.port);
        pool_->release(backend_endpoint_, std::move(backend_));
    } else {
        close_backend();
    }
}

void RelaySession::close_backend() {
    if (backend_) {
        backend_->async_shutdown([](asio::error_code) {});
        backend_.reset();
    }
}

void RelaySession::after_client_response() {
    // The backend connection is now pooled or closed (finish_backend).  The
    // client connection may persist (H1 keep-alive) — loop back for the next
    // request.
    if (client_keep_alive_ && !done_)
        request_phase();
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
