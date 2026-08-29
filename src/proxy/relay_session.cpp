#include "relay_session.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

RelaySession::RelaySession(ITransportStreamPtr client, ITransportStreamPtr backend,
                           ICodec* client_codec, ICodec* backend_codec)
    : client_(std::move(client)),
      backend_(std::move(backend)),
      client_codec_(client_codec),
      backend_codec_(backend_codec) {}

void RelaySession::forward(HttpRequestHead head, BodySourcePtr body,
                           const std::string& request_method) {
    request_method_ = request_method;
    send_backend_request(std::move(head), std::move(body));
}

void RelaySession::send_backend_request(HttpRequestHead head, BodySourcePtr body) {
    auto self = shared_from_this();
    backend_codec_->async_write_request(
        backend_, std::move(head), std::move(body),
        [this, self](asio::error_code ec) {
            if (ec) {
                spdlog::warn("relay: backend request write failed: {}",
                             ec.message());
                teardown();
                return;
            }
            relay_response();
        });
}

void RelaySession::relay_response() {
    auto self = shared_from_this();
    backend_codec_->async_parse_response(
        backend_,
        [this, self](asio::error_code ec, HttpResponseHead resp,
                     BodySourcePtr resp_body) {
            if (ec) {
                spdlog::warn("relay: backend response parse failed: {}",
                             ec.message());
                teardown();
                return;
            }
            // HEAD request: the response's Content-Length is a would-be
            // length — no body follows, so suppress it to avoid hanging.
            if (request_method_ == "HEAD")
                resp_body = nullptr;
            client_codec_->async_write_response(
                client_, std::move(resp), std::move(resp_body),
                [this, self](asio::error_code) { teardown(); });
        });
}

void RelaySession::teardown() {
    if (done_)
        return;
    done_ = true;
    spdlog::debug("relay: tearing down {} <-> {}", client_->stream_id(),
                  backend_->stream_id());
    client_->async_shutdown([](asio::error_code) {});
    backend_->async_shutdown([](asio::error_code) {});
}

} // namespace ebpf_quic_proxy
