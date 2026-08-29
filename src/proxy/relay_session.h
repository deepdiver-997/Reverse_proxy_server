#pragma once

#include "codec/icodec.h"
#include "router.h"
#include "transport/itransport_stream.h"
#include "upstream_pool.h"
#include <memory>
#include <string>

namespace ebpf_quic_proxy {

/// Bridges a client stream and a per-request backend stream, relaying HTTP
/// messages in a phase machine (ADR-7):
///
///   Request phase:  parse client request → route → connect backend → write
///   Response phase: parse backend response → write to client
///   after response: if client keep-alive (codec-reported) → back to Request,
///                   else teardown
///
/// The keep-alive decision comes from the codec's parse callbacks (Connection
/// header / HTTP version / body framing), not hard-coded per transport.
/// Router + UpstreamPool are injected (owned by ProxyCore, outlive this).
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    RelaySession(ITransportStreamPtr client, ICodec* client_codec,
                 ICodec* backend_codec, Router* router, UpstreamPool* pool);

    /// Begin relaying (enters the Request phase).
    void start();

private:
    void request_phase();
    void send_backend_request(HttpRequestHead head, BodySourcePtr body);
    void response_phase();
    void close_backend();
    void after_client_response();
    void write_error(HttpStatus status, const std::string& msg);
    void teardown();

    ITransportStreamPtr client_;
    ITransportStreamPtr backend_;
    ICodec* client_codec_;  // owned by ProxyCore, outlives this
    ICodec* backend_codec_; // owned by ProxyCore, outlives this
    Router* router_;
    UpstreamPool* pool_;
    std::string request_method_;
    bool client_keep_alive_ = false;
    bool done_ = false;
};

using RelaySessionPtr = std::shared_ptr<RelaySession>;

} // namespace ebpf_quic_proxy
