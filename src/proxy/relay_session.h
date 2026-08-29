#pragma once

#include "codec/icodec.h"
#include "config.h"
#include "router.h"
#include "transport/itransport_stream.h"
#include "upstream_pool.h"
#include <memory>
#include <string>

namespace ebpf_quic_proxy {

/// Bridges a client stream and a per-request backend stream, relaying HTTP
/// messages in a phase machine (ADR-7):
///
///   Request phase:  parse client request → route → check out/connect backend
///                   → write
///   Response phase: parse backend response → write to client
///   after response: keep-alive backend → return to pool (Step 2), else close;
///                   keep-alive client → loop to Request, else teardown
///
/// Backend connections are pooled (Step 2): idle connections are returned via
/// UpstreamPool::release and reused on the next request.  A pooled connection
/// may be stale (backend closed it while idle) — on a request write failure we
/// retry once on a fresh connection (only when there's no request body, since a
/// partially-consumed body can't be replayed).
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    RelaySession(ITransportStreamPtr client, ICodec* client_codec,
                 ICodec* backend_codec, Router* router, UpstreamPool* pool);

    /// Begin relaying (enters the Request phase).
    void start();

private:
    void request_phase();
    void send_backend_request(bool retry_allowed);
    void reconnect_backend_fresh();
    void response_phase();
    void finish_backend(bool backend_keep_alive);
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

    BackendEndpoint backend_endpoint_;
    bool backend_from_pool_ = false;
    std::shared_ptr<HttpRequestHead> pending_head_; // kept for a possible retry
    BodySourcePtr pending_body_;
    std::string request_method_;
    bool client_keep_alive_ = false;
    bool done_ = false;
};

using RelaySessionPtr = std::shared_ptr<RelaySession>;

} // namespace ebpf_quic_proxy
