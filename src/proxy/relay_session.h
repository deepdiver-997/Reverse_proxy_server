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
/// Three special flows branch off the request phase:
///   - CONNECT host:port          → direct tunnel (byte bridge), no route table
///   - absolute-form target       → forward proxy: direct-connect to the URL's
///                                  authority (ADR-7 "backend-select" split)
///   - WebSocket Upgrade request  → forwarded; a 101 response switches to the
///                                  same byte bridge (skip pool return)
///
/// Backend connections are pooled (Step 2): idle connections are returned via
/// UpstreamPool::release and reused on the next request.  A pooled connection
/// may be stale (backend closed it while idle) — on a request write failure we
/// retry once on a fresh connection (only when there's no request body, since a
/// partially-consumed body can't be replayed).
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    /// `client_codec` matches the client's transport; `h1_codec`/`h3_codec`
    /// are both offered for the BACKEND side — the relay picks one per request
    /// from the routed endpoint's protocol (TCP → H1, QUIC → H3).
    RelaySession(ITransportStreamPtr client, ICodec* client_codec,
                 ICodec* h1_codec, ICodec* h3_codec, Router* router,
                 UpstreamPool* pool);

    /// Begin relaying (enters the Request phase).
    void start();

    /// Graceful shutdown (server stopping): close this client connection
    /// without RST.
    ///   - idle (between requests, no pending writes): FIN (shutdown_send) now —
    ///     the pending request read sees the peer's EOF and tears down cleanly.
    ///   - mid-exchange: mark draining — finish the current response, then FIN +
    ///     drain instead of looping for the next request (see after_client_response).
    ///   - tunnel: just marked draining; torn down when the peer closes or the
    ///     server's grace period hard-stops the io_context.
    /// Must be called on this relay's worker thread.
    void graceful_close();

private:
    void request_phase();
    void handle_connect(HttpRequestHead head); // CONNECT → tunnel
    void handle_forward(HttpRequestHead head, BodySourcePtr body);
    void use_backend(asio::error_code ec, ITransportStreamPtr upstream,
                     const BackendEndpoint& endpoint, bool from_pool,
                     HttpRequestHead head, BodySourcePtr body);
    bool is_upgrade_request(const HttpRequestHead& head) const;
    void start_tunnel();
    void bridge_mode();
    void pump_bytes(ITransportStreamPtr src, ITransportStreamPtr dst);
    void send_backend_request(bool retry_allowed);
    void reconnect_backend_fresh();
    void response_phase();
    void finish_backend(bool backend_keep_alive);
    void close_backend();
    void after_client_response();
    void write_error(HttpStatus status, const std::string& msg);
    void teardown();

    // Graceful-close plumbing: shutdown_send, then consume the peer's input
    // until EOF so close() (via the stream's destructor) never RSTs.
    void gracefully_close_client();
    void drain_client();

    ITransportStreamPtr client_;
    ITransportStreamPtr backend_;
    ICodec* client_codec_;  // owned by ProxyCore, outlives this
    ICodec* h1_codec_;      // backend-side codecs, owned by ProxyCore
    ICodec* h3_codec_;
    ICodec* backend_codec_; // current backend codec (set in use_backend)
    Router* router_;
    UpstreamPool* pool_;

    BackendEndpoint backend_endpoint_;
    bool backend_from_pool_ = false;
    std::shared_ptr<HttpRequestHead> pending_head_; // kept for a possible retry
    BodySourcePtr pending_body_;
    std::string request_method_;
    // Client's wire version — responses are re-serialized with it, so an
    // HTTP/1.0 client sees "HTTP/1.0" in the status line (H1 write preserves
    // it; H3 ignores it).
    std::string client_version_;
    bool client_keep_alive_ = false;
    bool request_is_upgrade_ = false; // client asked for an Upgrade (WebSocket)
    bool done_ = false;
    // Graceful shutdown state:
    //   idle_waiting_ — currently waiting in request_phase for the next request
    //                   (only a read pending, no client writes → FIN is safe).
    //   draining_     — server stopping: close gracefully at the next safe point
    //                   instead of looping keep-alive.
    bool idle_waiting_ = true;
    bool draining_ = false;
};

using RelaySessionPtr = std::shared_ptr<RelaySession>;

} // namespace ebpf_quic_proxy
