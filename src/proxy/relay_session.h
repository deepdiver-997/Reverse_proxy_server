#pragma once

#include "codec/icodec.h"
#include "transport/itransport_stream.h"
#include <memory>
#include <string>

namespace ebpf_quic_proxy {

/// Bridges one parsed client request to a backend and relays the response back
/// to the client, both directions through codecs (ADR-7).
///
/// Holds both streams as shared_ptr: the backend stream can later be returned
/// to an upstream connection pool — the pool holds one ref while idle, the
/// relay holds one while active, and releasing the relay's ref on teardown is
/// exactly the "check-out / check-in" boundary.
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    RelaySession(ITransportStreamPtr client, ITransportStreamPtr backend,
                 ICodec* client_codec, ICodec* backend_codec);

    /// Forward one already-parsed request and relay the response back.
    /// `request_method` is used to suppress the body on HEAD responses
    /// (a HEAD response's Content-Length is a "would-be" length — no body
    /// follows on the wire, so reading it would hang).
    void forward(HttpRequestHead head, BodySourcePtr body,
                 const std::string& request_method);

private:
    void send_backend_request(HttpRequestHead head, BodySourcePtr body);
    void relay_response();
    void teardown();

    ITransportStreamPtr client_;
    ITransportStreamPtr backend_;
    ICodec* client_codec_;  // owned by ProxyCore, outlives this
    ICodec* backend_codec_; // owned by ProxyCore, outlives this
    std::string request_method_;
    bool done_ = false;
};

using RelaySessionPtr = std::shared_ptr<RelaySession>;

} // namespace ebpf_quic_proxy
