#pragma once

#include "codec/http_message.h"
#include "codec/icodec.h"
#include "config.h"
#include "router.h"
#include "transport/itransport_session.h"
#include "transport/itransport_stream.h"
#include "transport/quic_transport.h"
#include "upstream_pool.h"
#include <asio.hpp>
#include <memory>

namespace ebpf_quic_proxy {

class ProxyCore {
public:
    ProxyCore(asio::io_context& io, const ProxyConfig& cfg);

    /// Start TCP listener.  Does not block — runs on the io_context.
    void start_tcp();

    /// Start QUIC listener.  Requires TLS cert/key.
    void start_quic(uint16_t port, const std::string& cert_file,
                    const std::string& key_file);

private:
    void do_accept();
    void on_session(ITransportSessionPtr session);
    void on_stream(ITransportStreamPtr stream, ICodec* codec);
    void forward_request(ITransportStreamPtr client_stream,
                         HttpRequestHead head, BodySourcePtr body,
                         const std::string& backend_id);

    asio::io_context& io_;
    ITransportListenerPtr tcp_listener_;
    std::unique_ptr<QuicTransportListener> quic_listener_;
    std::unique_ptr<ICodec> h1_codec_;
    std::unique_ptr<ICodec> h3_codec_;
    Router router_;
    UpstreamPool upstream_pool_;
};

} // namespace ebpf_quic_proxy
