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
#include <set>

namespace ebpf_quic_proxy {

class RelaySession; // fwd — live_relays_ holds weak refs to these

/// One worker: a single io_context thread hosting the relay (business), its
/// frontend TCP sockets (handed over by the ingress thread), its QUIC server
/// engine (fed by the demux), and its private backend pool (keep-alive + its
/// own QUIC client engine).  Everything about a request — frontend, backend,
/// relay — runs on this one thread (co-located, zero cross-thread marshaling).
class ProxyCore {
public:
    ProxyCore(asio::io_context& io, const ProxyConfig& cfg);

    /// Accept a TCP connection handed over by the ingress thread.  Runs on
    /// this worker's thread (posted here by the ingress).
    void on_new_tcp_socket(asio::ip::tcp::socket socket);

    /// Create the QUIC server engine (no socket — it is fed by the demux) and
    /// register this worker with the demux.  `ssl_ctx` is the shared server
    /// TLS context, created once in main.
    void start_quic(QuicPacketDemux* demux, SslCtxPtr ssl_ctx);

    /// Graceful shutdown (server stopping): FIN + drain every live frontend
    /// connection on this worker, and GOAWAY every live QUIC server connection.
    /// Posts to this worker's io_context — callable from any thread.  Idle
    /// keep-alive clients get FIN now (their pending read sees the peer's EOF
    /// and tears down cleanly); in-flight exchanges finish, then close
    /// gracefully instead of looping for the next request.
    void graceful_shutdown();

    /// Final step (after the grace period): force CONNECTION_CLOSE on every
    /// remaining QUIC server connection and flush the frames now.  Posts to
    /// this worker's io_context.
    void force_close_quic();

private:
    void on_session(ITransportSessionPtr session);
    void on_stream(ITransportStreamPtr stream, ICodec* codec);

    asio::io_context& io_;
    std::unique_ptr<QuicServerEngine> quic_engine_;
    std::unique_ptr<ICodec> h1_codec_;
    std::unique_ptr<ICodec> h3_codec_;
    Router router_;
    UpstreamPool upstream_pool_;

    /// Live client relays on this worker (weak — a relay removes itself by
    /// dying; expired entries are pruned during graceful_shutdown).  Only ever
    /// touched on this worker's thread.
    std::set<std::weak_ptr<RelaySession>,
             std::owner_less<std::weak_ptr<RelaySession>>>
        live_relays_;
};

} // namespace ebpf_quic_proxy
