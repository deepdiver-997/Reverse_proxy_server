#include "upstream_pool.h"
#include "transport/tcp_transport.h"
#include <spdlog/spdlog.h>

namespace ebpf_quic_proxy {

UpstreamPool::UpstreamPool(asio::io_context& io, SslCtxPtr client_ssl_ctx)
    : io_(io), client_ssl_ctx_(std::move(client_ssl_ctx)) {}

void UpstreamPool::add_backend(const BackendEndpoint& be) {
    {
        std::lock_guard lock(mutex_);
        endpoints_.push_back(EndpointEntry{be, {}});
    }
    // First H3 backend creates the QUIC client engine (and wires its new-
    // session callback back to us).  The recv/tick loop starts lazily on the
    // first connect.
    if (be.protocol == TransportProtocol::QUIC) {
        std::lock_guard lock(mutex_);
        if (!quic_engine_) {
            quic_engine_ =
                std::make_unique<QuicClientEngine>(io_, client_ssl_ctx_);
            quic_engine_->set_new_session_cb(
                [this](QuicTransportSessionPtr session) {
                    on_client_conn(std::move(session));
                });
        }
    }
}

void UpstreamPool::async_connect(const std::string& backend_id,
                                 ConnectCallback cb) {
    // Find all endpoints for this backend_id.
    std::vector<EndpointEntry*> candidates;
    {
        std::lock_guard lock(mutex_);
        for (auto& e : endpoints_)
            if (e.be.backend_id == backend_id)
                candidates.push_back(&e);
    }

    if (candidates.empty()) {
        cb(asio::error::not_found, nullptr, {}, false);
        return;
    }

    // Round-robin pick among the group's endpoints.
    std::size_t idx = rr_index_.fetch_add(1) % candidates.size();
    auto* entry = candidates[idx];

    // H3 upstream: reuse an established QUIC connection (open a new stream).
    if (entry->be.protocol == TransportProtocol::QUIC) {
        quic_connect(entry->be, std::move(cb));
        return;
    }

    // Prefer a pooled idle connection over a fresh handshake.
    ITransportStreamPtr idle;
    {
        std::lock_guard lock(mutex_);
        if (!entry->idle.empty()) {
            idle = std::move(entry->idle.front());
            entry->idle.pop_front();
        }
    }
    if (idle) {
        spdlog::debug("reusing idle backend connection to {}:{}",
                      entry->be.host, entry->be.port);
        cb({}, std::move(idle), entry->be, /*from_pool=*/true);
        return;
    }

    connect_fresh_to(entry->be, std::move(cb));
}

void UpstreamPool::async_connect_fresh(const BackendEndpoint& endpoint,
                                       ConnectCallback cb) {
    if (endpoint.protocol == TransportProtocol::QUIC) {
        quic_connect_fresh(endpoint, std::move(cb));
        return;
    }
    connect_fresh_to(endpoint, std::move(cb));
}

void UpstreamPool::connect_fresh_to(const BackendEndpoint& target,
                                    ConnectCallback cb) {
    spdlog::debug("connecting to backend {} at {}:{}", target.backend_id,
                  target.host, target.port);

    // Resolve + connect.
    asio::ip::tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(target.host, std::to_string(target.port));

    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    asio::async_connect(
        *socket, endpoints,
        [socket, cb = std::move(cb),
         target](asio::error_code ec, auto /*endpoint*/) mutable {
            if (ec) {
                spdlog::warn("backend connect failed: {}", ec.message());
                cb(ec, nullptr, target, false);
                return;
            }
            auto stream =
                std::make_shared<TcpTransportStream>(std::move(*socket));
            cb({}, std::move(stream), target, /*from_pool=*/false);
        });
}

void UpstreamPool::release(const BackendEndpoint& endpoint,
                           ITransportStreamPtr stream) {
    if (endpoint.protocol == TransportProtocol::QUIC)
        return; // H3 streams are one-shot; the connection stays pooled on its own
    std::lock_guard lock(mutex_);
    for (auto& e : endpoints_) {
        if (e.be.backend_id == endpoint.backend_id &&
            e.be.host == endpoint.host && e.be.port == endpoint.port) {
            if (e.idle.size() < kMaxIdlePerEndpoint)
                e.idle.push_back(std::move(stream));
            // else: drop — the shared_ptr release closes the socket.
            return;
        }
    }
    // Unknown endpoint — dropping the ref closes the connection.
}

// ── QUIC (H3 upstream) path ───────────────────────────────

namespace {

std::string quic_key(const BackendEndpoint& ep) {
    return ep.host + ":" + std::to_string(ep.port);
}

} // namespace

void UpstreamPool::quic_connect(const BackendEndpoint& ep, ConnectCallback cb) {
    // Reuse an established connection if one is pooled.
    QuicTransportSessionPtr pooled;
    {
        std::lock_guard lock(mutex_);
        auto it = quic_conns_.find(quic_key(ep));
        if (it != quic_conns_.end() && !it->second.empty()) {
            pooled = std::move(it->second.front());
            it->second.pop_front();
            if (it->second.empty())
                quic_conns_.erase(it);
        }
    }
    if (pooled) {
        spdlog::debug("reusing QUIC connection to {}:{}", ep.host, ep.port);
        // NOTE: open_quic_stream MUST run without the mutex held.  It calls
        // lsquic_conn_make_stream, which fires on_new_stream SYNCHRONOUSLY,
        // re-entering this pool (the stream callback locks mutex_ again) — a
        // held std::mutex here would deadlock.
        open_quic_stream(std::move(pooled), ep, /*from_pool=*/true,
                         std::move(cb));
        return;
    }
    quic_connect_fresh(ep, std::move(cb));
}

void UpstreamPool::quic_connect_fresh(const BackendEndpoint& ep,
                                      ConnectCallback cb) {
    if (!quic_engine_) {
        cb(asio::error::not_found, nullptr, ep, false);
        return;
    }
    spdlog::debug("connecting to QUIC backend {} at {}:{}", ep.backend_id,
                  ep.host, ep.port);
    // Stash the pending connect; on_client_conn (called SYNCHRONOUSLY from
    // inside connect) consumes it.  Single-threaded, so a single slot is safe.
    pending_quic_ = PendingQuic{ep, std::move(cb)};
    bool ok = quic_engine_->connect(ep);
    if (!ok) {
        auto pend = std::move(*pending_quic_);
        pending_quic_.reset();
        if (pend.cb)
            pend.cb(asio::error::host_unreachable, nullptr, ep, false);
    }
}

void UpstreamPool::on_client_conn(QuicTransportSessionPtr session) {
    if (!pending_quic_) {
        spdlog::warn("QUIC: unexpected client conn (no pending connect)");
        return;
    }
    auto pend = std::move(*pending_quic_);
    pending_quic_.reset();

    // Remove this connection from the reuse table when it closes.  Capture the
    // RAW session pointer (not a shared_ptr) — capturing the shared_ptr in the
    // session's own closed_cb would recreate the cycle we deliberately break.
    QuicTransportSession* raw = session.get();
    session->set_closed_cb([this, ep = pend.endpoint, raw] {
        remove_quic_conn(ep, raw);
    });

    open_quic_stream(std::move(session), pend.endpoint, /*from_pool=*/false,
                     std::move(pend.cb));
}

void UpstreamPool::open_quic_stream(QuicTransportSessionPtr session,
                                    const BackendEndpoint& ep, bool from_pool,
                                    ConnectCallback cb) {
    // The stream arrives via on_new_stream once the handshake is done (or
    // promptly for an established conn); a nullptr stream means the connection
    // went away while the request was queued.
    session->async_open_stream(
        [this, session, ep, from_pool, cb = std::move(cb)](
            ITransportStreamPtr stream) mutable {
            if (stream) {
                // Connection is up (handshake complete) — keep it for reuse.
                // The session was popped from the pool on checkout, so put it
                // back regardless of from_pool: a QUIC connection carries many
                // streams, so it stays reusable after each request.  (If we
                // didn't, a reused conn would be lost and the next request
                // would try to create a second conn to the same address —
                // which lsquic refuses, ENG_CONNS_BY_ADDR.)
                {
                    std::lock_guard lock(mutex_);
                    quic_conns_[quic_key(ep)].push_back(session);
                }
                spdlog::debug("QUIC upstream stream on {}:{}", ep.host, ep.port);
                cb({}, std::move(stream), ep, from_pool);
            } else {
                // Connection died while opening the stream.
                remove_quic_conn(ep, session.get());
                if (from_pool)
                    quic_connect(ep, std::move(cb)); // stale pooled conn — retry fresh
                else
                    cb(asio::error::eof, nullptr, ep, false);
            }
        });
}

void UpstreamPool::remove_quic_conn(const BackendEndpoint& ep,
                                    QuicTransportSession* raw) {
    std::lock_guard lock(mutex_);
    auto it = quic_conns_.find(quic_key(ep));
    if (it == quic_conns_.end())
        return;
    auto& dq = it->second;
    for (auto itq = dq.begin(); itq != dq.end(); ++itq) {
        if (itq->get() == raw) {
            dq.erase(itq);
            break;
        }
    }
    if (dq.empty())
        quic_conns_.erase(it);
}

} // namespace ebpf_quic_proxy
