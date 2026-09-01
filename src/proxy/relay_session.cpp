#include "relay_session.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>

namespace ebpf_quic_proxy {

RelaySession::RelaySession(ITransportStreamPtr client, ICodec* client_codec,
                           ICodec* h1_codec, ICodec* h3_codec, Router* router,
                           UpstreamPool* pool, asio::io_context& io,
                           std::chrono::seconds idle_timeout)
    : client_(std::move(client)),
      client_codec_(client_codec),
      h1_codec_(h1_codec),
      h3_codec_(h3_codec),
      backend_codec_(h1_codec), // default; use_backend may switch to h3
      router_(router),
      pool_(pool),
      io_(io),
      idle_timeout_(idle_timeout),
      idle_timer_(io) {}

void RelaySession::start() { request_phase(); }

void RelaySession::request_phase() {
    auto self = shared_from_this();
    goto_phase(Phase::kRequest); // only a read is pending — FIN is safe here
    kick_idle_timer(); // covers the initial connect + keep-alive idle window
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
            goto_phase(Phase::kForward); // an exchange is beginning — no more FIN
            client_keep_alive_ = keep_alive;
            request_method_ = head.method;
            client_version_ = head.version; // echo the client's wire version
            // WebSocket / Upgrade: forwarded normally; a 101 response later
            // switches this relay into raw byte-bridge mode.
            request_is_upgrade_ = is_upgrade_request(head);
            kick_idle_timer(); // request arrived — restart the idle window

            spdlog::info("{} {} {} from {}", head.method, head.path,
                         head.headers.get("host").value_or("-"),
                         client_->stream_id());

            // CONNECT → a raw bidirectional tunnel to the requested target
            // (forward-proxy style), bypassing the route table entirely.
            if (head.method == "CONNECT") {
                handle_connect(std::move(head));
                return;
            }

            // Absolute-form target ("GET http://host/path") → the client is
            // using this proxy as a FORWARD proxy: connect straight to the
            // URL's authority, skip the route table.
            if (head.absolute_target) {
                handle_forward(std::move(head), std::move(body));
                return;
            }

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
                    use_backend(ec, std::move(upstream), endpoint, from_pool,
                                std::move(head), std::move(body));
                });
        });
}

// ── Forward proxy: absolute-form target ───────────────────

void RelaySession::handle_forward(HttpRequestHead head, BodySourcePtr body) {
    // The request-target was absolute-form; `head` already carries the URL's
    // scheme/authority and an origin-form path (H1Codec normalized it).  Plain
    // HTTP forward proxy — https absolute-form is invalid (clients must use
    // CONNECT to tunnel TLS), so reject it.
    if (head.scheme != "http") {
        spdlog::warn("forward: unsupported scheme '{}' (https needs CONNECT)",
                     head.scheme);
        write_error(HttpStatus::BadRequest,
                    "https absolute-form requires CONNECT\n");
        return;
    }

    // Split authority "host[:port]" — default port 80 for http.
    std::string host = head.authority;
    uint16_t port = 80;
    auto colon = head.authority.rfind(':');
    if (colon != std::string::npos) {
        char* end = nullptr;
        unsigned long p =
            std::strtoul(head.authority.c_str() + colon + 1, &end, 10);
        if (colon == 0 || p == 0 || p > 65535) {
            write_error(HttpStatus::BadRequest, "bad target\n");
            return;
        }
        host = head.authority.substr(0, colon);
        port = static_cast<uint16_t>(p);
    }

    // The origin must be identified by the URL authority (RFC 9110 §3.2.2).
    head.headers.set("host", head.authority);

    spdlog::info("forward {} http://{}{} from {}", head.method,
                 head.authority, head.path, client_->stream_id());

    BackendEndpoint target{"", host, port, 1};
    auto self = shared_from_this();
    pool_->async_connect_fresh(
        target,
        [this, self, head = std::move(head), body = std::move(body)](
            asio::error_code ec, ITransportStreamPtr upstream,
            const BackendEndpoint& endpoint, bool from_pool) mutable {
            use_backend(ec, std::move(upstream), endpoint, from_pool,
                        std::move(head), std::move(body));
        });
}

// ── Shared connect handling (reverse proxy + forward proxy) ──

void RelaySession::use_backend(asio::error_code ec,
                               ITransportStreamPtr upstream,
                               const BackendEndpoint& endpoint, bool from_pool,
                               HttpRequestHead head, BodySourcePtr body) {
    if (ec) {
        spdlog::warn("upstream connect failed: {}", ec.message());
        write_error(HttpStatus::BadGateway, "upstream unreachable\n");
        return;
    }
    backend_ = std::move(upstream);
    backend_endpoint_ = endpoint;
    kick_idle_timer(); // backend connected — waiting on connect is bounded too
    // Pick the backend codec from the endpoint's protocol: QUIC upstream
    // speaks HTTP/3, TCP speaks HTTP/1.1.
    backend_codec_ =
        (endpoint.protocol == TransportProtocol::QUIC) ? h3_codec_ : h1_codec_;
    backend_from_pool_ = from_pool;
    spdlog::debug("relay: backend connected {}:{} (from_pool={}, proto={})",
                  endpoint.host, endpoint.port, from_pool,
                  endpoint.protocol == TransportProtocol::QUIC ? "h3" : "h1");
    pending_head_ = std::make_shared<HttpRequestHead>(std::move(head));
    pending_body_ = std::move(body);
    send_backend_request(/*retry_allowed=*/true);
}

bool RelaySession::is_upgrade_request(const HttpRequestHead& head) const {
    // WebSocket and other protocol upgrades announce themselves with an
    // "Upgrade" header plus a "Connection: upgrade" token (RFC 9110 §7.8).
    if (!head.headers.get("upgrade"))
        return false;
    if (auto c = head.headers.get("connection")) {
        std::string lower = *c;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char ch) {
                           return static_cast<char>(std::tolower(ch));
                       });
        return lower.find("upgrade") != std::string::npos;
    }
    return false;
}

// ── CONNECT tunnel (Bridge mode) ──────────────────────────

void RelaySession::handle_connect(HttpRequestHead head) {
    // target is in the request path: "host:port".
    auto colon = head.path.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= head.path.size()) {
        write_error(HttpStatus::BadRequest, "bad CONNECT target\n");
        return;
    }
    std::string host = head.path.substr(0, colon);
    char* end = nullptr;
    unsigned long port = std::strtoul(head.path.c_str() + colon + 1, &end, 10);
    if (host.empty() || port == 0 || port > 65535) {
        write_error(HttpStatus::BadRequest, "bad CONNECT target\n");
        return;
    }

    spdlog::info("CONNECT {}:{} from {}", host, port, client_->stream_id());

    BackendEndpoint target{"", host, static_cast<uint16_t>(port), 1};
    auto self = shared_from_this();
    pool_->async_connect_fresh(
        target,
        [this, self](asio::error_code ec, ITransportStreamPtr stream,
                     const BackendEndpoint& endpoint, bool) {
            if (ec) {
                write_error(HttpStatus::BadGateway, "connect failed\n");
                return;
            }
            backend_ = std::move(stream);
            backend_endpoint_ = endpoint;
            start_tunnel();
        });
}

void RelaySession::start_tunnel() {
    // Send "200 Connection Established" through the client codec (correct H1
    // framing for this H1-only method), then switch to raw byte bridging.
    auto self = shared_from_this();
    HttpResponseHead resp;
    resp.status_code = 200;
    resp.reason = "Connection Established";
    client_codec_->async_write_response(
        client_, std::move(resp), nullptr,
        [this, self](asio::error_code ec) {
            if (ec) {
                teardown();
                return;
            }
            bridge_mode();
        });
}

void RelaySession::bridge_mode() {
    goto_phase(Phase::kBridge);
    // Two independent event-driven pumps: client ⇄ target.  When either side
    // ends (EOF/error), teardown closes both.
    pump_bytes(client_, backend_);
    pump_bytes(backend_, client_);
}

void RelaySession::pump_bytes(ITransportStreamPtr src, ITransportStreamPtr dst) {
    auto self = shared_from_this();
    auto buf = std::make_shared<std::array<char, 16384>>();
    src->async_read_some(
        asio::buffer(*buf),
        [this, self, src, dst, buf](asio::error_code ec, std::size_t n) mutable {
            if (done_)
                return;
            if (ec || n == 0) { // source closed / EOF
                teardown();
                return;
            }
            kick_idle_timer(); // tunnel traffic (read direction)
            dst->async_write_some(
                asio::buffer(buf->data(), n),
                [this, self, src, dst, buf](asio::error_code ec,
                                            std::size_t) mutable {
                    if (done_)
                        return;
                    if (ec) {
                        teardown();
                        return;
                    }
                    kick_idle_timer(); // tunnel traffic (write direction)
                    pump_bytes(src, dst); // continue pumping
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
            kick_idle_timer(); // request written to backend
            spdlog::debug("relay: backend request written");
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
    goto_phase(Phase::kResponse);
    kick_idle_timer(); // awaiting the backend response
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

            spdlog::debug("relay: backend response {} {}", resp.status_code,
                          resp.reason);
            // Re-serialize the status line with the CLIENT's version (the
            // backend's version described the backend connection).  H1 write
            // preserves it; H3 write ignores it.
            if (!client_version_.empty())
                resp.version = client_version_;
            kick_idle_timer(); // backend responded

            // 101 Switching Protocols: the backend accepted an Upgrade (e.g.
            // WebSocket).  Hand off the 101 (which has no body), then switch
            // this relay to a raw byte bridge.  The backend connection is NOT
            // returned to the pool — it's now a live tunnel.
            if (request_is_upgrade_ && resp.status_code == 101) {
                spdlog::info("relay: {} -> 101 upgrade, bridging",
                             client_->stream_id());
                client_codec_->async_write_response(
                    client_, std::move(resp), nullptr,
                    [this, self](asio::error_code ec) {
                        if (ec) {
                            teardown();
                            return;
                        }
                        backend_from_pool_ = false; // never pool an upgraded conn
                        bridge_mode();
                    });
                return;
            }

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
    // request.  But if the server is shutting down (draining_), close this
    // client gracefully instead: FIN, consume to EOF, then tear down.
    if (draining_) {
        gracefully_close_client();
        return;
    }
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

// ── Graceful close (server shutdown) ──────────────────────

void RelaySession::graceful_close() {
    if (done_)
        return;
    spdlog::debug("relay: graceful_close {} (phase={}, draining={})",
                  client_->stream_id(), phase_name(phase_), draining_);
    draining_ = true; // close at the next safe point, don't loop keep-alive
    if (phase_ == Phase::kRequest) {
        // Between requests: only a read is pending, no client writes.  FIN now.
        // The pending request_phase read sees the peer's EOF and tears down
        // cleanly — close() then finds nothing unread, so no RST.  If a request
        // arrives first, draining_ makes after_client_response close gracefully.
        client_->async_shutdown([](asio::error_code) {});
    }
    // Mid-exchange: can't shutdown_send yet (may have pending client writes).
    // draining_ is set; after_client_response does the graceful close once the
    // current response is fully written.
}

void RelaySession::goto_phase(Phase p) {
    if (phase_ != p) {
        spdlog::debug("relay: phase {} -> {}", phase_name(phase_), phase_name(p));
        phase_ = p;
    }
}

const char* RelaySession::phase_name(Phase p) {
    switch (p) {
        case Phase::kRequest: return "request";
        case Phase::kForward: return "forward";
        case Phase::kResponse: return "response";
        case Phase::kBridge: return "bridge";
        case Phase::kClosed: return "closed";
    }
    return "?";
}

void RelaySession::gracefully_close_client() {
    if (done_)
        return;
    draining_ = true;
    client_->async_shutdown([](asio::error_code) {});
    drain_client();
}

void RelaySession::drain_client() {
    if (done_)
        return;
    auto self = shared_from_this();
    auto buf = std::make_shared<std::array<char, 4096>>();
    client_->async_read_some(
        asio::buffer(*buf),
        [this, self, buf](asio::error_code ec, std::size_t n) {
            if (done_)
                return;
            if (ec || n == 0) { // peer FIN'd / closed — safe to close now
                teardown();
                return;
            }
            kick_idle_timer(); // draining still active
            drain_client(); // keep consuming until EOF
        });
}

// ── Idle timeout ──────────────────────────────────────────

void RelaySession::kick_idle_timer() {
    if (done_ || idle_timeout_.count() <= 0)
        return;
    // Re-arming cancels the previous wait (its handler fires with
    // operation_aborted and returns).  Reset on every relay-visible activity;
    // note the codec's internal body-pump reads/writes are not observed here,
    // so this is effectively a per-phase completion timeout as well as an
    // idle timeout for silent connections.
    idle_timer_.expires_after(idle_timeout_);
    idle_timer_.async_wait(
        [this, self = shared_from_this()](asio::error_code ec) {
            if (ec) // re-armed or cancelled — not a timeout
                return;
            spdlog::warn("relay: idle timeout ({}s) on {}",
                         idle_timeout_.count(), client_->stream_id());
            teardown();
        });
}

void RelaySession::teardown() {
    if (done_)
        return;
    done_ = true;
    idle_timer_.cancel(); // no timeout should fire after teardown
    goto_phase(Phase::kClosed);
    spdlog::debug("relay: tearing down {}", client_->stream_id());
    client_->async_shutdown([](asio::error_code) {});
    close_backend();
}

} // namespace ebpf_quic_proxy
