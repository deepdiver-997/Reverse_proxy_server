#include "h3_codec.h"
#include "http_message.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace ebpf_quic_proxy {

// ═══════════════════════════════════════════════════════════
// QUIC varint (RFC 9000 §16)
// ═══════════════════════════════════════════════════════════

VarintResult decode_varint(const uint8_t* data, std::size_t len) {
    if (len < 1)
        return {0, 0};
    uint8_t first = data[0];
    uint8_t tag = first >> 6;
    std::size_t bytes;
    switch (tag) {
    case 0: bytes = 1; break;
    case 1: bytes = 2; break;
    case 2: bytes = 4; break;
    default: bytes = 8; break;
    }
    if (len < bytes)
        return {0, 0};
    uint64_t value = 0;
    if (bytes == 1) {
        value = first & 0x3F;
    } else if (bytes == 2) {
        value = ((uint64_t)(first & 0x3F) << 8) | data[1];
    } else if (bytes == 4) {
        value = ((uint64_t)(first & 0x3F) << 24) |
                ((uint64_t)data[1] << 16) | ((uint64_t)data[2] << 8) | data[3];
    } else {
        value = ((uint64_t)(first & 0x3F) << 56) |
                ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) |
                ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) |
                ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | data[7];
    }
    return {value, bytes};
}

std::size_t varint_size(uint64_t value) {
    if (value <= 0x3F)
        return 1;
    if (value <= 0x3FFF)
        return 2;
    if (value <= 0x3FFFFFFF)
        return 4;
    return 8;
}

std::size_t encode_varint(uint64_t value, uint8_t* out) {
    std::size_t bytes = varint_size(value);
    switch (bytes) {
    case 1:
        out[0] = static_cast<uint8_t>(value);
        break;
    case 2:
        out[0] = 0x40 | static_cast<uint8_t>(value >> 8);
        out[1] = static_cast<uint8_t>(value);
        break;
    case 4:
        out[0] = 0x80 | static_cast<uint8_t>(value >> 24);
        out[1] = static_cast<uint8_t>(value >> 16);
        out[2] = static_cast<uint8_t>(value >> 8);
        out[3] = static_cast<uint8_t>(value);
        break;
    case 8:
        out[0] = 0xC0 | static_cast<uint8_t>(value >> 56);
        out[1] = static_cast<uint8_t>(value >> 48);
        out[2] = static_cast<uint8_t>(value >> 40);
        out[3] = static_cast<uint8_t>(value >> 32);
        out[4] = static_cast<uint8_t>(value >> 24);
        out[5] = static_cast<uint8_t>(value >> 16);
        out[6] = static_cast<uint8_t>(value >> 8);
        out[7] = static_cast<uint8_t>(value);
        break;
    }
    return bytes;
}

// ═══════════════════════════════════════════════════════════
// H3 literal header parsing (standalone helper — kept for unit tests)
// ═══════════════════════════════════════════════════════════

namespace h3_detail {

bool parse_request_headers(
    const uint8_t* data, std::size_t len,
    std::string& method, std::string& path, HeaderMap& hdrs,
    std::optional<std::size_t>& content_length) {

    std::size_t pos = 0;
    while (pos < len) {
        // Name: varint length + bytes
        if (pos >= len)
            return false;
        auto vr = decode_varint(data + pos, len - pos);
        if (vr.bytes_read == 0)
            return false;
        pos += vr.bytes_read;
        std::size_t name_len = static_cast<std::size_t>(vr.value);
        if (pos + name_len > len)
            return false;
        std::string name(reinterpret_cast<const char*>(data + pos), name_len);
        pos += name_len;

        // Value: varint length + bytes
        vr = decode_varint(data + pos, len - pos);
        if (vr.bytes_read == 0)
            return false;
        pos += vr.bytes_read;
        std::size_t value_len = static_cast<std::size_t>(vr.value);
        if (pos + value_len > len)
            return false;
        std::string value(reinterpret_cast<const char*>(data + pos), value_len);
        pos += value_len;

        // Route pseudo-headers.
        if (name == ":method") {
            method = std::move(value);
        } else if (name == ":path") {
            path = std::move(value);
        } else if (name == ":authority") {
            hdrs.add("host", std::move(value));
        } else if (name == "content-length") {
            content_length = std::stoull(value);
        } else if (!name.empty() && name[0] != ':') {
            hdrs.add(std::move(name), std::move(value));
        }
    }
    return true;
}

// ── Decoded-header-list → IR (transport only decodes; we interpret) ──

HttpRequestHead request_head_from_headers(
    const ITransportStream::HeaderList& raw) {
    HttpRequestHead head;
    head.version = "HTTP/3"; // H3 has no version line — it is always 3
    for (const auto& [n, v] : raw) {
        if (n == ":method") {
            head.method = v;
        } else if (n == ":path") {
            head.path = v;
        } else if (n == ":scheme") {
            head.scheme = v;
        } else if (n == ":authority") {
            // Map :authority → host so Host-based routing works uniformly with
            // H1; keep the field for forward-proxy direct connects.
            head.authority = v;
            head.headers.set("host", v);
        } else if (n.empty() || n[0] == ':') {
            continue; // unknown pseudo-header — skip
        } else {
            head.headers.add(n, v);
        }
    }
    if (auto cl = head.headers.get("content-length")) {
        char* end = nullptr;
        head.content_length = std::strtoul(cl->c_str(), &end, 10);
    }
    return head;
}

HttpResponseHead response_head_from_headers(
    const ITransportStream::HeaderList& raw) {
    HttpResponseHead head;
    head.reason = ""; // HTTP/3 has no reason phrase (RFC 9114 §4.1)
    head.version = "HTTP/3"; // H3 has no version line — it is always 3
    for (const auto& [n, v] : raw) {
        if (n == ":status") {
            char* end = nullptr;
            long sc = std::strtol(v.c_str(), &end, 10);
            head.status_code = static_cast<int>(sc);
        } else if (n.empty() || n[0] == ':') {
            continue; // other pseudo-headers don't belong in a response
        } else {
            head.headers.add(n, v);
        }
    }
    if (auto cl = head.headers.get("content-length")) {
        char* end = nullptr;
        head.content_length = std::strtoul(cl->c_str(), &end, 10);
    }
    return head;
}

} // namespace h3_detail

namespace {

// RFC 9113 §8.1.2.2: hop-by-hop headers describe a single HTTP/1.1 connection
// (framing, upgrade, proxies) and must NOT be carried over HTTP/2 or HTTP/3.
// The body framing is DATA frames, not chunked; Connection/Upgrade are end-to-
// end concepts only in the upgrade handshake, which H3 replaces (Extended
// CONNECT).  Strip them when re-serializing for an H3 peer.
bool is_hop_by_hop(const std::string& name) {
    std::string l(name);
    std::transform(l.begin(), l.end(), l.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return l == "connection" || l == "keep-alive" ||
           l == "proxy-connection" || l == "transfer-encoding" ||
           l == "upgrade";
}

} // namespace

// ═══════════════════════════════════════════════════════════
// H3Codec — async_parse_request
// ═══════════════════════════════════════════════════════════

void H3Codec::async_parse_request(ITransportStreamPtr stream,
                                   ParseCallback cb) {
    // ADR-8 (route B): headers come pre-decoded from the transport (lsquic
    // QPACK) as a raw list; interpret them into the request IR here.  The body
    // is the stream's DATA payloads read until FIN.
    bool ok = stream->async_take_headers(
        [stream, cb = std::move(cb)](
            asio::error_code ec, ITransportStream::HeaderList raw) mutable {
            if (ec) {
                cb(ec, {}, nullptr, false);
                return;
            }
            auto head = h3_detail::request_head_from_headers(raw);
            auto body = std::make_shared<StreamEofBodySource>(stream);
            // HTTP/3 streams are one-shot — the connection persists at the
            // session level, not via keep-alive on this stream.
            cb({}, std::move(head), std::move(body), /*keep_alive=*/false);
        });
    if (!ok) {
        cb(asio::error::operation_not_supported, {}, nullptr, false);
    }
}

// ═══════════════════════════════════════════════════════════
// H3Codec — async_parse_response
// ═══════════════════════════════════════════════════════════

void H3Codec::async_parse_response(ITransportStreamPtr stream,
                                   ResponseCallback cb) {
    // Same decoded-header machinery as the request path; the response IR picks
    // up `:status`.  Only reachable once an HTTP/3 upstream transport exists.
    bool ok = stream->async_take_headers(
        [stream, cb = std::move(cb)](
            asio::error_code ec, ITransportStream::HeaderList raw) mutable {
            if (ec) {
                cb(ec, {}, nullptr, false);
                return;
            }
            auto resp = h3_detail::response_head_from_headers(raw);
            auto body = std::make_shared<StreamEofBodySource>(stream);
            cb({}, std::move(resp), std::move(body), /*keep_alive=*/false);
        });
    if (!ok)
        cb(asio::error::operation_not_supported, {}, nullptr, false);
}

// ═══════════════════════════════════════════════════════════
// H3Codec — async_write_request
// ═══════════════════════════════════════════════════════════

void H3Codec::async_write_request(ITransportStreamPtr stream,
                                  HttpRequestHead head, BodySourcePtr body,
                                  WriteCallback cb) {
    // Serialize the IR as HTTP/3 pseudo-headers + regular fields, then pump
    // the body as DATA payloads.  Only reachable once an HTTP/3 upstream
    // transport exists.
    ITransportStream::HeaderList headers;
    headers.emplace_back(":method",
                         head.method.empty() ? "GET" : head.method);
    headers.emplace_back(":scheme",
                         head.scheme.empty() ? "http" : head.scheme);
    std::string authority = head.authority;
    if (authority.empty())
        authority = head.headers.get("host").value_or("");
    headers.emplace_back(":authority", std::move(authority));
    headers.emplace_back(":path", head.path.empty() ? "/" : head.path);
    for (const auto& [k, v] : head.headers.entries()) {
        if (is_hop_by_hop(k))
            continue; // RFC 9113 §8.1.2.2 — framing/upgrade headers don't cross
        headers.emplace_back(k, v);
    }

    bool ok = stream->async_send_headers(
        headers,
        [stream, body = std::move(body), cb = std::move(cb)](
            asio::error_code ec, std::size_t) mutable {
            if (ec || !body) {
                cb(ec);
                return;
            }
            pump_body_to_stream(std::move(stream), std::move(body),
                                std::move(cb));
        });
    if (!ok)
        cb(asio::error::operation_not_supported);
}

// ═══════════════════════════════════════════════════════════
// H3Codec — async_write_response
// ═══════════════════════════════════════════════════════════

void H3Codec::async_write_response(ITransportStreamPtr stream,
                                   HttpResponseHead head, BodySourcePtr body,
                                   WriteCallback cb) {
    // Send the header block via lsquic_stream_send_headers, then pump the body
    // as DATA payloads.  Hop-by-hop headers from the H1 upstream (e.g.
    // "transfer-encoding: chunked", "connection") are stripped — they describe
    // the upstream connection, not this H3 response (RFC 9113 §8.1.2.2).
    ITransportStream::HeaderList headers;
    headers.emplace_back(":status", std::to_string(head.status_code));
    for (const auto& [k, v] : head.headers.entries()) {
        if (is_hop_by_hop(k))
            continue;
        headers.emplace_back(k, v);
    }

    bool ok = stream->async_send_headers(
        headers,
        [stream, body = std::move(body), cb = std::move(cb)](
            asio::error_code ec, std::size_t) mutable {
            if (ec || !body) {
                cb(ec);
                return;
            }
            pump_body_to_stream(std::move(stream), std::move(body),
                                std::move(cb));
        });
    if (!ok)
        cb(asio::error::operation_not_supported);
}

} // namespace ebpf_quic_proxy
