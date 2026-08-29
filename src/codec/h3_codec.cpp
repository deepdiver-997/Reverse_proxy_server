#include "h3_codec.h"
#include "http_message.h"
#include <spdlog/spdlog.h>

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

} // namespace h3_detail

// ═══════════════════════════════════════════════════════════
// H3Codec — async_parse_request
// ═══════════════════════════════════════════════════════════

void H3Codec::async_parse_request(ITransportStreamPtr stream,
                                   ParseCallback cb) {
    // ADR-8 (route B): request headers come pre-decoded from the transport
    // (lsquic QPACK, see QuicTransportStream::try_take_headers); the body is
    // the stream's DATA payloads read until FIN.
    bool ok = stream->async_take_headers(
        [stream, cb = std::move(cb)](asio::error_code ec,
                                     HttpRequestHead head) mutable {
            if (ec) {
                cb(ec, {}, nullptr, false);
                return;
            }
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
// H3Codec — async_write_response
// ═══════════════════════════════════════════════════════════

void H3Codec::async_write_response(ITransportStreamPtr stream,
                                    HttpResponseHead head, BodySourcePtr body,
                                    WriteCallback cb) {
    // Send the header block via lsquic_stream_send_headers, then pump the body
    // as DATA payloads.
    ITransportStream::HeaderList headers;
    headers.emplace_back(":status", std::to_string(head.status_code));
    for (const auto& [k, v] : head.headers.entries())
        headers.emplace_back(k, v);

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
// H3Codec — async_parse_response / async_write_request
// ═══════════════════════════════════════════════════════════
// Only needed when the UPSTREAM speaks HTTP/3.  Not wired yet (the upstream
// side is HTTP/1.1), so these are explicit "not supported" stubs.

void H3Codec::async_parse_response(ITransportStreamPtr stream,
                                   ResponseCallback cb) {
    spdlog::warn("H3: async_parse_response not implemented (H3 upstream not wired)");
    cb(asio::error::operation_not_supported, {}, nullptr, false);
}

void H3Codec::async_write_request(ITransportStreamPtr stream,
                                  HttpRequestHead head, BodySourcePtr body,
                                  WriteCallback cb) {
    spdlog::warn("H3: async_write_request not implemented (H3 upstream not wired)");
    cb(asio::error::operation_not_supported);
}

} // namespace ebpf_quic_proxy
