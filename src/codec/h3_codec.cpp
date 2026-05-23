#include "h3_codec.h"
#include "http_message.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cstring>

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
// H3 literal header parsing
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
    auto ctx = std::make_shared<ParseCtx>();
    ctx->stream = std::move(stream);
    ctx->cb     = std::move(cb);
    parse_loop(std::move(ctx));
}

void H3Codec::parse_loop(std::shared_ptr<ParseCtx> ctx) {
    if (ctx->state == ParseState::Done)
        return;

    // Read up to 64 KiB at a time.
    static constexpr std::size_t kChunk = 65536;
    std::size_t old_size = ctx->buf.size();
    ctx->buf.resize(old_size + kChunk);
    auto* raw = ctx->stream.get();
    raw->async_read_some(
        asio::mutable_buffer(ctx->buf.data() + old_size, kChunk),
        [this, ctx](asio::error_code ec, std::size_t n) mutable {
            if (ec == asio::error::eof) {
                // Stream ended — process any remaining bytes.
                if (ctx->buf.size() > n)
                    build_request_ir(ctx);
                return;
            }
            if (ec)
                return;
            ctx->buf.resize(ctx->buf.size() - kChunk + n);
            while (true) {
                switch (ctx->state) {
                case ParseState::ExpectHeaders:
                    on_frame_header(ctx);
                    break;
                case ParseState::ReadingHeaders:
                    on_frame_header(ctx);
                    break;
                case ParseState::ExpectData:
                    on_frame_header(ctx);
                    break;
                case ParseState::ReadingData:
                    on_frame_payload(ctx);
                    break;
                case ParseState::Done:
                    return;
                }
                // If we got stuck waiting for more data, re-read.
                if (ctx->state != ParseState::Done &&
                    ctx->frame_bytes_needed > ctx->buf.size()) {
                    parse_loop(ctx);
                    return;
                }
            }
        });
}

void H3Codec::on_frame_header(std::shared_ptr<ParseCtx> ctx) {
    // We need at least 2 varints worth of bytes for a frame header.
    if (ctx->buf.size() < 2)
        return; // need more data

    auto vr_type = decode_varint(ctx->buf.data(), ctx->buf.size());
    if (vr_type.bytes_read == 0)
        return;

    if (vr_type.bytes_read >= ctx->buf.size())
        return;

    auto vr_len = decode_varint(ctx->buf.data() + vr_type.bytes_read,
                                ctx->buf.size() - vr_type.bytes_read);
    if (vr_len.bytes_read == 0)
        return;

    ctx->current_frame_type = static_cast<H3FrameType>(vr_type.value);
    ctx->frame_bytes_needed = vr_type.bytes_read + vr_len.bytes_read +
                               static_cast<std::size_t>(vr_len.value);

    // Skip SETTINGS frames — we don't act on them yet.
    if (ctx->current_frame_type == H3FrameType::SETTINGS) {
        if (ctx->buf.size() >= ctx->frame_bytes_needed) {
            ctx->buf.erase(ctx->buf.begin(),
                           ctx->buf.begin() +
                               static_cast<long>(ctx->frame_bytes_needed));
            ctx->frame_bytes_needed = 0;
        }
        return;
    }

    if (ctx->current_frame_type == H3FrameType::HEADERS) {
        ctx->state = ParseState::ReadingHeaders;
        if (ctx->buf.size() >= ctx->frame_bytes_needed)
            on_frame_payload(ctx);
    } else if (ctx->current_frame_type == H3FrameType::DATA) {
        ctx->state = ParseState::ReadingData;
        if (ctx->buf.size() >= ctx->frame_bytes_needed)
            on_frame_payload(ctx);
    }
}

void H3Codec::on_frame_payload(std::shared_ptr<ParseCtx> ctx) {
    if (ctx->buf.size() < ctx->frame_bytes_needed)
        return; // need more data

    std::size_t header_offset = 2; // approximate — need proper varint skip
    // Recalculate header offset from stored type and length.
    auto vr_type = decode_varint(ctx->buf.data(), ctx->buf.size());
    auto vr_len = decode_varint(ctx->buf.data() + vr_type.bytes_read,
                                ctx->buf.size() - vr_type.bytes_read);
    std::size_t hdr_sz = vr_type.bytes_read + vr_len.bytes_read;
    std::size_t payload_sz = static_cast<std::size_t>(vr_len.value);

    if (ctx->current_frame_type == H3FrameType::HEADERS) {
        // Save the headers payload for later assembly of the request IR.
        ctx->headers_content_offset = hdr_sz;
        ctx->headers_content_len = payload_sz;

        // Check if more frames follow (DATA frame with body).
        ctx->buf.erase(ctx->buf.begin(),
                       ctx->buf.begin() + static_cast<long>(ctx->frame_bytes_needed));
        ctx->frame_bytes_needed = 0;
        ctx->state = ParseState::ExpectData;
        return;
    }

    if (ctx->current_frame_type == H3FrameType::DATA) {
        // If there's request body, we'll build a BodySource for it.
        // For now, content-length is set from headers; body follows.
        build_request_ir(ctx);
        return;
    }

    // Unknown frame — skip.
    ctx->buf.erase(ctx->buf.begin(),
                   ctx->buf.begin() + static_cast<long>(ctx->frame_bytes_needed));
    ctx->frame_bytes_needed = 0;
}

void H3Codec::build_request_ir(std::shared_ptr<ParseCtx> ctx) {
    ctx->state = ParseState::Done;

    HttpRequestHead head;
    if (!h3_detail::parse_request_headers(
            ctx->buf.data() + ctx->headers_content_offset,
            ctx->headers_content_len, head.method, head.path, head.headers,
            head.content_length)) {
        ctx->cb(asio::error::invalid_argument, {}, nullptr);
        return;
    }

    spdlog::debug("H3: {} {} (content-length={})", head.method, head.path,
                  head.content_length.value_or(0));

    // Build body source if there's payload after the frames.
    BodySourcePtr body;
    auto vr_type = decode_varint(ctx->buf.data(), ctx->buf.size());
    auto vr_len = decode_varint(ctx->buf.data() + vr_type.bytes_read,
                                ctx->buf.size() - vr_type.bytes_read);
    std::size_t hdr_sz = vr_type.bytes_read + vr_len.bytes_read;

    if (vr_type.value == 0 && vr_len.value > 0 &&
        ctx->buf.size() > hdr_sz + vr_len.value) {
        // DATA frame present — wrap remaining bytes as body.
        std::size_t body_off = hdr_sz;
        std::size_t body_len = static_cast<std::size_t>(vr_len.value);
        std::string body_str(
            reinterpret_cast<const char*>(ctx->buf.data() + body_off),
            body_len);
        body = std::make_shared<BufferBodySource>(std::move(body_str));
    }

    ctx->cb({}, std::move(head), std::move(body));
}

// ═══════════════════════════════════════════════════════════
// H3Codec — async_write_response
// ═══════════════════════════════════════════════════════════

void H3Codec::async_write_response(ITransportStreamPtr stream,
                                    HttpResponseHead head,
                                    BodySourcePtr body,
                                    WriteCallback cb) {
    // Build HEADERS frame payload.
    // Format: varint(len(name)) + name + varint(len(value)) + value
    std::vector<uint8_t> headers_payload;

    auto append_header = [&](const std::string& name, const std::string& val) {
        uint8_t vbuf[8];
        std::size_t ns = encode_varint(name.size(), vbuf);
        headers_payload.insert(headers_payload.end(), vbuf, vbuf + ns);
        headers_payload.insert(headers_payload.end(),
                               reinterpret_cast<const uint8_t*>(name.data()),
                               reinterpret_cast<const uint8_t*>(name.data()) +
                                   name.size());
        std::size_t vs = encode_varint(val.size(), vbuf);
        headers_payload.insert(headers_payload.end(), vbuf, vbuf + vs);
        headers_payload.insert(headers_payload.end(),
                               reinterpret_cast<const uint8_t*>(val.data()),
                               reinterpret_cast<const uint8_t*>(val.data()) +
                                   val.size());
    };

    append_header(":status", std::to_string(head.status_code));
    for (const auto& [k, v] : head.headers.entries()) {
        append_header(k, v);
    }

    // Build HEADERS frame.
    uint8_t fbuf[16];
    std::size_t type_sz = encode_varint(
        static_cast<uint64_t>(H3FrameType::HEADERS), fbuf);
    std::size_t len_sz = encode_varint(headers_payload.size(), fbuf + type_sz);
    std::size_t hdr_sz = type_sz + len_sz;

    auto frame_data = std::make_shared<std::vector<uint8_t>>();
    frame_data->insert(frame_data->end(), fbuf, fbuf + hdr_sz);
    frame_data->insert(frame_data->end(), headers_payload.begin(),
                       headers_payload.end());

    spdlog::debug("H3: → {} {} ({} bytes HEADERS)",
                  head.status_code, head.reason, headers_payload.size());

    // If there's a body, append DATA frame(s).
    if (body) {
        auto body_buf = std::make_shared<std::vector<char>>(65536);
        auto* body_raw = body.get();
        body_raw->async_read_some(
            asio::buffer(*body_buf),
            [stream, body_buf, body, frame_data, cb = std::move(cb)](
                asio::error_code ec, std::size_t n) mutable {
                if (ec && ec != asio::error::eof)
                    return;

                // Append DATA frame to our buffer.
                uint8_t dbuf[16];
                std::size_t dt = encode_varint(0, dbuf); // type=DATA
                std::size_t dl = encode_varint(n, dbuf + dt);
                frame_data->insert(frame_data->end(), dbuf, dbuf + dt + dl);
                frame_data->insert(frame_data->end(),
                                   reinterpret_cast<uint8_t*>(body_buf->data()),
                                   reinterpret_cast<uint8_t*>(body_buf->data()) +
                                       n);

                // Write everything.
                stream->async_write_some(
                    asio::buffer(*frame_data),
                    [stream, frame_data, cb = std::move(cb)](
                        asio::error_code, std::size_t) mutable {
                        stream->async_shutdown(
                            [cb = std::move(cb)](asio::error_code) {
                                cb({});
                            });
                    });
            });
        return;
    }

    // No body — write HEADERS frame + shutdown.
    stream->async_write_some(
        asio::buffer(*frame_data),
        [stream, frame_data, cb = std::move(cb)](
            asio::error_code, std::size_t) mutable {
            stream->async_shutdown(
                [cb = std::move(cb)](asio::error_code) { cb({}); });
        });
}

} // namespace ebpf_quic_proxy
