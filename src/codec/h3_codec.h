#pragma once

#include "icodec.h"
#include "http_message.h"
#include <asio.hpp>
#include <cstdint>
#include <string>

namespace ebpf_quic_proxy {

// ── QUIC variable-length integer ─────────────────────────
// RFC 9000 §16: top 2 bits encode the length.

struct VarintResult {
    uint64_t value;
    std::size_t bytes_read;
};

/// Decode a QUIC varint from the buffer. Returns bytes_read=0 on error.
VarintResult decode_varint(const uint8_t* data, std::size_t len);

/// Encode a uint64_t into QUIC varint.
std::size_t encode_varint(uint64_t value, uint8_t* out);

/// Return the encoded length of a QUIC varint.
std::size_t varint_size(uint64_t value);

// ── HTTP/3 frame types ───────────────────────────────────

enum class H3FrameType : uint64_t {
    DATA = 0x0,
    HEADERS = 0x1,
    CANCEL_PUSH = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    GOAWAY = 0x7,
    MAX_PUSH_ID = 0xD,
};

// ── H3 Codec ─────────────────────────────────────────────

/// HTTP/3 codec on top of lsquic's native H3 (ADR-8, route B).
///
/// Header handling is delegated to the transport: request headers are decoded
/// by lsquic's QPACK into a header set, claimed via
/// ITransportStream::async_take_headers(), and mapped to the IR; response
/// headers go out via ITransportStream::async_send_headers()
/// (lsquic_stream_send_headers).  Bodies are raw DATA payloads — read/write
/// via the ordinary stream byte interface.
///
/// Implements the same ICodec interface as H1Codec, so ProxyCore
/// can swap them based on the listener that produced the stream.
class H3Codec final : public ICodec {
public:
    void async_parse_request(ITransportStreamPtr stream,
                              ParseCallback cb) override;

    void async_parse_response(ITransportStreamPtr stream,
                              ResponseCallback cb) override;

    void async_write_request(ITransportStreamPtr stream,
                             HttpRequestHead head,
                             BodySourcePtr body,
                             WriteCallback cb) override;

    void async_write_response(ITransportStreamPtr stream,
                              HttpResponseHead head,
                              BodySourcePtr body,
                              WriteCallback cb) override;
};

/// Standalone helpers — exposed for unit testing.
namespace h3_detail {
    bool parse_request_headers(
        const uint8_t* data, std::size_t len,
        std::string& method, std::string& path, HeaderMap& hdrs,
        std::optional<std::size_t>& content_length);

    /// Interpret a QPACK-decoded header list (pseudo-headers included) into a
    /// request IR.  The transport only decodes; this does the interpretation.
    HttpRequestHead request_head_from_headers(
        const ITransportStream::HeaderList& raw);

    /// Interpret a QPACK-decoded header list (pseudo-headers included) into a
    /// response IR (`:status` → status_code; HTTP/3 has no reason phrase).
    HttpResponseHead response_head_from_headers(
        const ITransportStream::HeaderList& raw);
}

} // namespace ebpf_quic_proxy
