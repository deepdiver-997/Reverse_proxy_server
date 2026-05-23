#pragma once

#include "icodec.h"
#include "http_message.h"
#include <asio.hpp>
#include <cstdint>
#include <string>
#include <vector>

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

/// Minimal HTTP/3 codec.
///
/// Parses HEADERS + optional DATA frames from a QUIC stream into
/// the protocol-independent IR.  QPACK is NOT implemented —
/// responses use literal headers (name/value in the HEADERS frame).
///
/// Implements the same ICodec interface as H1Codec, so ProxyCore
/// can swap them based on the listener that produced the stream.
class H3Codec final : public ICodec {
public:
    void async_parse_request(ITransportStreamPtr stream,
                              ParseCallback cb) override;

    void async_write_response(ITransportStreamPtr stream,
                              HttpResponseHead head,
                              BodySourcePtr body,
                              WriteCallback cb) override;

private:
    // ── Parsing state ───────────────────────────────────
    enum class ParseState {
        ExpectHeaders,
        ReadingHeaders,
        ExpectData,
        ReadingData,
        Done,
    };

    struct ParseCtx {
        ITransportStreamPtr stream;
        ParseCallback cb;
        ParseState state = ParseState::ExpectHeaders;
        std::vector<uint8_t> buf; // accumulated bytes
        std::size_t frame_bytes_needed = 0;
        H3FrameType current_frame_type = H3FrameType::DATA;
        std::size_t headers_content_offset = 0;
        std::size_t headers_content_len = 0;
        std::optional<std::size_t> content_length;
        std::string method;
        std::string path;
        HeaderMap hdrs;
    };

    void parse_loop(std::shared_ptr<ParseCtx> ctx);
    void on_frame_header(std::shared_ptr<ParseCtx> ctx);
    void on_frame_payload(std::shared_ptr<ParseCtx> ctx);
    void build_request_ir(std::shared_ptr<ParseCtx> ctx);
};

/// Standalone helpers — exposed for unit testing.
namespace h3_detail {
    bool parse_request_headers(
        const uint8_t* data, std::size_t len,
        std::string& method, std::string& path, HeaderMap& hdrs,
        std::optional<std::size_t>& content_length);
}

} // namespace ebpf_quic_proxy
