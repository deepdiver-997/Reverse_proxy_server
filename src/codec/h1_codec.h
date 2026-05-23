#pragma once

#include "icodec.h"
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

/// HTTP/1.1 codec.
/// Parsing: buffers until \r\n\r\n, then splits request-line + headers.
/// Serialization: writes status-line + headers + \r\n + body bytes.
class H1Codec final : public ICodec {
public:
    void async_parse_request(ITransportStreamPtr stream,
                             ParseCallback cb) override;

    void async_write_response(ITransportStreamPtr stream,
                              HttpResponseHead head,
                              BodySourcePtr body,
                              WriteCallback cb) override;

private:
    // Internal: keep reading until the header block is complete.
    void read_header_block(ITransportStreamPtr stream,
                           std::shared_ptr<std::vector<char>> buf,
                           ParseCallback cb);

    std::pair<HttpRequestHead, std::string>
    parse_header_block(const std::string& raw);
};

} // namespace ebpf_quic_proxy
