#pragma once

#include "icodec.h"
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

/// HTTP/1.1 codec.
/// Parsing: buffers until \r\n\r\n, then splits request/response line + headers.
/// Serialization: writes request/response line + headers + \r\n + body bytes.
class H1Codec final : public ICodec {
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

private:
    // Internal: keep reading until the header block is complete.
    void read_header_block(ITransportStreamPtr stream,
                           std::shared_ptr<std::vector<char>> buf,
                           ParseCallback cb);

    void read_response_header(ITransportStreamPtr stream,
                              std::shared_ptr<std::vector<char>> buf,
                              ResponseCallback cb);

    std::pair<HttpRequestHead, std::string>
    parse_header_block(const std::string& raw);

    std::pair<HttpResponseHead, std::string>
    parse_response_block(const std::string& raw);
};

} // namespace ebpf_quic_proxy
