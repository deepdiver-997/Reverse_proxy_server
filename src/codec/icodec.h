#pragma once

#include "http_message.h"
#include "transport/itransport_stream.h"
#include <functional>

namespace ebpf_quic_proxy {

/// Protocol codec: parses requests from a stream, serializes responses to it.
class ICodec {
public:
    using ParseCallback = std::function<void(asio::error_code,
                                             HttpRequestHead,
                                             BodySourcePtr)>;

    using WriteCallback =
        std::function<void(asio::error_code)>;

    virtual ~ICodec() = default;

    /// Parse one HTTP request from the stream.
    /// On success, cb(ec, head, body) — body may be nullptr if no body.
    virtual void async_parse_request(ITransportStreamPtr stream,
                                     ParseCallback cb) = 0;

    /// Write a response to the stream, including body if present.
    virtual void async_write_response(ITransportStreamPtr stream,
                                      HttpResponseHead head,
                                      BodySourcePtr body,
                                      WriteCallback cb) = 0;
};

} // namespace ebpf_quic_proxy
