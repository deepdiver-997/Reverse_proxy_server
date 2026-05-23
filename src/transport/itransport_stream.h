#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>

namespace ebpf_quic_proxy {

/// Single bidirectional byte-stream (ordered, reliable).
/// TCP: 1 connection = 1 stream.
/// QUIC: 1 connection = N streams, each request/response runs on its own stream.
class ITransportStream {
public:
    using ReadCallback =
        std::function<void(asio::error_code, std::size_t)>;
    using WriteCallback =
        std::function<void(asio::error_code, std::size_t)>;
    using ShutdownCallback =
        std::function<void(asio::error_code)>;

    virtual ~ITransportStream() = default;

    /// Read up to buf.size() bytes.  n == 0 means EOF.
    virtual void async_read_some(asio::mutable_buffer buf,
                                 ReadCallback cb) = 0;

    /// Write up to buf.size() bytes.
    virtual void async_write_some(asio::const_buffer buf,
                                  WriteCallback cb) = 0;

    /// Shut down the write side (TCP: shutdown(SHUT_WR); QUIC: stream FIN).
    virtual void async_shutdown(ShutdownCallback cb) = 0;

    /// Opaque id for logging / tracing.
    virtual std::string stream_id() const = 0;
};

using ITransportStreamPtr = std::shared_ptr<ITransportStream>;

} // namespace ebpf_quic_proxy
