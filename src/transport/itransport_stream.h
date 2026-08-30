#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ebpf_quic_proxy {

struct HttpRequestHead; // fwd — codec IR, used only in callback signatures

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

    /// Ordered list of (name, value) header pairs for HTTP/3 — QPACK-decoded
    /// pseudo-headers (e.g. ":status") plus regular fields, in wire order.
    using HeaderList = std::vector<std::pair<std::string, std::string>>;

    /// Result of taking internally-decoded HTTP/3 headers (pseudo-headers
    /// included).  The transport only decodes; interpreting them into a
    /// request or response IR is the codec's job (see H3Codec).
    using HeadersCallback =
        std::function<void(asio::error_code, HeaderList)>;

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

    /// Optional (HTTP/3): transports that decode headers internally (lsquic
    /// QPACK) expose them here. `cb` fires with the raw decoded header list
    /// (pseudo-headers included) when ready, or with an error. Must be called
    /// before any body read. Base implementation reports "not supported".
    /// Returns false when the transport does not provide decoded headers
    /// (e.g. raw TCP) or a take is already pending.
    virtual bool async_take_headers(HeadersCallback /*cb*/) { return false; }

    /// Optional (HTTP/3): send a header block (lsquic_stream_send_headers)
    /// before writing the body. Pseudo-headers such as ":status" must be the
    /// first entries. Base implementation reports "not supported".
    virtual bool async_send_headers(const HeaderList& /*headers*/,
                                    WriteCallback /*cb*/) { return false; }
};

using ITransportStreamPtr = std::shared_ptr<ITransportStream>;

} // namespace ebpf_quic_proxy
