#pragma once

#include <asio.hpp>
#include "transport/itransport_stream.h"
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

// ── Header map (case-insensitive keys, insertion-ordered) ──

class HeaderMap {
public:
    using Entry = std::pair<std::string, std::string>;

    void add(const std::string& key, const std::string& value);
    void set(const std::string& key, const std::string& value);

    /// First value for key, or nullopt.
    std::optional<std::string> get(const std::string& key) const;

    /// All values for key.
    std::vector<std::string> get_all(const std::string& key) const;

    /// Remove all entries for key.
    void remove(const std::string& key);

    const std::vector<Entry>& entries() const { return entries_; }
    bool empty() const { return entries_.empty(); }

    /// Serialize to wire format: "Key: Value\r\n" per entry.
    std::string to_wire() const;

private:
    std::vector<Entry> entries_;

    static std::string lower(std::string s);
};

// ── HTTP status codes ─────────────────────────────────────

enum class HttpStatus : int {
    OK = 200,
    BadRequest = 400,
    NotFound = 404,
    BadGateway = 502,
    ServiceUnavailable = 503,
};

/// Reason phrase for a status code (e.g. 200 → "OK").
const char* status_reason(HttpStatus status);

/// Build a complete HTTP/1.1 response string (status-line + headers + body).
/// No allocations beyond the returned string.
std::string make_error_response(HttpStatus status, std::string body);

// ── Protocol-independent HTTP IR ──────────────────────────

struct HttpRequestHead {
    std::string method;
    std::string path;
    HeaderMap headers;
    std::optional<std::size_t> content_length;
};

struct HttpResponseHead {
    int status_code;
    std::string reason;
    HeaderMap headers;
    std::optional<std::size_t> content_length;

    /// Serialize to a complete HTTP/1.1 response string (status-line +
    /// headers + \r\n + body).  Caller supplies the body separately.
    std::string to_h1_head() const;
};

// ── Streaming body ────────────────────────────────────────

/// Abstract source of body bytes.
/// Owned by the stream that provided them; this is just an access handle.
class BodySource {
public:
    using ReadCallback =
        std::function<void(asio::error_code, std::size_t)>;

    virtual ~BodySource() = default;

    /// Read up to buf.size() bytes.  n == 0 means body exhausted.
    virtual void async_read_some(asio::mutable_buffer buf,
                                 ReadCallback cb) = 0;

    /// Known total length, or nullopt if unknown (chunked / close-delimited).
    virtual std::optional<std::size_t> content_length() const = 0;
};

using BodySourcePtr = std::shared_ptr<BodySource>;

/// BodySource that reads from an ITransportStream with a byte limit.
class StreamBodySource final
    : public BodySource,
      public std::enable_shared_from_this<StreamBodySource> {
public:
    /// Construct with the underlying stream and Content-Length (0 = close-delimited).
    StreamBodySource(ITransportStreamPtr stream, std::size_t remaining);

    void async_read_some(asio::mutable_buffer buf,
                         ReadCallback cb) override;
    std::optional<std::size_t> content_length() const override;

private:
    ITransportStreamPtr stream_;
    std::size_t remaining_;
};

/// BodySource that serves from an in-memory buffer.
class BufferBodySource final : public BodySource {
public:
    explicit BufferBodySource(std::string data);

    void async_read_some(asio::mutable_buffer buf,
                         ReadCallback cb) override;
    std::optional<std::size_t> content_length() const override;

private:
    std::string data_;
    std::size_t read_pos_ = 0;
};

} // namespace ebpf_quic_proxy
