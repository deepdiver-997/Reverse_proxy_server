#include "h1_codec.h"
#include <asio.hpp>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <string_view>

namespace ebpf_quic_proxy {

namespace {

/// Decodes HTTP/1.1 chunked transfer-encoding (RFC 9112 §7.1).
/// Returns one chunk's worth of data per async_read_some call; 0 = body end.
class ChunkedBodySource final : public BodySource,
                                public std::enable_shared_from_this<ChunkedBodySource> {
public:
    explicit ChunkedBodySource(ITransportStreamPtr stream)
        : stream_(std::move(stream)) {}

    void async_read_some(asio::mutable_buffer buf, ReadCallback cb) override {
        auto self = shared_from_this();
        if (finished_) {
            cb({}, 0);
            return;
        }
        if (chunk_remaining_ == 0)
            read_size_line(buf, std::move(cb));
        else
            read_chunk_payload(buf, std::move(cb));
    }

    std::optional<std::size_t> content_length() const override {
        return std::nullopt; // chunked → length unknown up front
    }

private:
    void read_size_line(asio::mutable_buffer buf, ReadCallback cb) {
        auto self = shared_from_this();
        read_line([this, self, buf, cb](bool ok) mutable {
            if (!ok) {
                finished_ = true;
                cb(asio::error::eof, 0);
                return;
            }
            auto semi = size_line_.find(';');
            if (semi != std::string::npos)
                size_line_.resize(semi); // drop chunk extensions
            char* end = nullptr;
            unsigned long sz = std::strtoul(size_line_.c_str(), &end, 16);
            if (end == size_line_.c_str()) { // no hex digits
                finished_ = true;
                cb(asio::error::invalid_argument, 0);
                return;
            }
            size_line_.clear();
            chunk_remaining_ = static_cast<std::size_t>(sz);
            if (chunk_remaining_ == 0) { // last-chunk → consume trailers
                read_trailers([this, self, cb](bool ok) mutable {
                    if (!ok) {
                        finished_ = true;
                        cb(asio::error::eof, 0);
                        return;
                    }
                    finished_ = true;
                    cb({}, 0); // body exhausted
                });
                return;
            }
            read_chunk_payload(buf, std::move(cb));
        });
    }

    void read_chunk_payload(asio::mutable_buffer buf, ReadCallback cb) {
        auto self = shared_from_this();
        std::size_t want = std::min(buf.size(), chunk_remaining_);
        stream_->async_read_some(
            asio::buffer(buf.data(), want),
            [this, self, cb](asio::error_code ec, std::size_t n) mutable {
                if (ec) {
                    finished_ = true;
                    cb(ec, 0);
                    return;
                }
                chunk_remaining_ -= n;
                if (chunk_remaining_ == 0) {
                    // Each chunk's data ends with CRLF; consume it before the
                    // next chunk-size line.
                    skip_crlf([this, self, cb, n](bool ok) mutable {
                        if (!ok) {
                            finished_ = true;
                            cb(asio::error::eof, 0);
                            return;
                        }
                        cb({}, n);
                    });
                } else {
                    cb({}, n);
                }
            });
    }

    void skip_crlf(std::function<void(bool)> done) {
        auto self = shared_from_this();
        read_exact(2, [this, self, done](bool ok) { done(ok); });
    }

    void read_line(std::function<void(bool)> done) {
        size_line_.clear();
        read_line_byte(std::move(done));
    }

    void read_line_byte(std::function<void(bool)> done) {
        auto self = shared_from_this();
        std::array<char, 1> b;
        stream_->async_read_some(
            asio::buffer(b),
            [this, self, done, b](asio::error_code ec, std::size_t n) mutable {
                if (ec || n == 0) {
                    done(false);
                    return;
                }
                if (b[0] == '\n') {
                    done(true);
                    return;
                }
                if (b[0] != '\r')
                    size_line_.push_back(b[0]);
                read_line_byte(std::move(done));
            });
    }

    // Trailer section follows the 0-chunk: header lines terminated by a blank
    // line.  Skip them so a keep-alive connection is left at a clean boundary
    // (required before returning the connection to the pool).
    void read_trailers(std::function<void(bool)> done) {
        read_line([this, done](bool ok) {
            if (!ok) {
                done(false);
                return;
            }
            if (size_line_.empty()) { // blank line ends the trailer section
                done(true);
                return;
            }
            read_trailers(std::move(done));
        });
    }

    // Reads exactly `count` bytes, discarding them (skips a CRLF).
    void read_exact(std::size_t count, std::function<void(bool)> done) {
        auto self = shared_from_this();
        std::array<char, 64> buf;
        std::size_t take = std::min(count, buf.size());
        stream_->async_read_some(
            asio::buffer(buf, take),
            [this, self, count, done](asio::error_code ec, std::size_t n) mutable {
                if (ec || n == 0) {
                    done(false);
                    return;
                }
                if (n >= count) {
                    done(true);
                    return;
                }
                read_exact(count - n, std::move(done));
            });
    }

    ITransportStreamPtr stream_;
    std::string size_line_;
    std::size_t chunk_remaining_ = 0;
    bool finished_ = false;
};

// ── keep_alive decision (RFC 9112 §9.3) ──────────────────

// HTTP/1.0 keeps alive only with an explicit Connection: keep-alive;
// HTTP/1.1+ keeps alive unless told otherwise.
bool version_keeps_alive(const std::string& version) {
    return version.rfind("HTTP/1.0", 0) != 0; // 1.1+ or unknown → keep alive
}

bool header_says_close(const HeaderMap& hdrs) {
    if (auto c = hdrs.get("connection"))
        return c->find("close") != std::string::npos;
    return false;
}

bool header_says_keep_alive(const HeaderMap& hdrs) {
    if (auto c = hdrs.get("connection"))
        return c->find("keep-alive") != std::string::npos;
    return false;
}

bool compute_keep_alive(const HeaderMap& hdrs, const std::string& version) {
    bool ka = version_keeps_alive(version);
    if (header_says_close(hdrs))
        ka = false;
    else if (header_says_keep_alive(hdrs))
        ka = true;
    return ka;
}

// Version string to write on the wire: preserve a valid HTTP/1.x version
// (the client's), otherwise normalize to HTTP/1.1.  The relay always
// re-frames, so it can safely speak the client's version to a backend.
std::string wire_h1_version(const std::string& v) {
    if (v.rfind("HTTP/1.", 0) == 0)
        return v;
    return "HTTP/1.1";
}

} // namespace


// ── Parse request ─────────────────────────────────────────

void H1Codec::async_parse_request(ITransportStreamPtr stream,
                                   ParseCallback cb) {
    auto buf = std::make_shared<std::vector<char>>();
    buf->reserve(4096);
    read_header_block(std::move(stream), std::move(buf), std::move(cb));
}

void H1Codec::read_header_block(ITransportStreamPtr stream,
                                 std::shared_ptr<std::vector<char>> buf,
                                 ParseCallback cb) {
    // Read a chunk into buf.
    auto chunk = std::make_shared<std::array<char, 4096>>();
    auto* raw_stream = stream.get();
    raw_stream->async_read_some(
        asio::buffer(*chunk),
        [this, stream = std::move(stream), buf = std::move(buf),
         cb = std::move(cb), chunk](asio::error_code ec,
                                     std::size_t n) mutable {
            if (ec) {
                cb(ec, {}, nullptr, false);
                return;
            }
            if (n == 0) {
                // EOF before headers complete → client closed connection
                cb(asio::error::eof, {}, nullptr, false);
                return;
            }

            buf->insert(buf->end(), chunk->begin(), chunk->begin() + n);

            // Look for \r\n\r\n
            std::string_view view(buf->data(), buf->size());
            auto pos = view.find("\r\n\r\n");
            if (pos == std::string_view::npos) {
                // Keep reading.
                read_header_block(std::move(stream), std::move(buf),
                                  std::move(cb));
                return;
            }

            // Header block complete. Split raw block and body prefix.
            std::string raw(buf->data(), pos + 4); // includes \r\n\r\n
            std::string body_prefix(buf->data() + pos + 4,
                                     buf->size() - pos - 4);

            std::string version;
            auto [head, err] = parse_header_block(raw, &version);
            if (!err.empty()) {
                cb(asio::error::invalid_argument, {}, nullptr, false);
                return;
            }

            // Determine body source.
            BodySourcePtr body_src;
            if (head.content_length.has_value()) {
                std::size_t remaining = *head.content_length;
                if (!body_prefix.empty()) {
                    std::size_t prefix_len =
                        std::min(body_prefix.size(), remaining);
                    std::string prefix_data =
                        body_prefix.substr(0, prefix_len);
                    remaining -= prefix_len;

                    if (remaining == 0) {
                        // Entire body was captured in the header read.
                        body_src = std::make_shared<BufferBodySource>(
                            std::move(prefix_data));
                    } else {
                        // Partial body in prefix; remainder is on the stream.
                        // Phase 2: chained BodySource.  For now, return a
                        // StreamBodySource for the remainder only (prefix is
                        // lost — FIXME).
                        body_src = std::make_shared<StreamBodySource>(
                            stream, remaining);
                    }
                } else if (remaining > 0) {
                    body_src = std::make_shared<StreamBodySource>(
                        stream, remaining);
                }
            } else {
                // No Content-Length, no body.
            }

            bool keep_alive = compute_keep_alive(head.headers, version);
            cb({}, std::move(head), std::move(body_src), keep_alive);
        });
}

std::pair<HttpRequestHead, std::string>
H1Codec::parse_header_block(const std::string& raw, std::string* version_out) {
    HttpRequestHead head;
    std::istringstream iss(raw);
    std::string line;

    // Request line: METHOD SP PATH SP VERSION
    if (!std::getline(iss, line) || line.empty())
        return {{}, "empty request"};
    // Remove trailing \r
    if (!line.empty() && line.back() == '\r')
        line.pop_back();

    std::istringstream rl(line);
    std::string version;
    rl >> head.method >> head.path >> version;
    if (version_out)
        *version_out = version;
    if (head.method.empty() || head.path.empty())
        return {{}, "bad request line: " + line};
    head.version = version; // carry the wire version in the IR

    // Request-target may be origin-form ("/path") or absolute-form
    // ("http://host/path" — a forward-proxy request).  Normalize absolute-form
    // to origin-form here so the backend always receives origin-form; the URL's
    // scheme/authority are recorded for the relay to direct-connect.
    auto scheme_pos = head.path.find("://");
    if (scheme_pos != std::string::npos && scheme_pos > 0) {
        std::string scheme = head.path.substr(0, scheme_pos);
        std::string rest = head.path.substr(scheme_pos + 3);
        auto slash = rest.find('/');
        std::string authority =
            (slash == std::string::npos) ? rest : rest.substr(0, slash);
        std::string path =
            (slash == std::string::npos) ? "/" : rest.substr(slash);
        std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                       [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                       });
        head.scheme = std::move(scheme);
        head.authority = std::move(authority);
        head.path = std::move(path);
        head.absolute_target = true;
    }

    // Headers
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break; // end of headers

        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue; // malformed, skip
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        // Trim leading whitespace from val.
        auto start = val.find_first_not_of(" \t");
        if (start != std::string::npos)
            val = val.substr(start);
        head.headers.add(key, val);
    }

    // Extract Content-Length.
    if (auto cl = head.headers.get("content-length")) {
        head.content_length = std::strtoul(cl->c_str(), nullptr, 10);
    }

    // Origin-form request: authority comes from the Host header, scheme is
    // inferred as http (this transport does not speak TLS).
    if (!head.absolute_target) {
        head.scheme = "http";
        if (auto host = head.headers.get("host"))
            head.authority = *host;
    }

    return {std::move(head), {}};
}

// ── Parse response ────────────────────────────────────────

void H1Codec::async_parse_response(ITransportStreamPtr stream,
                                   ResponseCallback cb) {
    auto buf = std::make_shared<std::vector<char>>();
    buf->reserve(4096);
    read_response_header(std::move(stream), std::move(buf), std::move(cb));
}

void H1Codec::read_response_header(ITransportStreamPtr stream,
                                   std::shared_ptr<std::vector<char>> buf,
                                   ResponseCallback cb) {
    auto chunk = std::make_shared<std::array<char, 4096>>();
    auto* raw_stream = stream.get();
    raw_stream->async_read_some(
        asio::buffer(*chunk),
        [this, stream = std::move(stream), buf = std::move(buf),
         cb = std::move(cb), chunk](asio::error_code ec,
                                    std::size_t n) mutable {
            if (ec) {
                cb(ec, {}, nullptr, false);
                return;
            }
            if (n == 0) {
                cb(asio::error::eof, {}, nullptr, false);
                return;
            }

            buf->insert(buf->end(), chunk->begin(), chunk->begin() + n);
            std::string_view view(buf->data(), buf->size());
            auto pos = view.find("\r\n\r\n");
            if (pos == std::string_view::npos) {
                read_response_header(std::move(stream), std::move(buf),
                                     std::move(cb));
                return;
            }

            std::string raw_block(buf->data(), pos + 4);
            std::string body_prefix(buf->data() + pos + 4,
                                    buf->size() - pos - 4);

            std::string version;
            auto [head, err] = parse_response_block(raw_block, &version);
            if (!err.empty()) {
                cb(asio::error::invalid_argument, {}, nullptr, false);
                return;
            }

            BodySourcePtr body_src;
            bool close_delimited = false; // no CL/chunked → body ends at close
            // Status-determined no-body responses.
            if (head.status_code / 100 == 1 || head.status_code == 204 ||
                head.status_code == 304) {
                // no body
            } else if (auto te = head.headers.get("transfer-encoding");
                       te && te->find("chunked") != std::string::npos) {
                // Note: any bytes already read past the header block are
                // dropped (rare in practice) — FIXME seed the decoder.
                body_src = std::make_shared<ChunkedBodySource>(stream);
            } else if (head.content_length.has_value()) {
                std::size_t remaining = *head.content_length;
                if (!body_prefix.empty()) {
                    std::size_t prefix_len =
                        std::min(body_prefix.size(), remaining);
                    std::string prefix_data =
                        body_prefix.substr(0, prefix_len);
                    remaining -= prefix_len;
                    if (remaining == 0) {
                        body_src = std::make_shared<BufferBodySource>(
                            std::move(prefix_data));
                    } else {
                        // Prefix lost for the remainder — FIXME same as request.
                        body_src = std::make_shared<StreamBodySource>(
                            stream, remaining);
                    }
                } else if (remaining > 0) {
                    body_src = std::make_shared<StreamBodySource>(
                        stream, remaining);
                }
            } else {
                body_src = std::make_shared<StreamEofBodySource>(stream);
                close_delimited = true;
            }

            bool keep_alive = compute_keep_alive(head.headers, version);
            if (close_delimited)
                keep_alive = false; // body delimited by connection close
            cb({}, std::move(head), std::move(body_src), keep_alive);
        });
}

std::pair<HttpResponseHead, std::string>
H1Codec::parse_response_block(const std::string& raw, std::string* version_out) {
    HttpResponseHead head;
    std::istringstream iss(raw);
    std::string line;

    // Status line: HTTP/1.1 SP STATUS SP REASON
    if (!std::getline(iss, line) || line.empty())
        return {head, "empty response"};
    if (!line.empty() && line.back() == '\r')
        line.pop_back();

    std::istringstream rl(line);
    std::string version;
    rl >> version >> head.status_code;
    if (version_out)
        *version_out = version;
    if (head.status_code <= 0)
        return {head, "bad status line: " + line};
    head.version = version; // carry the wire version in the IR
    std::getline(rl, head.reason);
    // Trim leading space from reason (" OK" → "OK").
    auto start = head.reason.find_first_not_of(" \t");
    if (start != std::string::npos)
        head.reason = head.reason.substr(start);

    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break;

        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        auto vs = val.find_first_not_of(" \t");
        if (vs != std::string::npos)
            val = val.substr(vs);
        head.headers.add(key, val);
    }

    if (auto cl = head.headers.get("content-length"))
        head.content_length = std::strtoul(cl->c_str(), nullptr, 10);

    return {std::move(head), {}};
}

// ── Write request / response ──────────────────────────────

void H1Codec::async_write_request(ITransportStreamPtr stream,
                                  HttpRequestHead head, BodySourcePtr body,
                                  WriteCallback cb) {
    std::ostringstream oss;
    oss << head.method << " " << head.path << " "
        << wire_h1_version(head.version) << "\r\n";
    oss << head.headers.to_wire();
    oss << "\r\n";

    auto header_str = std::make_shared<std::string>(oss.str());
    stream->async_write_some(
        asio::buffer(*header_str),
        [stream, body = std::move(body), cb = std::move(cb),
         header_str](asio::error_code ec, std::size_t) mutable {
            if (ec || !body) {
                cb(ec);
                return;
            }
            pump_body_to_stream(std::move(stream), std::move(body), std::move(cb));
        });
}

void H1Codec::async_write_response(ITransportStreamPtr stream,
                                    HttpResponseHead head, BodySourcePtr body,
                                    WriteCallback cb) {
    std::ostringstream oss;
    oss << wire_h1_version(head.version) << " " << head.status_code << " "
        << head.reason << "\r\n";
    oss << head.headers.to_wire();
    oss << "\r\n";

    auto header_str = std::make_shared<std::string>(oss.str());
    stream->async_write_some(
        asio::buffer(*header_str),
        [stream, body = std::move(body), cb = std::move(cb),
         header_str](asio::error_code ec, std::size_t) mutable {
            if (ec || !body) {
                cb(ec);
                return;
            }
            pump_body_to_stream(std::move(stream), std::move(body), std::move(cb));
        });
}

} // namespace ebpf_quic_proxy
