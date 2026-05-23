#include "h1_codec.h"
#include <asio.hpp>
#include <cstdlib>
#include <sstream>
#include <string_view>

namespace ebpf_quic_proxy {


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
                cb(ec, {}, nullptr);
                return;
            }
            if (n == 0) {
                // EOF before headers complete → client closed connection
                cb(asio::error::eof, {}, nullptr);
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

            auto [head, err] = parse_header_block(raw);
            if (!err.empty()) {
                cb(asio::error::invalid_argument, {}, nullptr);
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

            cb({}, std::move(head), std::move(body_src));
        });
}

std::pair<HttpRequestHead, std::string>
H1Codec::parse_header_block(const std::string& raw) {
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
    rl >> head.method >> head.path;
    if (head.method.empty() || head.path.empty())
        return {{}, "bad request line: " + line};

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

    return {std::move(head), {}};
}

// ── Write response ────────────────────────────────────────

void H1Codec::async_write_response(ITransportStreamPtr stream,
                                    HttpResponseHead head, BodySourcePtr body,
                                    WriteCallback cb) {
    // Build header block.
    std::ostringstream oss;
    oss << "HTTP/1.1 " << head.status_code << " " << head.reason << "\r\n";
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
            // Pump body into the stream.
            // Phase 1: simple recursive pump.
            auto pump = std::make_shared<std::function<void()>>();
            auto buf = std::make_shared<std::array<char, 8192>>();
            *pump = [stream, body, cb, pump, buf]() mutable {
                body->async_read_some(
                    asio::buffer(*buf),
                    [stream, body, cb, pump,
                     buf](asio::error_code ec, std::size_t n) mutable {
                        if (ec || n == 0) {
                            cb(ec);
                            return;
                        }
                        stream->async_write_some(
                            asio::buffer(buf->data(), n),
                            [pump, cb](asio::error_code ec,
                                        std::size_t) mutable {
                                if (ec) {
                                    cb(ec);
                                    return;
                                }
                                (*pump)();
                            });
                    });
            };
            (*pump)();
        });
}

} // namespace ebpf_quic_proxy
