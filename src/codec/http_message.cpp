#include "http_message.h"
#include "transport/itransport_stream.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace ebpf_quic_proxy {

// ── HeaderMap ─────────────────────────────────────────────

std::string HeaderMap::lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

void HeaderMap::add(const std::string& key, const std::string& value) {
    entries_.emplace_back(key, value);
}

void HeaderMap::set(const std::string& key, const std::string& value) {
    remove(key);
    add(key, value);
}

std::optional<std::string> HeaderMap::get(const std::string& key) const {
    auto lk = lower(key);
    for (const auto& [k, v] : entries_) {
        if (lower(k) == lk)
            return v;
    }
    return std::nullopt;
}

std::vector<std::string> HeaderMap::get_all(const std::string& key) const {
    std::vector<std::string> out;
    auto lk = lower(key);
    for (const auto& [k, v] : entries_) {
        if (lower(k) == lk)
            out.push_back(v);
    }
    return out;
}

void HeaderMap::remove(const std::string& key) {
    auto lk = lower(key);
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const auto& e) { return lower(e.first) == lk; }),
        entries_.end());
}

std::string HeaderMap::to_wire() const {
    std::ostringstream oss;
    for (const auto& [k, v] : entries_)
        oss << k << ": " << v << "\r\n";
    return oss.str();
}

// ── StreamBodySource ──────────────────────────────────────

StreamBodySource::StreamBodySource(ITransportStreamPtr stream,
                                   std::size_t remaining)
    : stream_(std::move(stream)), remaining_(remaining) {}

void StreamBodySource::async_read_some(asio::mutable_buffer buf,
                                        ReadCallback cb) {
    if (remaining_ == 0) {
        cb({}, 0);
        return;
    }
    auto self = shared_from_this();
    std::size_t cap = std::min(buf.size(), remaining_);
    auto sub = asio::buffer(buf.data(), cap);
    stream_->async_read_some(
        sub, [self, cb = std::move(cb)](asio::error_code ec,
                                         std::size_t n) {
            if (!ec) {
                if (n > self->remaining_)
                    n = self->remaining_;
                self->remaining_ -= n;
            }
            cb(ec, n);
        });
}

std::optional<std::size_t> StreamBodySource::content_length() const {
    return remaining_;
}

// ── BufferBodySource ──────────────────────────────────────

BufferBodySource::BufferBodySource(std::string data)
    : data_(std::move(data)) {}

void BufferBodySource::async_read_some(asio::mutable_buffer buf,
                                        ReadCallback cb) {
    std::size_t n =
        std::min(buf.size(), data_.size() - read_pos_);
    if (n > 0)
        std::memcpy(buf.data(), data_.data() + read_pos_, n);
    read_pos_ += n;
    cb({}, n);
}

std::optional<std::size_t> BufferBodySource::content_length() const {
    return data_.size();
}

// ── HttpStatus helpers ────────────────────────────────────

const char* status_reason(HttpStatus status) {
    switch (status) {
    case HttpStatus::OK:                  return "OK";
    case HttpStatus::BadRequest:          return "Bad Request";
    case HttpStatus::NotFound:            return "Not Found";
    case HttpStatus::BadGateway:          return "Bad Gateway";
    case HttpStatus::ServiceUnavailable:  return "Service Unavailable";
    }
    return "Unknown";
}

std::string make_error_response(HttpStatus status, std::string body) {
    auto body_len = std::to_string(body.size());
    std::string resp;
    resp.reserve(128 + body.size());
    resp += "HTTP/1.1 ";
    resp += std::to_string(static_cast<int>(status));
    resp += " ";
    resp += status_reason(status);
    resp += "\r\nContent-Type: text/plain\r\nContent-Length: ";
    resp += body_len;
    resp += "\r\n\r\n";
    resp += std::move(body);
    return resp;
}

std::string HttpResponseHead::to_h1_head() const {
    std::string out;
    out.reserve(256);
    out += "HTTP/1.1 ";
    out += std::to_string(status_code);
    out += " ";
    out += reason;
    out += "\r\n";
    out += headers.to_wire();
    out += "\r\n";
    return out;
}

} // namespace ebpf_quic_proxy
