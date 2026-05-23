#include "tcp_transport.h"
#include <sstream>

namespace ebpf_quic_proxy {

// ── TcpTransportStream ────────────────────────────────────

TcpTransportStream::TcpTransportStream(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)) {
    std::ostringstream oss;
    oss << "tcp:" << socket_.remote_endpoint();
    id_ = oss.str();
}

void TcpTransportStream::async_read_some(asio::mutable_buffer buf,
                                          ReadCallback cb) {
    auto self = shared_from_this();
    socket_.async_read_some(
        buf, [self, cb = std::move(cb)](auto ec, auto n) { cb(ec, n); });
}

void TcpTransportStream::async_write_some(asio::const_buffer buf,
                                           WriteCallback cb) {
    auto self = shared_from_this();
    asio::async_write(
        socket_, buf,
        [self, cb = std::move(cb)](auto ec, auto n) { cb(ec, n); });
}

void TcpTransportStream::async_shutdown(ShutdownCallback cb) {
    auto self = shared_from_this();
    asio::error_code ec;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    // shutdown on a socket that was already closed by the peer is not an error
    if (ec == asio::error::not_connected)
        ec.clear();
    cb(ec);
}

std::string TcpTransportStream::stream_id() const { return id_; }

// ── TcpTransportSession ───────────────────────────────────

TcpTransportSession::TcpTransportSession(asio::ip::tcp::socket socket)
    : stream_(std::make_shared<TcpTransportStream>(std::move(socket))) {
    remote_addr_ = stream_->stream_id();
}

void TcpTransportSession::set_new_stream_cb(NewStreamCallback cb) {
    // TCP / HTTP/1.1: exactly one stream, deliver it immediately.
    cb(stream_);
}

ITransportStreamPtr TcpTransportSession::open_stream() {
    // TCP can't create additional streams on an existing connection.
    return nullptr;
}

void TcpTransportSession::close() {
    asio::error_code ec;
    // We don't own a socket directly — the stream does.
    // Let the stream's destructor close it.
    stream_.reset();
}

std::string TcpTransportSession::remote_addr() const { return remote_addr_; }

// ── TcpTransportListener ──────────────────────────────────

TcpTransportListener::TcpTransportListener(
    asio::io_context& io,
    const asio::ip::tcp::endpoint& ep)
    : acceptor_(io, ep) {
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
}

void TcpTransportListener::async_accept(AcceptCallback cb) {
    auto self = shared_from_this();
    acceptor_.async_accept(
        [self, cb = std::move(cb)](asio::error_code ec,
                                    asio::ip::tcp::socket socket) {
            if (ec) {
                // Pass nullptr to signal error — caller decides to retry or die.
                cb(nullptr);
                return;
            }
            auto session =
                std::make_shared<TcpTransportSession>(std::move(socket));
            cb(session);
        });
}

} // namespace ebpf_quic_proxy
