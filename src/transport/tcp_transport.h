#pragma once

#include "itransport_stream.h"
#include "itransport_session.h"
#include <asio.hpp>

namespace ebpf_quic_proxy {

/// TCP-backed ITransportStream — wraps a connected asio::ip::tcp::socket.
class TcpTransportStream final
    : public ITransportStream,
      public std::enable_shared_from_this<TcpTransportStream> {
public:
    explicit TcpTransportStream(asio::ip::tcp::socket socket);

    void async_read_some(asio::mutable_buffer buf,
                         ReadCallback cb) override;
    void async_write_some(asio::const_buffer buf,
                          WriteCallback cb) override;
    void async_shutdown(ShutdownCallback cb) override;
    std::string stream_id() const override;

private:
    asio::ip::tcp::socket socket_;
    std::string id_;
};

/// TCP-backed ITransportSession.
/// For HTTP/1.1 there is exactly one stream per connection,
/// so set_new_stream_cb() fires synchronously with the sole stream.
class TcpTransportSession final
    : public ITransportSession,
      public std::enable_shared_from_this<TcpTransportSession> {
public:
    explicit TcpTransportSession(asio::ip::tcp::socket socket);

    void set_new_stream_cb(NewStreamCallback cb) override;
    ITransportStreamPtr open_stream() override;
    void close() override;
    std::string remote_addr() const override;

private:
    std::shared_ptr<TcpTransportStream> stream_;
    std::string remote_addr_;
};

/// TCP-backed ITransportListener — wraps asio::ip::tcp::acceptor.
class TcpTransportListener final
    : public ITransportListener,
      public std::enable_shared_from_this<TcpTransportListener> {
public:
    TcpTransportListener(asio::io_context& io,
                         const asio::ip::tcp::endpoint& ep);

    void async_accept(AcceptCallback cb) override;

private:
    asio::ip::tcp::acceptor acceptor_;
};

} // namespace ebpf_quic_proxy
