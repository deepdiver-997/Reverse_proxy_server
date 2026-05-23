#pragma once

#include "itransport_stream.h"
#include <functional>
#include <memory>
#include <string>

namespace ebpf_quic_proxy {

/// A transport session is the "connection" abstraction above streams.
/// TCP: 1 session = 1 connection, 1 fixed stream.
/// QUIC: 1 session = 1 connection, N dynamically-opened streams.
class ITransportSession {
public:
    using NewStreamCallback =
        std::function<void(ITransportStreamPtr)>;

    virtual ~ITransportSession() = default;

    /// Register a callback that fires each time the remote peer opens a stream.
    /// TCP: fires exactly once, synchronously inside set_new_stream_cb().
    /// QUIC: fires N times, asynchronously, for each incoming request stream.
    virtual void set_new_stream_cb(NewStreamCallback cb) = 0;

    /// Actively open a new outbound stream (for connecting to upstreams).
    /// TCP: returns nullptr — you can't create a stream on an existing TCP conn.
    /// QUIC: returns a new stream on the existing connection.
    virtual ITransportStreamPtr open_stream() = 0;

    /// Gracefully close the session.
    virtual void close() = 0;

    /// Peer address (for logging, not for routing — CID handles that in QUIC).
    virtual std::string remote_addr() const = 0;
};

using ITransportSessionPtr = std::shared_ptr<ITransportSession>;

/// Accepts incoming transport sessions.
class ITransportListener {
public:
    using AcceptCallback =
        std::function<void(ITransportSessionPtr)>;

    virtual ~ITransportListener() = default;

    /// Async accept — cb fires when a new session is established.
    virtual void async_accept(AcceptCallback cb) = 0;
};

using ITransportListenerPtr = std::shared_ptr<ITransportListener>;

} // namespace ebpf_quic_proxy
