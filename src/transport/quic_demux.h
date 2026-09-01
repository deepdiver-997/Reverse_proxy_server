#pragma once

#include <asio.hpp>
extern "C" {
#include <lsquic.h>
}
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ebpf_quic_proxy {

class QuicServerEngine; // fwd — demux posts packets to engines

/// All server SCIDs have this fixed length (see design-quic-demux.md §6.5):
/// short-header packets don't carry the DCID length, so the demux must assume
/// the negotiated value, and the engine must be configured to issue SCIDs of
/// exactly this length.  Matches lsquic's LSQUIC_DF_SCID_LEN default.
constexpr unsigned kServerCidLen = 8;

// ── shared helpers (also used by quic_transport.cpp) ───────

/// Copy an asio UDP endpoint into a sockaddr_storage.
void to_sockaddr(const asio::ip::udp::endpoint& ep,
                 struct sockaddr_storage* sa);

/// Send a batch of lsquic out-specs as UDP datagrams, picking `fd_v4` or
/// `fd_v6` by each spec's destination family (a v4 socket can't send to a v6
/// address; a batch may mix families).  Returns how many were sent;
/// `*blocked` is set if any hit EAGAIN — lsquic retains the unsent packets and
/// expects lsquic_engine_send_unsent_packets() once the socket drains.
unsigned send_specs(int fd_v4, int fd_v6, const lsquic_out_spec* specs,
                    unsigned count, bool* blocked);

/// Raw-bytes key for a CID (length-prefixed, so it's unambiguous regardless of
/// the CID length).  Used as the CID→worker table key.
std::string cid_key(const lsquic_cid_t* cid);

// ── QuicPacketDemux ────────────────────────────────────────

/// The single QUIC ingress: owns the ONE shared UDP socket for the QUIC listen
/// port, parses the DCID out of each datagram (lsquic_dcid_from_packet), routes
/// it to a worker by CID (migration-safe), and wakes that worker's io_context
/// with io_context::post — the packet landed on *this* socket, so it will never
/// trigger an event on the worker's own io_context on its own.
///
/// Outbound packets do NOT go through the demux: workers send synchronously on
/// the shared fd from their own thread (ea_packets_out contract), and only
/// report EAGAIN here so a single write-watch can coordinate the shared socket.
class QuicPacketDemux {
public:
    /// `dual_stack` opens a second IPv6 UDP socket on the same port so QUIC
    /// clients can connect over either family.  If the IPv6 bind fails it logs
    /// a loud warning and continues IPv4-only.
    QuicPacketDemux(asio::io_context& io, uint16_t port, bool dual_stack);
    ~QuicPacketDemux();

    QuicPacketDemux(const QuicPacketDemux&) = delete;
    QuicPacketDemux& operator=(const QuicPacketDemux&) = delete;

    /// Register one worker slot (its io_context + server engine).  Returns the
    /// worker index (0-based, assignment order).  Must be called before start().
    int add_worker(asio::io_context& worker_io, QuicServerEngine* engine);

    /// Begin the recv loop (arm async_receive_from).  No packets flow before
    /// this, so all workers must be registered first.
    void start();

    /// Graceful shutdown: cancel the UDP recv (and the write-watch).  Packets
    /// already posted to workers still process; no new datagrams are received.
    /// Call on the demux's io_context thread.
    void stop();

    /// CID table — thread-safe; called from worker threads (engine SCID
    /// callbacks).  Key is cid_key() bytes.
    void register_cid(const std::string& key, int worker_idx);
    void remove_cid(const std::string& key);

    /// Shared send fds (v4 + v6, when dual-stack) — workers sendmsg directly
    /// on the one matching each destination's family (UDP sendto is
    /// thread-safe, single-datagram atomic).  v6_fd() is -1 when the IPv6
    /// socket failed to bind.
    int v4_fd() const { return raw_fd_; }
    int v6_fd() const { return raw6_fd_; }

    /// Called from a worker thread when ea_packets_out hit EAGAIN.  Arms the
    /// write-watch on whichever socket(s) drained; when they do, all workers
    /// are asked to flush lsquic_engine_send_unsent_packets().
    void notify_tx_blocked();

private:
    asio::io_context& io_;
    asio::ip::udp::socket socket_;   // IPv4
    asio::ip::udp::socket socket6_;  // IPv6 (dual_stack; default-constructed)
    int raw_fd_ = -1;
    int raw6_fd_ = -1;

    std::array<char, 65536> recv_buf_{};
    asio::ip::udp::endpoint recv_endpoint_;
    struct sockaddr_storage local_sa_{}; // cached once at bind — constant
    std::array<char, 65536> recv6_buf_{};
    asio::ip::udp::endpoint recv6_endpoint_;
    struct sockaddr_storage local6_sa_{};

    struct WorkerSlot {
        asio::io_context* io = nullptr;
        QuicServerEngine* engine = nullptr;
    };
    std::vector<WorkerSlot> workers_;

    std::mutex cid_mu_;
    std::map<std::string, int> cid_to_worker_;

    bool send_retry_armed_ = false;
    bool send_retry6_armed_ = false;

    void do_recv();
    void do_recv6();
    void on_packet(asio::error_code ec, std::size_t n,
                   const struct sockaddr_storage& local_sa);

    /// DCID → worker.  Known CID routes by the table; unknown CID (new
    /// connection) hashes the source address.  Returns -1 to drop.
    int route(const unsigned char* buf, std::size_t len,
              const std::string& src_addr);

    void arm_send_retry();
    void arm_write_watch(asio::ip::udp::socket& s, bool& armed);
};

} // namespace ebpf_quic_proxy
