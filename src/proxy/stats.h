#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace ebpf_quic_proxy {

/// Process-wide counters behind the /stats endpoint.  Workers bump atomics
/// from their own threads; the stats listener reads them.  v1 stays coarse
/// (totals + backend-latency sum/count) — histograms come when there is data
/// worth histogramming; see docs/perf.md for methodology and baselines.
struct ProxyStats {
    std::atomic<uint64_t> tcp_conns{0};         // frontend TCP accepts
    std::atomic<uint64_t> quic_conns{0};        // QUIC sessions established
    std::atomic<uint64_t> requests{0};          // client exchanges begun
    std::atomic<uint64_t> resp_ok{0};           // backend responses < 400
    std::atomic<uint64_t> resp_err{0};          // write_error() sinks (5xx etc.)
    std::atomic<uint64_t> backend_connects{0};  // fresh (non-pooled) connects
    std::atomic<uint64_t> lat_us_total{0};      // request → backend response
    std::atomic<uint64_t> lat_count{0};
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    void record_latency(std::chrono::steady_clock::time_point from) {
        lat_us_total += uint64_t(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - from).count());
        ++lat_count;
    }

    /// Prometheus-style text; snapshot may be internally inconsistent across
    /// fields (each atomic read independently) — fine for monitoring.
    std::string render() const;
};

} // namespace ebpf_quic_proxy
