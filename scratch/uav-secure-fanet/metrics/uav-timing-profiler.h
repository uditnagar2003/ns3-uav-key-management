/**
 * metrics/uav-timing-profiler.h
 * Real timing profiler for crypto + network events
 *
 * Uses:
 *   std::chrono — for CPU/wall-clock crypto timing
 *   Simulator::Now() — for NS-3 network event timing
 */

#ifndef UAV_TIMING_PROFILER_H
#define UAV_TIMING_PROFILER_H

#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/simulator.h"

#include <chrono>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <array>
#include <mutex>

namespace uav {
namespace metrics {

// ===========================================================================
// CryptoTimingRecord — one crypto operation measurement
// ===========================================================================
struct CryptoTimingRecord {
    std::string operation;    // AES_ENC, AES_DEC, HMAC_GEN etc
    utils::u32  node_id   = 0;
    utils::u32  cluster_id= 0;
    double      sim_time_s= 0.0;
    double      wall_us   = 0.0;  // microseconds wall-clock
    uint32_t    data_bytes= 0;
};

// ===========================================================================
// NetworkEventRecord — one network timing measurement
// ===========================================================================
struct NetworkEventRecord {
    std::string event_type;  // JOIN, LEAVE, REKEY, HANDOVER etc
    utils::u32  uav_id    = 0;
    utils::u32  cluster_id= 0;
    double      trigger_s = 0.0;
    double      complete_s= 0.0;
    double      latency_ms= 0.0;
    std::string details;
};

// ===========================================================================
// PacketTimingRecord — per-packet timing
// ===========================================================================
struct PacketTimingRecord {
    std::string pkt_type;
    utils::u32  src_id    = 0;
    utils::u32  dst_id    = 0;
    double      send_s    = 0.0;
    double      recv_s    = 0.0;
    double      delay_ms  = 0.0;
    uint32_t    size_bytes= 0;
};

// ===========================================================================
// ScopeTimer — RAII wall-clock timer
// ===========================================================================
class ScopeTimer {
public:
    ScopeTimer() : m_start(Clock::now()) {}

    double ElapsedUs() const {
        auto end  = Clock::now();
        auto diff = end - m_start;
        using us  = std::chrono::microseconds;
        return static_cast<double>(
            std::chrono::duration_cast<us>(
                diff).count());
    }

    double ElapsedMs() const {
        return ElapsedUs() / 1000.0;
    }

private:
    using Clock = std::chrono::high_resolution_clock;
    std::chrono::time_point<Clock> m_start;
};

// ===========================================================================
// TimingProfiler — central metrics collector
// ===========================================================================
class TimingProfiler {
public:
    static TimingProfiler& Instance() {
        static TimingProfiler inst;
        return inst;
    }

    void Reset();

    // -----------------------------------------------------------------------
    // Crypto timing (wall-clock)
    // -----------------------------------------------------------------------
    void RecordCrypto(
        const std::string& operation,
        utils::u32         node_id,
        utils::u32         cluster_id,
        double             wall_us,
        uint32_t           data_bytes = 0);

    // -----------------------------------------------------------------------
    // Network event timing (sim time)
    // -----------------------------------------------------------------------
    void RecordEventStart(
        const std::string& event_type,
        utils::u32         uav_id,
        utils::u32         cluster_id);

    void RecordEventComplete(
        const std::string& event_type,
        utils::u32         uav_id,
        const std::string& details = "");

    // -----------------------------------------------------------------------
    // Packet timing
    // -----------------------------------------------------------------------
    void RecordPacketSend(
        const std::string& pkt_type,
        utils::u32         src_id,
        utils::u32         dst_id,
        uint32_t           size_bytes = 0);

    void RecordPacketRecv(
        const std::string& pkt_type,
        utils::u32         src_id,
        utils::u32         dst_id);

    // -----------------------------------------------------------------------
    // Direct record (for rekey/handover managers)
    // -----------------------------------------------------------------------
    void RecordNetworkEvent(const NetworkEventRecord& r);

    // -----------------------------------------------------------------------
    // CSV export
    // -----------------------------------------------------------------------
    void ExportCryptoTimingCsv(
        const std::string& path) const;
    void ExportEventProcessingCsv(
        const std::string& path) const;
    void ExportPacketDelayCsv(
        const std::string& path) const;
    void ExportAllCsv(
        const std::string& output_dir) const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    double GetAvgCryptoTime(
        const std::string& op) const;
    double GetAvgEventLatency(
        const std::string& event_type) const;
    size_t GetCryptoCount()  const {
        return m_crypto.size();
    }
    size_t GetEventCount()   const {
        return m_events.size();
    }
    size_t GetPacketCount()  const {
        return m_packets.size();
    }

    void PrintSummary() const;

private:
    TimingProfiler() = default;

    std::vector<CryptoTimingRecord>  m_crypto;
    std::vector<NetworkEventRecord>  m_events;
    std::vector<PacketTimingRecord>  m_packets;

    // Pending events (start recorded, waiting for complete)
    struct PendingEvent {
        std::string event_type;
        utils::u32  cluster_id = 0;
        double      trigger_s  = 0.0;
    };
    std::map<std::string, PendingEvent> m_pending;
    // key = event_type + "_" + uav_id
};

// ===========================================================================
// Convenience macros for crypto timing
// ===========================================================================
#define UAV_TIME_CRYPTO_START(op, node, cluster) \
    uav::metrics::ScopeTimer _timer_##op; \
    (void)0

#define UAV_TIME_CRYPTO_END(op, node, cluster, bytes) \
    uav::metrics::TimingProfiler::Instance().RecordCrypto( \
        #op, node, cluster, _timer_##op.ElapsedUs(), bytes)

} // namespace metrics
} // namespace uav

#endif // UAV_TIMING_PROFILER_H
