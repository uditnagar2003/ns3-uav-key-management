/**
 * utils/uav-time-utils.h
 * Time helpers — wall-clock, monotonic, formatting, microsecond timestamps.
 *
 * IMPORTANT:
 *   NS-3 has its own simulation clock (ns3::Simulator::Now()).
 *   These utilities are for REAL wall-clock time only:
 *     - benchmarking (rekey latency measurement)
 *     - log timestamps
 *     - replay protection time-skew checks
 */

#ifndef UAV_TIME_UTILS_H
#define UAV_TIME_UTILS_H

#include "uav-types.h"
#include <string>

namespace uav {
namespace utils {

class TimeUtils {
public:
    /// Microseconds since UNIX epoch (UTC). Used for replay timestamps.
    static u64 NowEpochMicros();

    /// Microseconds since steady clock origin (monotonic).
    static u64 NowSteadyMicros();

    /// ISO-8601 UTC timestamp: "2025-01-15T10:23:45.123456Z"
    static std::string NowIso8601();

    /// Compact filename-safe timestamp: "20250115_102345_123456"
    static std::string NowFileSafe();

    /// Format an absolute epoch-micros value as ISO-8601
    static std::string FormatEpochMicros(u64 epoch_us);

    /// Sleep helpers — used only in test harness, NOT during simulation.
    static void SleepMicros(u64 us);
    static void SleepMillis(u64 ms);

    /// Elapsed microseconds between two TimePoint values.
    static u64 ElapsedMicros(TimePoint start, TimePoint end);

    /// Returns true if |a - b| <= max_skew_us
    static bool WithinSkew(u64 a_us, u64 b_us, u64 max_skew_us);
};

// ---------------------------------------------------------------------------
// ScopedTimer — RAII benchmark helper.
// Usage:
//     {
//         ScopedTimer t("rekey_op");
//         do_rekey();
//     }  // logs elapsed time on destruction
// ---------------------------------------------------------------------------
class ScopedTimer {
public:
    explicit ScopedTimer(std::string label);
    ~ScopedTimer();

    /// Stop manually; destructor becomes a no-op.
    u64 Stop();

    /// Get elapsed without stopping.
    u64 ElapsedMicros() const;

private:
    std::string m_label;
    TimePoint   m_start;
    bool        m_stopped;
};

} // namespace utils
} // namespace uav

#endif // UAV_TIME_UTILS_H