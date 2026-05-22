/**
 * metrics/uav-delay-metrics.h
 * Module 54 — Delay Metrics
 *
 * Computes per-UAV, per-cluster, global delay from
 * FlowMonitorManager::GetFlowMetrics().
 *
 * Metrics:
 *   - Average end-to-end delay (ms)
 *   - Min/Max delay (ms)
 *   - Jitter (ms)
 *   - Per-UAV delay
 *   - Per-cluster average delay
 */

#ifndef UAV_DELAY_METRICS_H
#define UAV_DELAY_METRICS_H

#include "routing/uav-flowmonitor.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include <array>
#include <vector>
#include <string>

namespace uav {
namespace metrics {

// ===========================================================================
// DelaySample — time-series entry
// ===========================================================================
struct DelaySample {
    double     time_s       = 0.0;
    utils::u32 cluster_id   = 0;
    double     avg_delay_ms = 0.0;
    double     jitter_ms    = 0.0;
};

// ===========================================================================
// DelayMetrics — Module 54
// ===========================================================================
class DelayMetrics {
public:
    DelayMetrics(
        const routing::TopologyResult* topo,
        routing::FlowMonitorManager*   flow_mgr);

    /// Compute from FlowMonitor data.
    /// Call after Simulator::Run() and CollectMetrics().
    void Compute();

    // Per-UAV
    double GetUavAvgDelay  (utils::u32 uav_id) const;
    double GetUavMinDelay  (utils::u32 uav_id) const;
    double GetUavMaxDelay  (utils::u32 uav_id) const;
    double GetUavJitter    (utils::u32 uav_id) const;

    // Per-cluster
    double GetClusterAvgDelay(utils::u32 cluster_id) const;
    double GetClusterJitter  (utils::u32 cluster_id) const;

    // Global
    double GetGlobalAvgDelay() const { return m_global_avg_delay_ms; }
    double GetGlobalMinDelay() const { return m_global_min_delay_ms; }
    double GetGlobalMaxDelay() const { return m_global_max_delay_ms; }
    double GetGlobalJitter()   const { return m_global_jitter_ms;    }

    // Periodic sampling
    void SchedulePeriodicSample(double interval_s);
    const std::vector<DelaySample>& GetSamples() const {
        return m_samples;
    }

    void PrintSummary() const;
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    routing::FlowMonitorManager*   m_flow_mgr;

    struct UavDelayStats {
        double avg_ms = 0.0;
        double min_ms = 0.0;
        double max_ms = 0.0;
        double jitter_ms = 0.0;
    };

    std::array<UavDelayStats, 18>  m_uav_delay{};
    std::array<double, 3>          m_cluster_avg_delay{};
    std::array<double, 3>          m_cluster_jitter{};

    double m_global_avg_delay_ms = 0.0;
    double m_global_min_delay_ms = 0.0;
    double m_global_max_delay_ms = 0.0;
    double m_global_jitter_ms    = 0.0;

    std::vector<DelaySample>       m_samples;
    double                         m_sample_interval = 1.0;

    void PeriodicSampleCallback();
};

} // namespace metrics
} // namespace uav

#endif // UAV_DELAY_METRICS_H
