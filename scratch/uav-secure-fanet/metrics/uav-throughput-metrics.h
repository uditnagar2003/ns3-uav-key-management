/**
 * metrics/uav-throughput-metrics.h
 * Module 53 — Throughput Metrics
 *
 * Computes per-UAV, per-cluster, and global throughput
 * from FlowMonitorManager::GetFlowMetrics().
 *
 * Outputs:
 *   - Per-UAV throughput (kbps)
 *   - Per-cluster throughput (kbps)
 *   - Global throughput (kbps)
 *   - Time-series throughput samples
 */

#ifndef UAV_THROUGHPUT_METRICS_H
#define UAV_THROUGHPUT_METRICS_H

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
// ThroughputSample — one time-series measurement
// ===========================================================================
struct ThroughputSample {
    double      time_s       = 0.0;
    utils::u32  cluster_id   = 0;
    double      throughput_kbps = 0.0;
};

// ===========================================================================
// ThroughputMetrics — Module 53
// ===========================================================================
class ThroughputMetrics {
public:
    ThroughputMetrics(
        const routing::TopologyResult*    topo,
        routing::FlowMonitorManager*      flow_mgr);

    /**
     * Compute — extract throughput from FlowMonitor data.
     * Call after Simulator::Run() and CollectMetrics().
     */
    void Compute();

    // -----------------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------------

    /// Per-UAV throughput (kbps) indexed by UAV id (0-17)
    double GetUavThroughput(utils::u32 uav_id) const;

    /// Per-cluster total throughput (kbps)
    double GetClusterThroughput(utils::u32 cluster_id) const;

    /// Global total throughput (kbps)
    double GetGlobalThroughput() const {
        return m_global_throughput_kbps;
    }

    /// Peak throughput across all UAVs (kbps)
    double GetPeakThroughput() const {
        return m_peak_throughput_kbps;
    }

    /// Average per-UAV throughput (kbps)
    double GetAvgUavThroughput() const;

    // -----------------------------------------------------------------------
    // Periodic sampling (for time-series)
    // -----------------------------------------------------------------------
    void SchedulePeriodicSample(double interval_s);

    const std::vector<ThroughputSample>&
        GetSamples() const { return m_samples; }

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------
    void PrintSummary() const;

    /// Write throughput CSV
    /// Format: time_s, cluster_id, throughput_kbps
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    routing::FlowMonitorManager*   m_flow_mgr;

    std::array<double, 18>         m_uav_throughput{};
    std::array<double, 3>          m_cluster_throughput{};
    double                         m_global_throughput_kbps = 0.0;
    double                         m_peak_throughput_kbps   = 0.0;

    std::vector<ThroughputSample>  m_samples;
    double                         m_sample_interval = 1.0;

    void PeriodicSampleCallback();
};

} // namespace metrics
} // namespace uav

#endif // UAV_THROUGHPUT_METRICS_H
