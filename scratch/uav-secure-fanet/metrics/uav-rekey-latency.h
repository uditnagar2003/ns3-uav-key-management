/**
 * metrics/uav-rekey-latency.h
 * Module 57 — Rekey Latency Metrics
 *
 * Uses FlowMonitorManager::RecordRekeyStart/Complete()
 * to measure rekey latency per cluster.
 *
 * Also tracks:
 *   - RekeyManager history (already collected)
 *   - Per-trigger type latency
 *   - Min/Max/Avg rekey latency
 */

#ifndef UAV_REKEY_LATENCY_H
#define UAV_REKEY_LATENCY_H

#include "routing/uav-flowmonitor.h"
#include "apps/uav-rekey-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include <array>
#include <vector>
#include <string>

namespace uav {
namespace metrics {

struct RekeyLatencySample {
    double     time_s      = 0.0;
    utils::u32 cluster_id  = 0;
    double     latency_ms  = 0.0;
    apps::RekeyReason reason;
};

class RekeyLatencyMetrics {
public:
    RekeyLatencyMetrics(
        const routing::TopologyResult* topo,
        routing::FlowMonitorManager*   flow_mgr,
        apps::RekeyManager*            rekey_mgr);

    /**
     * Compute — extract rekey latency from RekeyManager history.
     * Call after Simulator::Run().
     */
    void Compute();

    double GetAvgLatency()   const { return m_avg_latency_ms;  }
    double GetMinLatency()   const { return m_min_latency_ms;  }
    double GetMaxLatency()   const { return m_max_latency_ms;  }
    utils::u64 GetTotalRekeys() const { return m_total_rekeys; }

    double GetClusterAvgLatency(utils::u32 cluster_id) const;

    const std::vector<RekeyLatencySample>&
        GetSamples() const { return m_samples; }

    void PrintSummary() const;
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    routing::FlowMonitorManager*   m_flow_mgr;
    apps::RekeyManager*            m_rekey_mgr;

    double     m_avg_latency_ms  = 0.0;
    double     m_min_latency_ms  = 0.0;
    double     m_max_latency_ms  = 0.0;
    utils::u64 m_total_rekeys    = 0;

    std::array<double, 3>     m_cluster_avg_latency{};
    std::array<uint32_t, 3>   m_cluster_count{};

    std::vector<RekeyLatencySample> m_samples;
};

} // namespace metrics
} // namespace uav

#endif // UAV_REKEY_LATENCY_H
