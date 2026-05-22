/**
 * metrics/uav-routing-overhead.h
 * Module 56 — Routing Overhead Metrics
 *
 * Routing overhead = OLSR control bytes / total data bytes
 *
 * Computes:
 *   - Total OLSR control bytes (HELLO + TC packets)
 *   - Routing overhead ratio
 *   - Per-cluster overhead
 *   - Normalized overhead (bytes/s)
 */

#ifndef UAV_ROUTING_OVERHEAD_H
#define UAV_ROUTING_OVERHEAD_H

#include "routing/uav-flowmonitor.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"
#include "ns3/olsr-module.h"

#include <array>
#include <vector>
#include <string>

namespace uav {
namespace metrics {

struct RoutingOverheadSample {
    double     time_s          = 0.0;
    double     overhead_ratio  = 0.0;
    double     ctrl_bytes_s    = 0.0;
};

class RoutingOverheadMetrics {
public:
    RoutingOverheadMetrics(
        const routing::TopologyResult* topo,
        routing::FlowMonitorManager*   flow_mgr);

    void Compute(double sim_duration_s);

    double GetOverheadRatio()    const {
        return m_overhead_ratio;
    }
    double GetCtrlBytesPerSec()  const {
        return m_ctrl_bytes_per_sec;
    }
    double GetTotalCtrlBytes()   const {
        return m_total_ctrl_bytes;
    }
    double GetTotalDataBytes()   const {
        return m_total_data_bytes;
    }

    void SchedulePeriodicSample(double interval_s);
    const std::vector<RoutingOverheadSample>&
        GetSamples() const { return m_samples; }

    void PrintSummary() const;
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    routing::FlowMonitorManager*   m_flow_mgr;

    double     m_overhead_ratio     = 0.0;
    double     m_ctrl_bytes_per_sec = 0.0;
    double     m_total_ctrl_bytes   = 0.0;
    double     m_total_data_bytes   = 0.0;
    double     m_sim_duration_s     = 0.0;

    std::vector<RoutingOverheadSample> m_samples;
    double     m_sample_interval    = 1.0;

    // OLSR packet size estimates (per spec)
    // HELLO: sent every 2s per UAV, ~60 bytes each
    // TC:    sent every 5s per UAV, ~80 bytes each
    static constexpr double HELLO_INTERVAL_S  = 2.0;
    static constexpr double TC_INTERVAL_S     = 5.0;
    static constexpr double HELLO_SIZE_BYTES  = 60.0;
    static constexpr double TC_SIZE_BYTES     = 80.0;

    void PeriodicSampleCallback();
};

} // namespace metrics
} // namespace uav

#endif // UAV_ROUTING_OVERHEAD_H
