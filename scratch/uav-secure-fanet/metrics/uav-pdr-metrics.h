/**
 * metrics/uav-pdr-metrics.h
 * Module 55 — Packet Delivery Ratio Metrics
 *
 * PDR = rx_packets / tx_packets per flow
 *
 * Computes:
 *   - Per-UAV PDR
 *   - Per-cluster PDR
 *   - Global PDR
 *   - Packet loss count per UAV
 *   - Time-series PDR samples
 */

#ifndef UAV_PDR_METRICS_H
#define UAV_PDR_METRICS_H

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

struct PdrSample {
    double     time_s     = 0.0;
    utils::u32 cluster_id = 0;
    double     pdr        = 0.0;
};

class PdrMetrics {
public:
    PdrMetrics(
        const routing::TopologyResult* topo,
        routing::FlowMonitorManager*   flow_mgr);

    void Compute();

    double GetUavPdr        (utils::u32 uav_id)     const;
    double GetUavLossRate   (utils::u32 uav_id)     const;
    utils::u64 GetUavLostPkts(utils::u32 uav_id)   const;
    double GetClusterPdr    (utils::u32 cluster_id) const;
    double GetGlobalPdr     ()                       const {
        return m_global_pdr;
    }
    utils::u64 GetGlobalLost() const { return m_global_lost; }
    utils::u64 GetGlobalTx()   const { return m_global_tx;   }
    utils::u64 GetGlobalRx()   const { return m_global_rx;   }

    void SchedulePeriodicSample(double interval_s);
    const std::vector<PdrSample>& GetSamples() const {
        return m_samples;
    }

    void PrintSummary() const;
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    routing::FlowMonitorManager*   m_flow_mgr;

    struct UavPdrStats {
        double     pdr       = 0.0;
        utils::u64 tx        = 0;
        utils::u64 rx        = 0;
        utils::u64 lost      = 0;
    };

    std::array<UavPdrStats, 18> m_uav_pdr{};
    std::array<double, 3>       m_cluster_pdr{};

    double     m_global_pdr  = 0.0;
    utils::u64 m_global_tx   = 0;
    utils::u64 m_global_rx   = 0;
    utils::u64 m_global_lost = 0;

    std::vector<PdrSample> m_samples;
    double                 m_sample_interval = 1.0;

    void PeriodicSampleCallback();
};

} // namespace metrics
} // namespace uav

#endif // UAV_PDR_METRICS_H
