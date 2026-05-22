/**
 * metrics/uav-sinr-metrics.h
 * Module 58 — SINR Metrics
 *
 * Uses JammerManager real API:
 *   ComputeSinr(uav_index)      → SINR in dB
 *   IsJammed(uav_index)         → bool
 *   GetJammerImpact(uav_index)  → 0.0-1.0
 *   GetDropProbability(uav_index) → 0.0-1.0
 *   SINR_THRESHOLD_DB = 8.0
 *
 * Computes:
 *   - Per-UAV SINR (dB)
 *   - Per-cluster avg SINR
 *   - Global avg/min/max SINR
 *   - Jammed UAV count
 *   - Drop probability per UAV
 *   - Time-series SINR samples
 */

#ifndef UAV_SINR_METRICS_H
#define UAV_SINR_METRICS_H

#include "apps/uav-jammer-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <array>
#include <vector>
#include <string>

namespace uav {
namespace metrics {

struct SinrSample {
    double     time_s        = 0.0;
    utils::u32 uav_id        = 0;
    double     sinr_db       = 0.0;
    bool       jammed        = false;
    double     drop_prob     = 0.0;
};

class SinrMetrics {
public:
    SinrMetrics(
        const routing::TopologyResult* topo,
        apps::JammerManager*           jammer_mgr);

    /**
     * Compute — snapshot current SINR for all UAVs.
     * Can be called multiple times during simulation.
     */
    void Compute();

    /**
     * SchedulePeriodicSample — record SINR every interval_s.
     */
    void SchedulePeriodicSample(double interval_s);

    // Per-UAV
    double GetUavSinr       (utils::u32 uav_id) const;
    bool   IsUavJammed      (utils::u32 uav_id) const;
    double GetUavDropProb   (utils::u32 uav_id) const;
    double GetUavImpact     (utils::u32 uav_id) const;

    // Per-cluster
    double     GetClusterAvgSinr  (utils::u32 cluster_id) const;
    utils::u32 GetClusterJammedCount(utils::u32 cluster_id) const;

    // Global
    double     GetGlobalAvgSinr() const { return m_global_avg_sinr; }
    double     GetGlobalMinSinr() const { return m_global_min_sinr; }
    double     GetGlobalMaxSinr() const { return m_global_max_sinr; }
    utils::u32 GetJammedCount()   const { return m_jammed_count;    }
    double     GetSinrThreshold() const {
        return apps::JammerManager::SINR_THRESHOLD_DB;
    }

    const std::vector<SinrSample>& GetSamples() const {
        return m_samples;
    }

    void PrintSummary() const;
    void WriteCsv(const std::string& filename) const;

private:
    const routing::TopologyResult* m_topo;
    apps::JammerManager*           m_jammer_mgr;

    std::array<double, 18>     m_uav_sinr{};
    std::array<bool,   18>     m_uav_jammed{};
    std::array<double, 18>     m_uav_drop_prob{};
    std::array<double, 18>     m_uav_impact{};
    std::array<double, 3>      m_cluster_avg_sinr{};
    std::array<uint32_t, 3>    m_cluster_jammed{};

    double     m_global_avg_sinr = 0.0;
    double     m_global_min_sinr = 0.0;
    double     m_global_max_sinr = 0.0;
    utils::u32 m_jammed_count    = 0;

    std::vector<SinrSample> m_samples;
    double                  m_sample_interval = 1.0;

    void PeriodicSampleCallback();
};

} // namespace metrics
} // namespace uav

#endif // UAV_SINR_METRICS_H
