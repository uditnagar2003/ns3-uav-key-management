/**
 * metrics/uav-delay-metrics.cc
 * Module 54 — Delay Metrics
 */

#include "metrics/uav-delay-metrics.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <limits>

NS_LOG_COMPONENT_DEFINE("UavDelayMetrics");

using namespace ns3;

namespace uav {
namespace metrics {

DelayMetrics::DelayMetrics(
    const routing::TopologyResult* topo,
    routing::FlowMonitorManager*   flow_mgr)
    : m_topo(topo)
    , m_flow_mgr(flow_mgr)
{
    m_cluster_avg_delay.fill(0.0);
    m_cluster_jitter.fill(0.0);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "DelayMetrics: constructed");
}

void DelayMetrics::Compute()
{
    const auto& flows = m_flow_mgr->GetFlowMetrics();

    // Reset
    for (auto& s : m_uav_delay) s = {};
    m_cluster_avg_delay.fill(0.0);
    m_cluster_jitter.fill(0.0);
    m_global_avg_delay_ms = 0.0;
    m_global_min_delay_ms =
        std::numeric_limits<double>::max();
    m_global_max_delay_ms = 0.0;
    m_global_jitter_ms    = 0.0;

    if (flows.empty()) {
        m_global_min_delay_ms = 0.0;
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "DelayMetrics: no flows");
        return;
    }

    // Per-cluster accumulators
    std::array<double, 3> cluster_delay_sum{};
    std::array<double, 3> cluster_jitter_sum{};
    std::array<uint32_t, 3> cluster_count{};
    cluster_delay_sum.fill(0.0);
    cluster_jitter_sum.fill(0.0);
    cluster_count.fill(0);

    double global_sum   = 0.0;
    double jitter_sum   = 0.0;
    uint32_t flow_count = 0;

    for (const auto& f : flows) {
        // Per-UAV
        if (f.src_uav < 18) {
            m_uav_delay[f.src_uav].avg_ms    = f.avg_delay_ms;
            m_uav_delay[f.src_uav].min_ms    = f.min_delay_ms;
            m_uav_delay[f.src_uav].max_ms    = f.max_delay_ms;
            m_uav_delay[f.src_uav].jitter_ms = f.jitter_ms;
        }

        // Per-cluster
        if (f.cluster_id < 3) {
            cluster_delay_sum[f.cluster_id]  += f.avg_delay_ms;
            cluster_jitter_sum[f.cluster_id] += f.jitter_ms;
            ++cluster_count[f.cluster_id];
        }

        // Global
        global_sum += f.avg_delay_ms;
        jitter_sum += f.jitter_ms;
        if (f.min_delay_ms < m_global_min_delay_ms)
            m_global_min_delay_ms = f.min_delay_ms;
        if (f.max_delay_ms > m_global_max_delay_ms)
            m_global_max_delay_ms = f.max_delay_ms;
        ++flow_count;
    }

    // Average per-cluster
    for (uint32_t c = 0; c < 3; ++c) {
        if (cluster_count[c] > 0) {
            m_cluster_avg_delay[c] =
                cluster_delay_sum[c] / cluster_count[c];
            m_cluster_jitter[c] =
                cluster_jitter_sum[c] / cluster_count[c];
        }
    }

    // Global averages
    if (flow_count > 0) {
        m_global_avg_delay_ms = global_sum / flow_count;
        m_global_jitter_ms    = jitter_sum / flow_count;
    }
    if (m_global_min_delay_ms ==
        std::numeric_limits<double>::max())
        m_global_min_delay_ms = 0.0;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "DelayMetrics: computed flows=" << flows.size()
        << " avg=" << m_global_avg_delay_ms << "ms");
}

double DelayMetrics::GetUavAvgDelay(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_delay[uav_id].avg_ms;
}

double DelayMetrics::GetUavMinDelay(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_delay[uav_id].min_ms;
}

double DelayMetrics::GetUavMaxDelay(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_delay[uav_id].max_ms;
}

double DelayMetrics::GetUavJitter(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_delay[uav_id].jitter_ms;
}

double DelayMetrics::GetClusterAvgDelay(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_avg_delay[cluster_id];
}

double DelayMetrics::GetClusterJitter(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_jitter[cluster_id];
}

void DelayMetrics::SchedulePeriodicSample(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_sample_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &DelayMetrics::PeriodicSampleCallback,
        this);
}

void DelayMetrics::PeriodicSampleCallback()
{
    for (uint32_t c = 0; c < 3; ++c) {
        DelaySample s;
        s.time_s       = Simulator::Now().GetSeconds();
        s.cluster_id   = c;
        s.avg_delay_ms = m_cluster_avg_delay[c];
        s.jitter_ms    = m_cluster_jitter[c];
        m_samples.push_back(s);
    }
    Simulator::Schedule(
        Seconds(m_sample_interval),
        &DelayMetrics::PeriodicSampleCallback,
        this);
}

void DelayMetrics::PrintSummary() const
{
    std::cout << "\n=== Delay Metrics ===\n";
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  Global avg: "
              << m_global_avg_delay_ms << " ms\n";
    std::cout << "  Global min: "
              << m_global_min_delay_ms << " ms\n";
    std::cout << "  Global max: "
              << m_global_max_delay_ms << " ms\n";
    std::cout << "  Jitter:     "
              << m_global_jitter_ms    << " ms\n";
    for (uint32_t c = 0; c < 3; ++c) {
        std::cout << "  C" << c
            << " avg=" << m_cluster_avg_delay[c]
            << " jitter=" << m_cluster_jitter[c]
            << " ms\n";
    }
}

void DelayMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) return;
    f << "uav_id,cluster_id,avg_delay_ms,"
         "min_delay_ms,max_delay_ms,jitter_ms\n";
    for (uint32_t i = 0; i < 18; ++i) {
        f << i << "," << (i/6) << ","
          << m_uav_delay[i].avg_ms    << ","
          << m_uav_delay[i].min_ms    << ","
          << m_uav_delay[i].max_ms    << ","
          << m_uav_delay[i].jitter_ms << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "DelayMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
