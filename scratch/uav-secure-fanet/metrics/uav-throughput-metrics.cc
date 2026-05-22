/**
 * metrics/uav-throughput-metrics.cc
 * Module 53 — Throughput Metrics
 */

#include "metrics/uav-throughput-metrics.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

NS_LOG_COMPONENT_DEFINE("UavThroughputMetrics");

using namespace ns3;

namespace uav {
namespace metrics {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
ThroughputMetrics::ThroughputMetrics(
    const routing::TopologyResult*    topo,
    routing::FlowMonitorManager*      flow_mgr)
    : m_topo(topo)
    , m_flow_mgr(flow_mgr)
{
    m_uav_throughput.fill(0.0);
    m_cluster_throughput.fill(0.0);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "ThroughputMetrics: constructed");
}

// ---------------------------------------------------------------------------
// Compute
// ---------------------------------------------------------------------------
void ThroughputMetrics::Compute()
{
    const auto& flows = m_flow_mgr->GetFlowMetrics();

    m_uav_throughput.fill(0.0);
    m_cluster_throughput.fill(0.0);
    m_global_throughput_kbps = 0.0;
    m_peak_throughput_kbps   = 0.0;

    for (const auto& f : flows) {
        // Per-UAV
        if (f.src_uav < 18) {
            m_uav_throughput[f.src_uav] +=
                f.throughput_kbps;
        }

        // Per-cluster
        if (f.cluster_id < 3) {
            m_cluster_throughput[f.cluster_id] +=
                f.throughput_kbps;
        }

        // Global
        m_global_throughput_kbps += f.throughput_kbps;

        // Peak
        if (f.throughput_kbps > m_peak_throughput_kbps)
            m_peak_throughput_kbps = f.throughput_kbps;
    }

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "ThroughputMetrics: computed"
        " flows=" << flows.size()
        << " global=" << m_global_throughput_kbps
        << " kbps");
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------
double ThroughputMetrics::GetUavThroughput(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_throughput[uav_id];
}

double ThroughputMetrics::GetClusterThroughput(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_throughput[cluster_id];
}

double ThroughputMetrics::GetAvgUavThroughput() const
{
    double sum = 0.0;
    uint32_t count = 0;
    for (const auto& t : m_uav_throughput) {
        if (t > 0.0) { sum += t; ++count; }
    }
    return (count > 0) ? sum / count : 0.0;
}

// ---------------------------------------------------------------------------
// Periodic sampling
// ---------------------------------------------------------------------------
void ThroughputMetrics::SchedulePeriodicSample(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_sample_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &ThroughputMetrics::PeriodicSampleCallback,
        this);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "ThroughputMetrics: periodic sampling every "
        << interval_s << "s");
}

void ThroughputMetrics::PeriodicSampleCallback()
{
    // Take snapshot of current cluster throughput
    for (uint32_t c = 0; c < 3; ++c) {
        ThroughputSample s;
        s.time_s          = Simulator::Now().GetSeconds();
        s.cluster_id      = c;
        s.throughput_kbps = m_cluster_throughput[c];
        m_samples.push_back(s);
    }

    Simulator::Schedule(
        Seconds(m_sample_interval),
        &ThroughputMetrics::PeriodicSampleCallback,
        this);
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
void ThroughputMetrics::PrintSummary() const
{
    std::cout << "\n=== Throughput Metrics ===\n";
    std::cout << "  Global:  "
              << std::fixed << std::setprecision(2)
              << m_global_throughput_kbps << " kbps\n";
    std::cout << "  Peak:    "
              << m_peak_throughput_kbps << " kbps\n";
    std::cout << "  Avg/UAV: "
              << GetAvgUavThroughput() << " kbps\n";

    for (uint32_t c = 0; c < 3; ++c) {
        std::cout << "  C" << c << ": "
            << m_cluster_throughput[c] << " kbps\n";
    }

    for (uint32_t i = 0; i < 18; ++i) {
        if (m_uav_throughput[i] > 0.0) {
            std::cout << "  UAV" << i << ": "
                << m_uav_throughput[i] << " kbps\n";
        }
    }
}

void ThroughputMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) {
        UAV_LOG_WARN(uav::log::channels::SYSTEM,
            "ThroughputMetrics: cannot open "
            << filename);
        return;
    }

    f << "uav_id,cluster_id,throughput_kbps\n";
    for (uint32_t i = 0; i < 18; ++i) {
        f << i << ","
          << (i / 6) << ","
          << m_uav_throughput[i] << "\n";
    }
    f.close();

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "ThroughputMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
