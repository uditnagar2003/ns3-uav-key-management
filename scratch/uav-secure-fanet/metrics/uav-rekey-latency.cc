/**
 * metrics/uav-rekey-latency.cc
 * Module 57 — Rekey Latency Metrics
 */

#include "metrics/uav-rekey-latency.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <limits>

NS_LOG_COMPONENT_DEFINE("UavRekeyLatency");

using namespace ns3;

namespace uav {
namespace metrics {

RekeyLatencyMetrics::RekeyLatencyMetrics(
    const routing::TopologyResult* topo,
    routing::FlowMonitorManager*   flow_mgr,
    apps::RekeyManager*            rekey_mgr)
    : m_topo(topo)
    , m_flow_mgr(flow_mgr)
    , m_rekey_mgr(rekey_mgr)
{
    m_cluster_avg_latency.fill(0.0);
    m_cluster_count.fill(0);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RekeyLatencyMetrics: constructed");
}

void RekeyLatencyMetrics::Compute()
{
    if (!m_rekey_mgr) return;

    const auto& history = m_rekey_mgr->GetHistory();
    m_total_rekeys = history.size();

    if (history.empty()) {
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "RekeyLatencyMetrics: no rekey events");
        return;
    }

    double sum   = 0.0;
    double min_v = std::numeric_limits<double>::max();
    double max_v = 0.0;

    std::array<double, 3>   cluster_sum{};
    cluster_sum.fill(0.0);
    m_cluster_count.fill(0);

    for (const auto& r : history) {
        // RekeyEvent has latency_ms field
        double lat = r.latency_ms;

        sum += lat;
        if (lat < min_v) min_v = lat;
        if (lat > max_v) max_v = lat;

        if (r.cluster_id < 3) {
            cluster_sum[r.cluster_id]   += lat;
            ++m_cluster_count[r.cluster_id];
        }

        // Build sample
        RekeyLatencySample s;
        s.time_s     = r.time_s;
        s.cluster_id = r.cluster_id;
        s.latency_ms = lat;
        s.reason     = r.reason;
        m_samples.push_back(s);
    }

    m_avg_latency_ms = sum / history.size();
    m_min_latency_ms = (min_v == std::numeric_limits<double>::max())
                       ? 0.0 : min_v;
    m_max_latency_ms = max_v;

    for (uint32_t c = 0; c < 3; ++c) {
        if (m_cluster_count[c] > 0)
            m_cluster_avg_latency[c] =
                cluster_sum[c] / m_cluster_count[c];
    }

    // Report to FlowMonitorManager
    m_flow_mgr->RecordRekeyStart(0, 0.0);
    m_flow_mgr->RecordRekeyComplete(0, m_avg_latency_ms);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RekeyLatencyMetrics: computed"
        " total=" << m_total_rekeys
        << " avg=" << m_avg_latency_ms << "ms"
        << " min=" << m_min_latency_ms << "ms"
        << " max=" << m_max_latency_ms << "ms");
}

double RekeyLatencyMetrics::GetClusterAvgLatency(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_avg_latency[cluster_id];
}

void RekeyLatencyMetrics::PrintSummary() const
{
    std::cout << "\n=== Rekey Latency Metrics ===\n";
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  Total rekeys: " << m_total_rekeys  << "\n";
    std::cout << "  Avg latency:  "
              << m_avg_latency_ms << " ms\n";
    std::cout << "  Min latency:  "
              << m_min_latency_ms << " ms\n";
    std::cout << "  Max latency:  "
              << m_max_latency_ms << " ms\n";
    for (uint32_t c = 0; c < 3; ++c) {
        std::cout << "  C" << c
            << " avg=" << m_cluster_avg_latency[c]
            << " ms (" << m_cluster_count[c]
            << " rekeys)\n";
    }
}

void RekeyLatencyMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) return;
    f << "time_s,cluster_id,reason,latency_ms\n";
    for (const auto& s : m_samples) {
        f << s.time_s << ","
          << s.cluster_id << ","
          << apps::RekeyReasonStr(s.reason) << ","
          << s.latency_ms << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RekeyLatencyMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
