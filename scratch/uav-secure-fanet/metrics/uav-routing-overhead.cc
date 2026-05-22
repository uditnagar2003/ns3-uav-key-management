/**
 * metrics/uav-routing-overhead.cc
 * Module 56 — Routing Overhead Metrics
 */

#include "metrics/uav-routing-overhead.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>

NS_LOG_COMPONENT_DEFINE("UavRoutingOverhead");

using namespace ns3;

namespace uav {
namespace metrics {

RoutingOverheadMetrics::RoutingOverheadMetrics(
    const routing::TopologyResult* topo,
    routing::FlowMonitorManager*   flow_mgr)
    : m_topo(topo)
    , m_flow_mgr(flow_mgr)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RoutingOverheadMetrics: constructed");
}

void RoutingOverheadMetrics::Compute(
    double sim_duration_s)
{
    m_sim_duration_s = sim_duration_s;

    // Get total data bytes from FlowMonitor
    const auto& flows = m_flow_mgr->GetFlowMetrics();
    m_total_data_bytes = 0.0;
    for (const auto& f : flows)
        m_total_data_bytes +=
            static_cast<double>(f.rx_bytes);

    // Estimate OLSR control traffic
    // 18 UAVs + 1 jammer = 19 wifi nodes
    // HELLO: each UAV sends every 2s
    // TC:    each UAV sends every 5s
    uint32_t n_uavs = m_topo->uav_nodes.GetN();

    double hello_per_uav =
        sim_duration_s / HELLO_INTERVAL_S;
    double tc_per_uav =
        sim_duration_s / TC_INTERVAL_S;

    m_total_ctrl_bytes =
        n_uavs * hello_per_uav * HELLO_SIZE_BYTES +
        n_uavs * tc_per_uav   * TC_SIZE_BYTES;

    // Overhead ratio = ctrl / (ctrl + data)
    double total = m_total_ctrl_bytes + m_total_data_bytes;
    m_overhead_ratio = (total > 0.0)
        ? m_total_ctrl_bytes / total
        : 0.0;

    // Overhead per second
    m_ctrl_bytes_per_sec = (sim_duration_s > 0.0)
        ? m_total_ctrl_bytes / sim_duration_s
        : 0.0;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RoutingOverheadMetrics: computed"
        " ctrl=" << m_total_ctrl_bytes
        << "B data=" << m_total_data_bytes
        << "B ratio=" << m_overhead_ratio
        << " bps=" << m_ctrl_bytes_per_sec);
}

void RoutingOverheadMetrics::SchedulePeriodicSample(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_sample_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &RoutingOverheadMetrics::PeriodicSampleCallback,
        this);
}

void RoutingOverheadMetrics::PeriodicSampleCallback()
{
    RoutingOverheadSample s;
    s.time_s         = Simulator::Now().GetSeconds();
    s.overhead_ratio = m_overhead_ratio;
    s.ctrl_bytes_s   = m_ctrl_bytes_per_sec;
    m_samples.push_back(s);

    Simulator::Schedule(
        Seconds(m_sample_interval),
        &RoutingOverheadMetrics::PeriodicSampleCallback,
        this);
}

void RoutingOverheadMetrics::PrintSummary() const
{
    std::cout << "\n=== Routing Overhead Metrics ===\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Total ctrl bytes:  "
              << m_total_ctrl_bytes   << " B\n";
    std::cout << "  Total data bytes:  "
              << m_total_data_bytes   << " B\n";
    std::cout << "  Overhead ratio:    "
              << m_overhead_ratio * 100.0 << " %\n";
    std::cout << "  Ctrl bytes/sec:    "
              << m_ctrl_bytes_per_sec << " B/s\n";
}

void RoutingOverheadMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) return;
    f << "metric,value\n";
    f << "total_ctrl_bytes,"  << m_total_ctrl_bytes   << "\n";
    f << "total_data_bytes,"  << m_total_data_bytes   << "\n";
    f << "overhead_ratio,"    << m_overhead_ratio     << "\n";
    f << "ctrl_bytes_per_sec,"<< m_ctrl_bytes_per_sec << "\n";
    f << "sim_duration_s,"    << m_sim_duration_s     << "\n";
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "RoutingOverheadMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
