/**
 * metrics/uav-pdr-metrics.cc
 * Module 55 — PDR Metrics
 */

#include "metrics/uav-pdr-metrics.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>

NS_LOG_COMPONENT_DEFINE("UavPdrMetrics");

using namespace ns3;

namespace uav {
namespace metrics {

PdrMetrics::PdrMetrics(
    const routing::TopologyResult* topo,
    routing::FlowMonitorManager*   flow_mgr)
    : m_topo(topo)
    , m_flow_mgr(flow_mgr)
{
    m_cluster_pdr.fill(0.0);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PdrMetrics: constructed");
}

void PdrMetrics::Compute()
{
    const auto& flows = m_flow_mgr->GetFlowMetrics();

    for (auto& s : m_uav_pdr) s = {};
    m_cluster_pdr.fill(0.0);
    m_global_pdr  = 0.0;
    m_global_tx   = 0;
    m_global_rx   = 0;
    m_global_lost = 0;

    std::array<double, 3>     cluster_pdr_sum{};
    std::array<uint32_t, 3>   cluster_count{};
    cluster_pdr_sum.fill(0.0);
    cluster_count.fill(0);

    double pdr_sum = 0.0;
    uint32_t flow_count = 0;

    for (const auto& f : flows) {
        if (f.src_uav < 18) {
            m_uav_pdr[f.src_uav].pdr  = f.pdr;
            m_uav_pdr[f.src_uav].tx   = f.tx_packets;
            m_uav_pdr[f.src_uav].rx   = f.rx_packets;
            m_uav_pdr[f.src_uav].lost = f.lost_packets;
        }
        if (f.cluster_id < 3) {
            cluster_pdr_sum[f.cluster_id] += f.pdr;
            ++cluster_count[f.cluster_id];
        }
        pdr_sum += f.pdr;
        m_global_tx   += f.tx_packets;
        m_global_rx   += f.rx_packets;
        m_global_lost += f.lost_packets;
        ++flow_count;
    }

    for (uint32_t c = 0; c < 3; ++c) {
        if (cluster_count[c] > 0)
            m_cluster_pdr[c] =
                cluster_pdr_sum[c] / cluster_count[c];
    }

    if (flow_count > 0)
        m_global_pdr = pdr_sum / flow_count;
    else if (m_global_tx > 0)
        m_global_pdr =
            static_cast<double>(m_global_rx) /
            static_cast<double>(m_global_tx);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PdrMetrics: computed flows=" << flows.size()
        << " global_pdr=" << m_global_pdr
        << " lost=" << m_global_lost);
}

double PdrMetrics::GetUavPdr(utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_pdr[uav_id].pdr;
}

double PdrMetrics::GetUavLossRate(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return 1.0 - m_uav_pdr[uav_id].pdr;
}

utils::u64 PdrMetrics::GetUavLostPkts(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0;
    return m_uav_pdr[uav_id].lost;
}

double PdrMetrics::GetClusterPdr(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_pdr[cluster_id];
}

void PdrMetrics::SchedulePeriodicSample(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_sample_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &PdrMetrics::PeriodicSampleCallback, this);
}

void PdrMetrics::PeriodicSampleCallback()
{
    for (uint32_t c = 0; c < 3; ++c) {
        PdrSample s;
        s.time_s     = Simulator::Now().GetSeconds();
        s.cluster_id = c;
        s.pdr        = m_cluster_pdr[c];
        m_samples.push_back(s);
    }
    Simulator::Schedule(
        Seconds(m_sample_interval),
        &PdrMetrics::PeriodicSampleCallback, this);
}

void PdrMetrics::PrintSummary() const
{
    std::cout << "\n=== PDR Metrics ===\n";
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "  Global PDR:  " << m_global_pdr << "\n";
    std::cout << "  Global TX:   " << m_global_tx   << "\n";
    std::cout << "  Global RX:   " << m_global_rx   << "\n";
    std::cout << "  Global Lost: " << m_global_lost  << "\n";
    for (uint32_t c = 0; c < 3; ++c)
        std::cout << "  C" << c
            << " PDR=" << m_cluster_pdr[c] << "\n";
}

void PdrMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) return;
    f << "uav_id,cluster_id,pdr,tx,rx,lost\n";
    for (uint32_t i = 0; i < 18; ++i) {
        f << i << "," << (i/6) << ","
          << m_uav_pdr[i].pdr  << ","
          << m_uav_pdr[i].tx   << ","
          << m_uav_pdr[i].rx   << ","
          << m_uav_pdr[i].lost << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PdrMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
