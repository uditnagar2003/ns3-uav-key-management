/**
 * routing/uav-flowmonitor.cc
 */

#include "uav-flowmonitor.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/ipv4-flow-classifier.h"
#include "ns3/flow-monitor.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cmath>
#include <algorithm>

NS_LOG_COMPONENT_DEFINE("UavFlowMonitor");

using namespace ns3;

namespace uav {
namespace routing {

// ===========================================================================
// Constructor
// ===========================================================================
FlowMonitorManager::FlowMonitorManager(
    const TopologyResult& topo)
    : m_topo(topo)
{
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "FlowMonitorManager: initialized");
}

// ===========================================================================
// Install on all nodes
// ===========================================================================
void FlowMonitorManager::Install() {
    m_monitor = m_helper.InstallAll();
    m_classifier = m_helper.GetClassifier();
    m_installed = true;

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "FlowMonitorManager: installed on all nodes");
}

void FlowMonitorManager::InstallOn(
    const NodeContainer& nodes)
{
    m_monitor = m_helper.Install(nodes);
    m_classifier = m_helper.GetClassifier();
    m_installed = true;
}

// ===========================================================================
// Compute FlowMetrics from NS-3 FlowStats
// ===========================================================================
FlowMetrics FlowMonitorManager::ComputeFlowMetrics(
    utils::u32 flow_id,
    const FlowMonitor::FlowStats& stats,
    double sim_duration_s) const
{
    FlowMetrics fm;
    fm.flow_id    = flow_id;
    fm.tx_packets = stats.txPackets;
    fm.rx_packets = stats.rxPackets;
    fm.tx_bytes   = stats.txBytes;
    fm.rx_bytes   = stats.rxBytes;
    fm.lost_packets = stats.lostPackets;

    // PDR
    fm.pdr = (stats.txPackets > 0)
        ? static_cast<double>(stats.rxPackets) /
          static_cast<double>(stats.txPackets)
        : 0.0;

    // Throughput
    double duration = sim_duration_s;
    if (stats.timeLastRxPacket > stats.timeFirstTxPacket) {
        duration = (stats.timeLastRxPacket -
                    stats.timeFirstTxPacket).GetSeconds();
    }
    fm.flow_duration_s = duration;
    fm.throughput_kbps = (duration > 0)
        ? (stats.rxBytes * 8.0) / (duration * 1000.0)
        : 0.0;

    // Delay
    if (stats.rxPackets > 0) {
        double total_delay_ns =
            stats.delaySum.GetNanoSeconds();
        fm.avg_delay_ms =
            (total_delay_ns / stats.rxPackets) / 1e6;

        // Jitter
        if (stats.rxPackets > 1) {
            double total_jitter_ns =
                stats.jitterSum.GetNanoSeconds();
            fm.jitter_ms =
                (total_jitter_ns /
                 (stats.rxPackets - 1)) / 1e6;
        }
    }

    fm.first_tx_s =
        stats.timeFirstTxPacket.GetSeconds();
    fm.last_rx_s  =
        stats.timeLastRxPacket.GetSeconds();

    return fm;
}

// ===========================================================================
// Get cluster from WiFi address
// WiFi addresses: 10.1.1.1 = UAV0, 10.1.1.2 = UAV1, ...
// UAV 0-5  = Cluster 0
// UAV 6-11 = Cluster 1
// UAV 12-17= Cluster 2
// ===========================================================================
utils::u32 FlowMonitorManager::GetClusterFromAddr(
    const Ipv4Address& addr) const
{
    for (utils::u32 i = 0; i < 18; ++i) {
        if (m_topo.wifi_interfaces.GetAddress(i) == addr) {
            return i / 6;
        }
    }
    return 0;
}

// ===========================================================================
// Collect metrics after simulation
// ===========================================================================
void FlowMonitorManager::CollectMetrics(
    double sim_duration_s)
{
    if (!m_installed || !m_monitor) {
        UAV_LOG_WARN(uav::log::channels::ROUTING,
            "FlowMonitorManager: not installed");
        return;
    }

    m_monitor->CheckForLostPackets();
    m_flow_metrics.clear();

    auto flow_stats = m_monitor->GetFlowStats();
    auto ipv4_classifier =
        DynamicCast<Ipv4FlowClassifier>(m_classifier);

    m_global = GlobalMetrics{};
    m_global.sim_duration_s = sim_duration_s;
    m_global.total_flows =
        static_cast<utils::u32>(flow_stats.size());

    for (const auto& [fid, stats] : flow_stats) {
        auto fm = ComputeFlowMetrics(
            static_cast<utils::u32>(fid),
            stats, sim_duration_s);

        // Get flow tuple for addresses
        if (ipv4_classifier) {
            Ipv4FlowClassifier::FiveTuple ft =
                ipv4_classifier->FindFlow(fid);
            std::ostringstream src_oss, dst_oss;
            ft.sourceAddress.Print(src_oss);
            ft.destinationAddress.Print(dst_oss);
            fm.src_addr  = src_oss.str();
            fm.dst_addr  = dst_oss.str();
            fm.src_port  = ft.sourcePort;
            fm.dst_port  = ft.destinationPort;
            fm.cluster_id = GetClusterFromAddr(
                ft.sourceAddress);
        }

        m_flow_metrics.push_back(fm);

        // Aggregate to global
        m_global.total_tx          += fm.tx_packets;
        m_global.total_rx          += fm.rx_packets;
        m_global.total_lost        += fm.lost_packets;
        m_global.total_throughput  += fm.throughput_kbps;
        m_global.avg_delay_ms      += fm.avg_delay_ms;
    }

    // Compute averages
    if (!m_flow_metrics.empty()) {
        double n = static_cast<double>(
            m_flow_metrics.size());
        m_global.avg_delay_ms /= n;
        m_global.avg_pdr = (m_global.total_tx > 0)
            ? static_cast<double>(m_global.total_rx) /
              static_cast<double>(m_global.total_tx)
            : 0.0;
    }

    // Compute rekey latency
    double rekey_sum = 0.0;
    utils::u32 rekey_count = 0;
    for (const auto& [cid, ev] : m_rekey_events) {
        if (ev.complete) {
            rekey_sum += (ev.end_s - ev.start_s) * 1000.0;
            ++rekey_count;
        }
    }
    m_global.rekey_latency_ms = (rekey_count > 0)
        ? rekey_sum / rekey_count : 0.0;

    // Compute handover latency
    double ho_sum = 0.0;
    utils::u32 ho_count = 0;
    for (const auto& [uid, ev] : m_handover_events) {
        if (ev.complete) {
            ho_sum += (ev.end_s - ev.start_s) * 1000.0;
            ++ho_count;
        }
    }
    m_global.handover_latency_ms = (ho_count > 0)
        ? ho_sum / ho_count : 0.0;

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "FlowMonitorManager: collected "
        << m_flow_metrics.size() << " flows"
        << " global_pdr=" << m_global.avg_pdr
        << " total_tp=" << m_global.total_throughput
        << " kbps");
}

// ===========================================================================
// Cluster metrics aggregation
// ===========================================================================
ClusterMetrics FlowMonitorManager::GetClusterMetrics(
    utils::u32 cluster) const
{
    ClusterMetrics cm;
    cm.cluster_id = cluster;

    utils::u32 count = 0;
    for (const auto& fm : m_flow_metrics) {
        if (fm.cluster_id != cluster) continue;
        ++cm.active_flows;
        cm.total_throughput += fm.throughput_kbps;
        cm.avg_pdr          += fm.pdr;
        cm.avg_delay_ms     += fm.avg_delay_ms;
        cm.total_tx         += fm.tx_packets;
        cm.total_rx         += fm.rx_packets;
        cm.total_lost       += fm.lost_packets;
        ++count;
    }

    if (count > 0) {
        cm.avg_pdr      /= count;
        cm.avg_delay_ms /= count;
    }
    return cm;
}

GlobalMetrics FlowMonitorManager::GetGlobalMetrics() const {
    return m_global;
}

// ===========================================================================
// Security event tracking
// ===========================================================================
void FlowMonitorManager::RecordRekeyStart(
    utils::u32 cluster, double time_s)
{
    m_rekey_events[cluster].start_s  = time_s;
    m_rekey_events[cluster].complete = false;
}

void FlowMonitorManager::RecordRekeyComplete(
    utils::u32 cluster, double time_s)
{
    m_rekey_events[cluster].end_s    = time_s;
    m_rekey_events[cluster].complete = true;
}

void FlowMonitorManager::RecordHandoverStart(
    utils::u32 uav_id, double time_s)
{
    m_handover_events[uav_id].start_s  = time_s;
    m_handover_events[uav_id].complete = false;
}

void FlowMonitorManager::RecordHandoverComplete(
    utils::u32 uav_id, double time_s)
{
    m_handover_events[uav_id].end_s    = time_s;
    m_handover_events[uav_id].complete = true;
}

// ===========================================================================
// Output: XML
// ===========================================================================
void FlowMonitorManager::WriteXml(
    const std::string& filename)
{
    if (!m_monitor) return;
    m_monitor->SerializeToXmlFile(filename, true, true);
    NS_LOG_UNCOND("FlowMonitor XML: " << filename);
}

// ===========================================================================
// Output: CSV
// ===========================================================================
void FlowMonitorManager::WriteCsv(
    const std::string& filename)
{
    std::ofstream f(filename);
    if (!f.is_open()) return;

    f << "flow_id,cluster_id,src,dst,"
      << "throughput_kbps,pdr,avg_delay_ms,"
      << "tx_pkts,rx_pkts,lost_pkts\n";

    for (const auto& fm : m_flow_metrics) {
        f << fm.flow_id << ","
          << fm.cluster_id << ","
          << fm.src_addr << ","
          << fm.dst_addr << ","
          << std::fixed << std::setprecision(3)
          << fm.throughput_kbps << ","
          << fm.pdr << ","
          << fm.avg_delay_ms << ","
          << fm.tx_packets << ","
          << fm.rx_packets << ","
          << fm.lost_packets << "\n";
    }

    NS_LOG_UNCOND("FlowMonitor CSV: " << filename);
}

// ===========================================================================
// Output: Cluster CSV
// ===========================================================================
void FlowMonitorManager::WriteClusterCsv(
    const std::string& filename)
{
    std::ofstream f(filename);
    if (!f.is_open()) return;

    f << "cluster_id,flows,throughput_kbps,"
      << "avg_pdr,avg_delay_ms,"
      << "tx_pkts,rx_pkts,lost_pkts\n";

    for (utils::u32 c = 0; c < 3; ++c) {
        auto cm = GetClusterMetrics(c);
        f << c << ","
          << cm.active_flows << ","
          << std::fixed << std::setprecision(3)
          << cm.total_throughput << ","
          << cm.avg_pdr << ","
          << cm.avg_delay_ms << ","
          << cm.total_tx << ","
          << cm.total_rx << ","
          << cm.total_lost << "\n";
    }

    NS_LOG_UNCOND("Cluster CSV: " << filename);
}

// ===========================================================================
// Print summary
// ===========================================================================
void FlowMonitorManager::PrintSummary() const {
    std::cout << "\n=== FlowMonitor Summary ===\n";
    std::cout << "  Total flows:      "
              << m_global.total_flows << "\n";
    std::cout << "  Total throughput: "
              << std::fixed << std::setprecision(2)
              << m_global.total_throughput
              << " kbps\n";
    std::cout << "  Global PDR:       "
              << m_global.avg_pdr * 100.0
              << " %\n";
    std::cout << "  Avg delay:        "
              << m_global.avg_delay_ms << " ms\n";
    std::cout << "  TX packets:       "
              << m_global.total_tx << "\n";
    std::cout << "  RX packets:       "
              << m_global.total_rx << "\n";
    std::cout << "  Lost packets:     "
              << m_global.total_lost << "\n";
    std::cout << "  Rekey latency:    "
              << m_global.rekey_latency_ms << " ms\n";
    std::cout << "  Handover latency: "
              << m_global.handover_latency_ms << " ms\n";

    std::cout << "\n  Per-cluster:\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        auto cm = GetClusterMetrics(c);
        std::cout << "    Cluster " << c
            << ": flows=" << cm.active_flows
            << " tp=" << cm.total_throughput
            << "kbps pdr=" << cm.avg_pdr * 100.0
            << "% delay=" << cm.avg_delay_ms
            << "ms\n";
    }
}

} // namespace routing
} // namespace uav
