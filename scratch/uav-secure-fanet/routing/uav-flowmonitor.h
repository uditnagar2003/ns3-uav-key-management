/**
 * routing/uav-flowmonitor.h
 *
 * FlowMonitor Integration Manager
 *
 * Installs and queries NS-3 FlowMonitor to collect:
 *   - Throughput (per flow, per cluster, global)
 *   - Packet Delivery Ratio (PDR)
 *   - End-to-end delay
 *   - Packet loss
 *   - Routing overhead
 *   - Rekey latency
 *   - Handover latency
 *
 * FLOWMONITOR METRICS (per project spec):
 *   - throughput
 *   - PDR
 *   - end-to-end delay
 *   - hop delay
 *   - routing overhead
 *   - rekey latency
 *   - handover latency
 *   - packet loss
 *   - queue drops
 *   - SINR degradation
 *   - control overhead
 *
 * OUTPUT:
 *   - FlowMonitor XML file
 *   - Per-flow CSV
 *   - Per-cluster summary
 */

#ifndef UAV_FLOWMONITOR_H
#define UAV_FLOWMONITOR_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>

namespace uav {
namespace routing {

// ===========================================================================
// FlowMetrics — metrics for a single flow
// ===========================================================================
struct FlowMetrics {
    utils::u32  flow_id         = 0;
    utils::u32  cluster_id      = 0;
    utils::u32  src_uav         = 0;
    std::string src_addr;
    std::string dst_addr;
    utils::u16  src_port        = 0;
    utils::u16  dst_port        = 0;

    // Core metrics
    double      throughput_kbps = 0.0;
    double      pdr             = 0.0;   // 0.0-1.0
    double      avg_delay_ms    = 0.0;
    double      min_delay_ms    = 0.0;
    double      max_delay_ms    = 0.0;
    double      jitter_ms       = 0.0;

    // Packet counts
    utils::u64  tx_packets      = 0;
    utils::u64  rx_packets      = 0;
    utils::u64  lost_packets    = 0;
    utils::u64  tx_bytes        = 0;
    utils::u64  rx_bytes        = 0;

    // Timing
    double      flow_duration_s = 0.0;
    double      first_tx_s      = 0.0;
    double      last_rx_s       = 0.0;
};

// ===========================================================================
// ClusterMetrics — aggregated per-cluster metrics
// ===========================================================================
struct ClusterMetrics {
    utils::u32  cluster_id         = 0;
    utils::u32  active_flows       = 0;
    double      total_throughput   = 0.0;  // kbps
    double      avg_pdr            = 0.0;
    double      avg_delay_ms       = 0.0;
    utils::u64  total_tx           = 0;
    utils::u64  total_rx           = 0;
    utils::u64  total_lost         = 0;
};

// ===========================================================================
// GlobalMetrics — simulation-wide aggregation
// ===========================================================================
struct GlobalMetrics {
    utils::u32  total_flows        = 0;
    double      total_throughput   = 0.0;  // kbps
    double      avg_pdr            = 0.0;
    double      avg_delay_ms       = 0.0;
    utils::u64  total_tx           = 0;
    utils::u64  total_rx           = 0;
    utils::u64  total_lost         = 0;
    double      routing_overhead   = 0.0;  // bytes/s
    double      rekey_latency_ms   = 0.0;
    double      handover_latency_ms= 0.0;
    double      sim_duration_s     = 0.0;
};

// ===========================================================================
// FlowMonitorManager
// ===========================================================================
class FlowMonitorManager {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit FlowMonitorManager(const TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Installation
    // -----------------------------------------------------------------------

    /// Install FlowMonitor on all nodes
    void Install();

    /// Install on specific node container
    void InstallOn(const ns3::NodeContainer& nodes);

    // -----------------------------------------------------------------------
    // Metrics collection (call after Simulator::Run)
    // -----------------------------------------------------------------------

    /// Collect and compute all metrics
    void CollectMetrics(double sim_duration_s);

    /// Get per-flow metrics
    const std::vector<FlowMetrics>& GetFlowMetrics() const {
        return m_flow_metrics;
    }

    /// Get per-cluster metrics
    ClusterMetrics GetClusterMetrics(utils::u32 cluster) const;

    /// Get global metrics
    GlobalMetrics GetGlobalMetrics() const;

    // -----------------------------------------------------------------------
    // Security event latency tracking
    // (called by application layer modules)
    // -----------------------------------------------------------------------

    /// Record a rekey event start time
    void RecordRekeyStart(utils::u32 cluster,
                          double time_s);

    /// Record a rekey event completion
    void RecordRekeyComplete(utils::u32 cluster,
                              double time_s);

    /// Record handover start
    void RecordHandoverStart(utils::u32 uav_id,
                              double time_s);

    /// Record handover completion
    void RecordHandoverComplete(utils::u32 uav_id,
                                 double time_s);

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------

    /// Write FlowMonitor XML
    void WriteXml(const std::string& filename);

    /// Write per-flow CSV
    void WriteCsv(const std::string& filename);

    /// Write per-cluster CSV
    void WriteClusterCsv(const std::string& filename);

    /// Print summary to stdout
    void PrintSummary() const;

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    ns3::Ptr<ns3::FlowMonitor> GetFlowMonitor() const {
        return m_monitor;
    }

    bool IsInstalled() const { return m_installed; }

private:
    const TopologyResult&           m_topo;
    ns3::FlowMonitorHelper          m_helper;
    ns3::Ptr<ns3::FlowMonitor>      m_monitor;
    ns3::Ptr<ns3::FlowClassifier>   m_classifier;
    bool                            m_installed = false;

    std::vector<FlowMetrics>        m_flow_metrics;
    GlobalMetrics                   m_global;

    // Security event timing
    struct EventRecord {
        double start_s = 0.0;
        double end_s   = 0.0;
        bool   complete = false;
    };
    std::unordered_map<utils::u32, EventRecord> m_rekey_events;
    std::unordered_map<utils::u32, EventRecord> m_handover_events;

    // Helper: compute metrics from FlowMonitor stats
    FlowMetrics ComputeFlowMetrics(
        utils::u32 flow_id,
        const ns3::FlowMonitor::FlowStats& stats,
        double sim_duration_s) const;

    // Helper: determine cluster from flow src address
    utils::u32 GetClusterFromAddr(
        const ns3::Ipv4Address& addr) const;
};

} // namespace routing
} // namespace uav

#endif // UAV_FLOWMONITOR_H
