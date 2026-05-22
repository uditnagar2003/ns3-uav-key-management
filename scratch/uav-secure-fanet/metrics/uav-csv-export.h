/**
 * metrics/uav-csv-export.h
 * Module 59 — CSV Export Manager
 *
 * Consolidates all metric CSV exports:
 *   - throughput.csv
 *   - delay.csv
 *   - pdr.csv
 *   - routing_overhead.csv
 *   - rekey_latency.csv
 *   - sinr.csv
 *   - metrics_global.csv
 *   - metrics_per_cluster.csv
 *   - metrics_per_uav.csv
 *
 * Exports on 1s interval (per project spec)
 * and final export at simulation end.
 */

#ifndef UAV_CSV_EXPORT_H
#define UAV_CSV_EXPORT_H

#include "metrics/uav-throughput-metrics.h"
#include "metrics/uav-delay-metrics.h"
#include "metrics/uav-pdr-metrics.h"
#include "metrics/uav-routing-overhead.h"
#include "metrics/uav-rekey-latency.h"
#include "metrics/uav-sinr-metrics.h"
#include "routing/uav-flowmonitor.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <string>

namespace uav {
namespace metrics {

class CsvExportManager {
public:
    CsvExportManager(
        const routing::TopologyResult* topo,
        const std::string&             output_dir,
        ThroughputMetrics*             tput,
        DelayMetrics*                  delay,
        PdrMetrics*                    pdr,
        RoutingOverheadMetrics*        overhead,
        RekeyLatencyMetrics*           rekey_lat,
        SinrMetrics*                   sinr,
        routing::FlowMonitorManager*   flow_mgr);

    /**
     * Initialize — schedule periodic exports every interval_s.
     * Per project spec: 1 second interval.
     */
    void Initialize(double interval_s = 1.0);

    /**
     * ExportAll — write all CSV files immediately.
     * Call after Simulator::Run() for final export.
     */
    void ExportAll(double sim_duration_s);

    /**
     * ExportGlobal — write metrics_global.csv
     * Format: metric,value
     */
    void ExportGlobal(double sim_duration_s);

    /**
     * ExportPerCluster — write metrics_per_cluster.csv
     * Format: cluster_id,throughput,pdr,avg_delay,jammed
     */
    void ExportPerCluster();

    /**
     * ExportPerUav — write metrics_per_uav.csv
     * Format: uav_id,cluster_id,throughput,pdr,delay,sinr
     */
    void ExportPerUav();

    /**
     * ExportFlowMonitor — write FlowMonitor XML
     */
    void ExportFlowMonitor();

    utils::u64 GetTotalExports() const {
        return m_total_exports;
    }

private:
    const routing::TopologyResult* m_topo;
    std::string                    m_output_dir;
    ThroughputMetrics*             m_tput;
    DelayMetrics*                  m_delay;
    PdrMetrics*                    m_pdr;
    RoutingOverheadMetrics*        m_overhead;
    RekeyLatencyMetrics*           m_rekey_lat;
    SinrMetrics*                   m_sinr;
    routing::FlowMonitorManager*   m_flow_mgr;

    double     m_interval_s    = 1.0;
    utils::u64 m_total_exports = 0;
    uint32_t   m_export_count  = 0;

    void PeriodicExportCallback();

    std::string Path(const std::string& filename) const {
        return m_output_dir + "/" + filename;
    }
};

} // namespace metrics
} // namespace uav

#endif // UAV_CSV_EXPORT_H
