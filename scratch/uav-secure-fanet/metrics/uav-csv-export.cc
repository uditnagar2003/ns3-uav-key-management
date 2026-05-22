/**
 * metrics/uav-csv-export.cc
 * Module 59 — CSV Export Manager
 */

#include "metrics/uav-csv-export.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <fstream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavCsvExport");

using namespace ns3;

namespace uav {
namespace metrics {

CsvExportManager::CsvExportManager(
    const routing::TopologyResult* topo,
    const std::string&             output_dir,
    ThroughputMetrics*             tput,
    DelayMetrics*                  delay,
    PdrMetrics*                    pdr,
    RoutingOverheadMetrics*        overhead,
    RekeyLatencyMetrics*           rekey_lat,
    SinrMetrics*                   sinr,
    routing::FlowMonitorManager*   flow_mgr)
    : m_topo(topo)
    , m_output_dir(output_dir)
    , m_tput(tput)
    , m_delay(delay)
    , m_pdr(pdr)
    , m_overhead(overhead)
    , m_rekey_lat(rekey_lat)
    , m_sinr(sinr)
    , m_flow_mgr(flow_mgr)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: constructed"
        " output=" << output_dir);
}

void CsvExportManager::Initialize(double interval_s)
{
    m_interval_s = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &CsvExportManager::PeriodicExportCallback,
        this);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: periodic export every "
        << interval_s << "s");
}

void CsvExportManager::PeriodicExportCallback()
{
    ++m_export_count;
    // Lightweight periodic: just SINR (changes every second)
    if (m_sinr) m_sinr->Compute();

    Simulator::Schedule(
        Seconds(m_interval_s),
        &CsvExportManager::PeriodicExportCallback,
        this);
}

void CsvExportManager::ExportAll(double sim_duration_s)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: ExportAll t="
        << sim_duration_s << "s");

    if (m_tput)
        m_tput->WriteCsv(Path("throughput.csv"));
    if (m_delay)
        m_delay->WriteCsv(Path("delay.csv"));
    if (m_pdr)
        m_pdr->WriteCsv(Path("pdr.csv"));
    if (m_overhead)
        m_overhead->WriteCsv(Path("routing_overhead.csv"));
    if (m_rekey_lat)
        m_rekey_lat->WriteCsv(Path("rekey_latency.csv"));
    if (m_sinr)
        m_sinr->WriteCsv(Path("sinr.csv"));

    ExportGlobal(sim_duration_s);
    ExportPerCluster();
    ExportPerUav();
    ExportFlowMonitor();

    m_total_exports += 9;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: exported 9 files");
}

void CsvExportManager::ExportGlobal(
    double sim_duration_s)
{
    std::ofstream f(Path("metrics_global.csv"));
    if (!f.is_open()) return;

    f << "metric,value\n";
    f << "sim_duration_s," << sim_duration_s << "\n";
    f << "global_throughput_kbps,"
      << (m_tput ? m_tput->GetGlobalThroughput() : 0.0)
      << "\n";
    f << "global_pdr,"
      << (m_pdr ? m_pdr->GetGlobalPdr() : 0.0) << "\n";
    f << "global_avg_delay_ms,"
      << (m_delay ? m_delay->GetGlobalAvgDelay() : 0.0)
      << "\n";
    f << "global_jitter_ms,"
      << (m_delay ? m_delay->GetGlobalJitter() : 0.0)
      << "\n";
    f << "total_tx,"
      << (m_pdr ? m_pdr->GetGlobalTx() : 0ULL) << "\n";
    f << "total_rx,"
      << (m_pdr ? m_pdr->GetGlobalRx() : 0ULL) << "\n";
    f << "total_lost,"
      << (m_pdr ? m_pdr->GetGlobalLost() : 0ULL) << "\n";
    f << "routing_overhead_ratio,"
      << (m_overhead ? m_overhead->GetOverheadRatio() : 0.0)
      << "\n";
    f << "ctrl_bytes_per_sec,"
      << (m_overhead ? m_overhead->GetCtrlBytesPerSec() : 0.0)
      << "\n";
    f << "avg_rekey_latency_ms,"
      << (m_rekey_lat ? m_rekey_lat->GetAvgLatency() : 0.0)
      << "\n";
    f << "total_rekeys,"
      << (m_rekey_lat ? m_rekey_lat->GetTotalRekeys() : 0ULL)
      << "\n";
    f << "global_avg_sinr_db,"
      << (m_sinr ? m_sinr->GetGlobalAvgSinr() : 0.0) << "\n";
    f << "global_min_sinr_db,"
      << (m_sinr ? m_sinr->GetGlobalMinSinr() : 0.0) << "\n";
    f << "jammed_uav_count,"
      << (m_sinr ? m_sinr->GetJammedCount() : 0U) << "\n";

    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: wrote metrics_global.csv");
}

void CsvExportManager::ExportPerCluster()
{
    std::ofstream f(Path("metrics_per_cluster.csv"));
    if (!f.is_open()) return;

    f << "cluster_id,throughput_kbps,pdr,"
         "avg_delay_ms,jitter_ms,"
         "avg_sinr_db,jammed_count\n";

    for (uint32_t c = 0; c < 3; ++c) {
        f << c << ","
          << (m_tput    ? m_tput->GetClusterThroughput(c)  : 0.0) << ","
          << (m_pdr     ? m_pdr->GetClusterPdr(c)          : 0.0) << ","
          << (m_delay   ? m_delay->GetClusterAvgDelay(c)   : 0.0) << ","
          << (m_delay   ? m_delay->GetClusterJitter(c)     : 0.0) << ","
          << (m_sinr    ? m_sinr->GetClusterAvgSinr(c)     : 0.0) << ","
          << (m_sinr    ? m_sinr->GetClusterJammedCount(c) : 0U)  << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: wrote metrics_per_cluster.csv");
}

void CsvExportManager::ExportPerUav()
{
    std::ofstream f(Path("metrics_per_uav.csv"));
    if (!f.is_open()) return;

    f << "uav_id,cluster_id,throughput_kbps,"
         "pdr,avg_delay_ms,sinr_db,"
         "jammed,drop_prob\n";

    for (uint32_t i = 0; i < 18; ++i) {
        f << i << "," << (i/6) << ","
          << (m_tput  ? m_tput->GetUavThroughput(i)  : 0.0) << ","
          << (m_pdr   ? m_pdr->GetUavPdr(i)          : 0.0) << ","
          << (m_delay ? m_delay->GetUavAvgDelay(i)   : 0.0) << ","
          << (m_sinr  ? m_sinr->GetUavSinr(i)        : 0.0) << ","
          << (m_sinr  ? m_sinr->IsUavJammed(i)       : false) << ","
          << (m_sinr  ? m_sinr->GetUavDropProb(i)    : 0.0) << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: wrote metrics_per_uav.csv");
}

void CsvExportManager::ExportFlowMonitor()
{
    if (!m_flow_mgr) return;
    std::string xml = m_output_dir + "/flowmonitor.xml";
    m_flow_mgr->WriteXml(xml);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "CsvExportManager: wrote flowmonitor.xml");
}

} // namespace metrics
} // namespace uav
