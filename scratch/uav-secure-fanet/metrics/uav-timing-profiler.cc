/**
 * metrics/uav-timing-profiler.cc
 */

#include "metrics/uav-timing-profiler.h"

#include "ns3/simulator.h"
#include "ns3/log.h"

#include <iostream>
#include <iomanip>
#include <numeric>
#include <algorithm>
#include <sys/stat.h>

NS_LOG_COMPONENT_DEFINE("UavTimingProfiler");

using namespace ns3;

namespace uav {
namespace metrics {

void TimingProfiler::Reset()
{
    m_crypto.clear();
    m_events.clear();
    m_packets.clear();
    m_pending.clear();
}

// ---------------------------------------------------------------------------
// RecordCrypto
// ---------------------------------------------------------------------------
void TimingProfiler::RecordCrypto(
    const std::string& operation,
    utils::u32         node_id,
    utils::u32         cluster_id,
    double             wall_us,
    uint32_t           data_bytes)
{
    CryptoTimingRecord r;
    r.operation  = operation;
    r.node_id    = node_id;
    r.cluster_id = cluster_id;
    r.sim_time_s =
        Simulator::Now().GetSeconds();
    r.wall_us    = wall_us;
    r.data_bytes = data_bytes;
    m_crypto.push_back(r);
}

// ---------------------------------------------------------------------------
// RecordEventStart
// ---------------------------------------------------------------------------
void TimingProfiler::RecordEventStart(
    const std::string& event_type,
    utils::u32         uav_id,
    utils::u32         cluster_id)
{
    std::string key = event_type + "_"
        + std::to_string(uav_id);
    PendingEvent pe;
    pe.event_type = event_type;
    pe.cluster_id = cluster_id;
    pe.trigger_s  =
        Simulator::Now().GetSeconds();
    m_pending[key] = pe;
}

// ---------------------------------------------------------------------------
// RecordEventComplete
// ---------------------------------------------------------------------------
void TimingProfiler::RecordEventComplete(
    const std::string& event_type,
    utils::u32         uav_id,
    const std::string& details)
{
    std::string key = event_type + "_"
        + std::to_string(uav_id);
    double now = Simulator::Now().GetSeconds();

    NetworkEventRecord r;
    r.event_type = event_type;
    r.uav_id     = uav_id;
    r.complete_s = now;
    r.details    = details;

    auto it = m_pending.find(key);
    if (it != m_pending.end()) {
        r.cluster_id = it->second.cluster_id;
        r.trigger_s  = it->second.trigger_s;
        r.latency_ms =
            (now - it->second.trigger_s) * 1000.0;
        m_pending.erase(it);
    } else {
        r.trigger_s  = now;
        r.latency_ms = 0.0;
    }
    m_events.push_back(r);
}

// ---------------------------------------------------------------------------
// RecordNetworkEvent (direct)
// ---------------------------------------------------------------------------
void TimingProfiler::RecordNetworkEvent(
    const NetworkEventRecord& r)
{
    m_events.push_back(r);
}

// ---------------------------------------------------------------------------
// RecordPacketSend
// ---------------------------------------------------------------------------
void TimingProfiler::RecordPacketSend(
    const std::string& pkt_type,
    utils::u32         src_id,
    utils::u32         dst_id,
    uint32_t           size_bytes)
{
    PacketTimingRecord r;
    r.pkt_type   = pkt_type;
    r.src_id     = src_id;
    r.dst_id     = dst_id;
    r.send_s     = Simulator::Now().GetSeconds();
    r.size_bytes = size_bytes;
    r.recv_s     = 0.0;
    r.delay_ms   = 0.0;
    m_packets.push_back(r);
}

// ---------------------------------------------------------------------------
// RecordPacketRecv
// ---------------------------------------------------------------------------
void TimingProfiler::RecordPacketRecv(
    const std::string& pkt_type,
    utils::u32         src_id,
    utils::u32         dst_id)
{
    double now = Simulator::Now().GetSeconds();
    // Find matching send record
    for (auto it = m_packets.rbegin();
         it != m_packets.rend(); ++it) {
        if (it->pkt_type == pkt_type
            && it->src_id == src_id
            && it->dst_id == dst_id
            && it->recv_s == 0.0) {
            it->recv_s   = now;
            it->delay_ms =
                (now - it->send_s) * 1000.0;
            return;
        }
    }
    // No matching send — record recv only
    PacketTimingRecord r;
    r.pkt_type = pkt_type;
    r.src_id   = src_id;
    r.dst_id   = dst_id;
    r.recv_s   = now;
    r.send_s   = now;
    r.delay_ms = 0.0;
    m_packets.push_back(r);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
double TimingProfiler::GetAvgCryptoTime(
    const std::string& op) const
{
    std::vector<double> vals;
    for (const auto& r : m_crypto)
        if (r.operation == op)
            vals.push_back(r.wall_us);
    if (vals.empty()) return 0.0;
    return std::accumulate(
        vals.begin(), vals.end(), 0.0)
        / vals.size();
}

double TimingProfiler::GetAvgEventLatency(
    const std::string& event_type) const
{
    std::vector<double> vals;
    for (const auto& r : m_events)
        if (r.event_type == event_type)
            vals.push_back(r.latency_ms);
    if (vals.empty()) return 0.0;
    return std::accumulate(
        vals.begin(), vals.end(), 0.0)
        / vals.size();
}

// ---------------------------------------------------------------------------
// CSV Export
// ---------------------------------------------------------------------------
void TimingProfiler::ExportCryptoTimingCsv(
    const std::string& path) const
{
    std::ofstream f(path);
    if (!f.is_open()) return;
    f << "sim_time_s,operation,node_id,"
         "cluster_id,wall_us,data_bytes\n";
    for (const auto& r : m_crypto) {
        f << r.sim_time_s << ","
          << r.operation  << ","
          << r.node_id    << ","
          << r.cluster_id << ","
          << r.wall_us    << ","
          << r.data_bytes << "\n";
    }
    f.close();
}

void TimingProfiler::ExportEventProcessingCsv(
    const std::string& path) const
{
    std::ofstream f(path);
    if (!f.is_open()) return;
    f << "trigger_s,complete_s,event_type,"
         "uav_id,cluster_id,latency_ms,details\n";
    for (const auto& r : m_events) {
        f << r.trigger_s  << ","
          << r.complete_s << ","
          << r.event_type << ","
          << r.uav_id     << ","
          << r.cluster_id << ","
          << r.latency_ms << ","
          << r.details    << "\n";
    }
    f.close();
}

void TimingProfiler::ExportPacketDelayCsv(
    const std::string& path) const
{
    std::ofstream f(path);
    if (!f.is_open()) return;
    f << "send_s,recv_s,pkt_type,src_id,"
         "dst_id,delay_ms,size_bytes\n";
    for (const auto& r : m_packets) {
        f << r.send_s     << ","
          << r.recv_s     << ","
          << r.pkt_type   << ","
          << r.src_id     << ","
          << r.dst_id     << ","
          << r.delay_ms   << ","
          << r.size_bytes << "\n";
    }
    f.close();
}

void TimingProfiler::ExportAllCsv(
    const std::string& output_dir) const
{
    mkdir(output_dir.c_str(), 0755);
    ExportCryptoTimingCsv(
        output_dir + "/crypto_timing.csv");
    ExportEventProcessingCsv(
        output_dir + "/event_processing.csv");
    ExportPacketDelayCsv(
        output_dir + "/packet_delay.csv");
    NS_LOG_UNCOND("[Profiler] CSV exported to: "
        << output_dir);
}

// ---------------------------------------------------------------------------
// PrintSummary
// ---------------------------------------------------------------------------
void TimingProfiler::PrintSummary() const
{
    std::cout << "\n=== Timing Profiler Summary ===\n";
    std::cout << "  Crypto records:  "
              << m_crypto.size() << "\n";
    std::cout << "  Event records:   "
              << m_events.size() << "\n";
    std::cout << "  Packet records:  "
              << m_packets.size() << "\n";

    // Crypto summary by operation
    std::map<std::string,
             std::vector<double>> ops;
    for (const auto& r : m_crypto)
        ops[r.operation].push_back(r.wall_us);

    if (!ops.empty()) {
        std::cout << "\n  Crypto timing (us):\n";
        for (const auto& [op, vals] : ops) {
            double avg = std::accumulate(
                vals.begin(), vals.end(), 0.0)
                / vals.size();
            double mx = *std::max_element(
                vals.begin(), vals.end());
            std::cout << "    " << op
                << ": avg=" << std::fixed
                << std::setprecision(2) << avg
                << " max=" << mx
                << " n=" << vals.size() << "\n";
        }
    }

    // Event latency summary
    std::map<std::string,
             std::vector<double>> evts;
    for (const auto& r : m_events)
        evts[r.event_type].push_back(
            r.latency_ms);

    if (!evts.empty()) {
        std::cout << "\n  Event latency (ms):\n";
        for (const auto& [et, vals] : evts) {
            double avg = std::accumulate(
                vals.begin(), vals.end(), 0.0)
                / vals.size();
            std::cout << "    " << et
                << ": avg=" << std::fixed
                << std::setprecision(3) << avg
                << " n=" << vals.size() << "\n";
        }
    }
}

} // namespace metrics
} // namespace uav
