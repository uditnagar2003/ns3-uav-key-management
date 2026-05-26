/**
 * metrics/uav-metrics-framework.cc
 *
 * Implementation of MetricsFramework — all 5 metric categories.
 * Topology: 3 clusters × 6 UAVs = 18 UAVs (unchanged).
 */

#include "metrics/uav-metrics-framework.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <numeric>
#include <algorithm>

NS_LOG_COMPONENT_DEFINE("UavMetricsFramework");

using namespace ns3;

namespace uav {
namespace metrics {

// ============================================================================
// Construction
// ============================================================================
MetricsFramework::MetricsFramework(
    const routing::TopologyResult* topo,
    const std::string& output_dir,
    uint32_t seed)
    : m_topo(topo)
    , m_output_dir(output_dir)
    , m_seed(seed)
{
    NS_LOG_INFO("MetricsFramework: constructed, output=" << output_dir);
}

void MetricsFramework::Initialize(double snapshot_interval_s)
{
    m_snapshot_interval_s = snapshot_interval_s;
    Simulator::Schedule(
        Seconds(snapshot_interval_s),
        &MetricsFramework::PeriodicSnapshot, this);
    NS_LOG_INFO("MetricsFramework: periodic snapshot every "
        << snapshot_interval_s << "s");
}

// ============================================================================
// Periodic snapshot
// ============================================================================
void MetricsFramework::PeriodicSnapshot()
{
    ++m_snapshot_count;
    double t = Simulator::Now().GetSeconds();

    TimeSeriesPoint pt;
    pt.t = t;

    // PDR snapshot
    pt.pdr = m_pkt_global.PDR();

    // Throughput snapshot (rate since last)
    double dur = m_snapshot_interval_s * m_snapshot_count;
    pt.throughput = m_pkt_global.ThroughputKbps(dur);

    // Delay snapshot
    pt.delay_ms = m_delay_global.Avg();

    // SINR snapshot — average of last N samples
    if (!m_sinr_samples.empty()) {
        double sum = 0.0;
        uint32_t cnt = 0;
        for (auto it = m_sinr_samples.rbegin();
             it != m_sinr_samples.rend() && cnt < 18; ++it, ++cnt)
            sum += it->sinr_db;
        pt.sinr_db = cnt ? sum / cnt : 0.0;
    }

    // Rekey count
    pt.rekeys = (uint32_t)m_rekeys.size();

    // Swarm survivability snapshot
    if (!m_swarm_snaps.empty())
        pt.survivability = m_swarm_snaps.back().survivability_ratio;

    // Connectivity
    if (!m_connectivity_samples.empty())
        pt.connectivity = m_connectivity_samples.back();

    // Overhead ratio
    if (!m_overhead_samples.empty()) {
        uint64_t total = 0, ctrl = 0;
        for (const auto& s : m_overhead_samples) {
            total += s.data_bytes + s.ctrl_bytes + s.rekey_bytes
                   + s.header_bytes + s.hmac_bytes + s.mtk_bytes;
            ctrl  += s.ctrl_bytes + s.rekey_bytes
                   + s.header_bytes + s.hmac_bytes + s.mtk_bytes;
        }
        pt.overhead_ratio = total ? (double)ctrl / total : 0.0;
    }

    m_timeseries.push_back(pt);

    Simulator::Schedule(
        Seconds(m_snapshot_interval_s),
        &MetricsFramework::PeriodicSnapshot, this);
}

// ============================================================================
// A — NETWORK METRIC HOOKS
// ============================================================================
void MetricsFramework::RecordTx(uint32_t uav_id,
                                 uint32_t bytes,
                                 bool is_ctrl)
{
    m_pkt_global.tx++;
    m_pkt_global.bytes_tx += bytes;
    if (is_ctrl) m_pkt_global.ctrl_tx++;

    if (uav_id < TOTAL_UAVS) {
        uint32_t c = ClusterId(uav_id);
        m_pkt_uav[uav_id].tx++;
        m_pkt_uav[uav_id].bytes_tx += bytes;
        m_pkt_cluster[c].tx++;
        m_pkt_cluster[c].bytes_tx += bytes;
        if (is_ctrl) {
            m_pkt_uav[uav_id].ctrl_tx++;
            m_pkt_cluster[c].ctrl_tx++;
        }
    }
}

void MetricsFramework::RecordRx(uint32_t uav_id,
                                 uint32_t bytes,
                                 double delay_ms,
                                 bool is_ctrl)
{
    m_pkt_global.rx++;
    m_pkt_global.bytes_rx += bytes;
    m_delay_global.Record(delay_ms);
    if (is_ctrl) m_pkt_global.ctrl_rx++;

    if (uav_id < TOTAL_UAVS) {
        uint32_t c = ClusterId(uav_id);
        m_pkt_uav[uav_id].rx++;
        m_pkt_uav[uav_id].bytes_rx += bytes;
        m_pkt_cluster[c].rx++;
        m_pkt_cluster[c].bytes_rx += bytes;
        m_delay_uav[uav_id].Record(delay_ms);
        m_delay_cluster[c].Record(delay_ms);
        if (is_ctrl) {
            m_pkt_uav[uav_id].ctrl_rx++;
            m_pkt_cluster[c].ctrl_rx++;
        }
    }
}

void MetricsFramework::RecordLoss(uint32_t uav_id, uint32_t bytes)
{
    m_pkt_global.lost++;
    if (uav_id < TOTAL_UAVS) {
        uint32_t c = ClusterId(uav_id);
        m_pkt_uav[uav_id].lost++;
        m_pkt_cluster[c].lost++;
    }
    (void)bytes;
}

void MetricsFramework::RecordRoutingUpdate(uint32_t active_routes,
                                            uint32_t broken_routes)
{
    RoutingStabilitySample s;
    s.time_s         = Simulator::Now().GetSeconds();
    s.active_routes  = active_routes;
    s.broken_routes  = broken_routes;
    s.total_nodes    = TOTAL_UAVS;
    uint32_t total   = active_routes + broken_routes;
    s.stability_idx  = total ? (double)active_routes / total : 1.0;
    m_stability_samples.push_back(s);
}

void MetricsFramework::RecordConnectivitySample(
    uint32_t connected_pairs,
    uint32_t total_possible_pairs)
{
    double r = total_possible_pairs
        ? (double)connected_pairs / total_possible_pairs : 0.0;
    m_connectivity_samples.push_back(r);
}

// ============================================================================
// B — SECURITY HOOKS
// ============================================================================
void MetricsFramework::RecordKeyEstablishment(
    uint32_t uav_id, uint32_t cluster_id,
    double latency_ms, bool success)
{
    KeyEstabRecord r;
    r.time_s     = Simulator::Now().GetSeconds();
    r.uav_id     = uav_id;
    r.cluster_id = cluster_id;
    r.latency_ms = latency_ms;
    r.success    = success;
    m_key_estab.push_back(r);
    NS_LOG_INFO("KeyEstab: uav=" << uav_id
        << " latency=" << latency_ms << "ms ok=" << success);
}

void MetricsFramework::RecordRekey(
    uint32_t cluster_id,
    const std::string& trigger,
    double latency_ms,
    uint32_t tek_version,
    uint32_t members,
    double msg_cost_bytes)
{
    RekeyRecord r;
    r.time_s      = Simulator::Now().GetSeconds();
    r.cluster_id  = cluster_id;
    r.trigger     = trigger;
    r.latency_ms  = latency_ms;
    r.tek_version = tek_version;
    r.members     = members;
    r.msg_cost    = msg_cost_bytes;
    m_rekeys.push_back(r);
}

void MetricsFramework::RecordAuthAttempt(
    uint32_t uav_id, uint32_t cluster_id,
    bool success, const std::string& failure_reason)
{
    AuthRecord r;
    r.time_s        = Simulator::Now().GetSeconds();
    r.uav_id        = uav_id;
    r.cluster_id    = cluster_id;
    r.success       = success;
    r.failure_reason = failure_reason;
    m_auth.push_back(r);
}

void MetricsFramework::RecordSecrecyCheck(
    uint32_t cluster_id, uint32_t tek_version,
    bool forward_ok, bool backward_ok,
    const std::string& event_type)
{
    SecrecyRecord r;
    r.time_s      = Simulator::Now().GetSeconds();
    r.cluster_id  = cluster_id;
    r.tek_version = tek_version;
    r.forward_ok  = forward_ok;
    r.backward_ok = backward_ok;
    r.event_type  = event_type;
    m_secrecy.push_back(r);
}

void MetricsFramework::RecordReplayDetection(
    uint32_t uav_id, uint32_t seq_num,
    bool detected, bool was_actual_replay)
{
    ReplayRecord r;
    r.time_s          = Simulator::Now().GetSeconds();
    r.uav_id          = uav_id;
    r.seq_num         = seq_num;
    r.detected        = detected;
    r.was_replay      = was_actual_replay;
    m_replay.push_back(r);
}

void MetricsFramework::RecordHealingAttempt(
    uint32_t uav_id, uint32_t cluster_id,
    double trigger_time_s, bool recovered,
    const std::string& event_type)
{
    HealingRecord r;
    r.trigger_time_s  = trigger_time_s;
    r.recovery_time_s = Simulator::Now().GetSeconds();
    r.uav_id          = uav_id;
    r.cluster_id      = cluster_id;
    r.recovered       = recovered;
    r.event_type      = event_type;
    r.recovery_latency_ms =
        (r.recovery_time_s - r.trigger_time_s) * 1000.0;
    m_healing.push_back(r);
}

// ============================================================================
// C — OVERHEAD HOOKS
// ============================================================================
void MetricsFramework::RecordPacketOverhead(
    uint32_t cluster_id,
    uint64_t data_bytes,
    uint64_t header_bytes,
    uint64_t hmac_bytes,
    uint64_t mtk_bytes,
    uint64_t ctrl_bytes,
    uint64_t rekey_bytes)
{
    OverheadSample s;
    s.time_s      = Simulator::Now().GetSeconds();
    s.cluster_id  = cluster_id;
    s.data_bytes  = data_bytes;
    s.header_bytes = header_bytes;
    s.hmac_bytes  = hmac_bytes;
    s.mtk_bytes   = mtk_bytes;
    s.ctrl_bytes  = ctrl_bytes;
    s.rekey_bytes = rekey_bytes;
    m_overhead_samples.push_back(s);
}

void MetricsFramework::RecordComputeTiming(
    const std::string& operation,
    uint32_t uav_id,
    double wall_us)
{
    ComputeTimingRecord r;
    r.operation = operation;
    r.uav_id    = uav_id;
    r.wall_us   = wall_us;
    m_compute_timings.push_back(r);
}

// ============================================================================
// D — DENIED ENVIRONMENT HOOKS
// ============================================================================
void MetricsFramework::RecordSinrSample(
    uint32_t uav_id, uint32_t cluster_id,
    double sinr_db, double threshold_db)
{
    MfSinrSample s;
    s.time_s     = Simulator::Now().GetSeconds();
    s.uav_id     = uav_id;
    s.cluster_id = cluster_id;
    s.sinr_db    = sinr_db;
    s.jammed     = (sinr_db < threshold_db);
    // Nakagami-based drop probability approximation
    double snr_linear = std::pow(10.0, sinr_db / 10.0);
    s.drop_prob  = std::exp(-snr_linear / 2.0);
    s.drop_prob  = std::min(1.0, std::max(0.0, s.drop_prob));
    m_sinr_samples.push_back(s);
}

void MetricsFramework::RecordJammerEvent(
    double start_s, double end_s,
    uint32_t affected_uavs, double avg_sinr_db)
{
    JammerEvent e;
    e.start_s       = start_s;
    e.end_s         = end_s;
    e.affected_uavs = affected_uavs;
    e.avg_sinr_db   = avg_sinr_db;
    m_jammer_events.push_back(e);
}

void MetricsFramework::RecordJammerRecovery(
    uint32_t uav_id, double recovery_latency_ms)
{
    m_jammer_recovery_ms[uav_id] = recovery_latency_ms;
}

void MetricsFramework::RecordLinkFailure(
    uint32_t uav_id, uint32_t cluster_id,
    const std::string& cause, bool recovered,
    double duration_ms)
{
    LinkFailureRecord r;
    r.time_s     = Simulator::Now().GetSeconds();
    r.uav_id     = uav_id;
    r.cluster_id = cluster_id;
    r.cause      = cause;
    r.recovered  = recovered;
    r.duration_ms = duration_ms;
    m_link_failures.push_back(r);
}

// ============================================================================
// E — MOBILITY & SWARM HOOKS
// ============================================================================
void MetricsFramework::RecordRouteBreak(
    uint32_t uav_id, uint32_t cluster_id,
    double velocity_mps, bool triggered_rekey)
{
    RouteBreakRecord r;
    r.time_s          = Simulator::Now().GetSeconds();
    r.uav_id          = uav_id;
    r.cluster_id      = cluster_id;
    r.velocity_mps    = velocity_mps;
    r.triggered_rekey = triggered_rekey;
    m_route_breaks.push_back(r);
}

void MetricsFramework::RecordSwarmSnapshot(
    uint32_t active_uavs, uint32_t jammed_uavs,
    uint32_t compromised_uavs, uint32_t disconnected_uavs,
    uint32_t connected_pairs)
{
    SwarmSurvivabilitySnapshot s;
    s.time_s              = Simulator::Now().GetSeconds();
    s.total_uavs          = TOTAL_UAVS;
    s.active_uavs         = active_uavs;
    s.jammed_uavs         = jammed_uavs;
    s.compromised_uavs    = compromised_uavs;
    s.disconnected_uavs   = disconnected_uavs;
    s.survivability_ratio = TOTAL_UAVS
        ? (double)active_uavs / TOTAL_UAVS : 0.0;
    // max pairs = N*(N-1)/2
    uint32_t max_p = TOTAL_UAVS * (TOTAL_UAVS - 1) / 2;
    s.connectivity_ratio  = max_p
        ? (double)connected_pairs / max_p : 0.0;
    m_swarm_snaps.push_back(s);
}

void MetricsFramework::RecordClusterHeadStatus(
    uint32_t cluster_id, uint32_t skdc_node_id,
    uint32_t active_members, bool skdc_reachable,
    double avg_member_dist_m)
{
    ClusterHeadStabilityRecord r;
    r.time_s            = Simulator::Now().GetSeconds();
    r.cluster_id        = cluster_id;
    r.skdc_node_id      = skdc_node_id;
    r.active_members    = active_members;
    r.skdc_reachable    = skdc_reachable;
    r.avg_member_dist_m = avg_member_dist_m;
    m_cluster_head.push_back(r);
}

// ============================================================================
// FINALIZATION — Compute all summaries
// ============================================================================
void MetricsFramework::Finalize(double sim_dur_s, uint32_t run_idx)
{
    m_summary.simulation_duration_s = sim_dur_s;
    m_summary.seed                   = m_seed;
    m_summary.run_index              = run_idx;

    // ---- A: Network ----
    auto& N = m_summary.network;
    N.global_pdr             = m_pkt_global.PDR();
    N.global_throughput_kbps = m_pkt_global.ThroughputKbps(sim_dur_s);
    N.global_avg_delay_ms    = m_delay_global.Avg();
    N.global_jitter_ms       = m_delay_global.Jitter();
    N.global_loss_ratio      = m_pkt_global.LossRatio();
    N.total_route_breaks     = (uint32_t)m_route_breaks.size();

    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
        N.pdr_per_cluster[c]             = m_pkt_cluster[c].PDR();
        N.throughput_per_cluster_kbps[c] =
            m_pkt_cluster[c].ThroughputKbps(sim_dur_s);
        N.delay_per_cluster_ms[c]        = m_delay_cluster[c].Avg();
        N.loss_per_cluster[c]            = m_pkt_cluster[c].LossRatio();
    }
    for (uint32_t u = 0; u < TOTAL_UAVS; ++u) {
        N.pdr_per_uav[u]             = m_pkt_uav[u].PDR();
        N.throughput_per_uav_kbps[u] = m_pkt_uav[u].ThroughputKbps(sim_dur_s);
        N.delay_per_uav_ms[u]        = m_delay_uav[u].Avg();
    }
    if (!m_stability_samples.empty()) {
        double sum = 0;
        for (const auto& s : m_stability_samples) sum += s.stability_idx;
        N.avg_routing_stability = sum / m_stability_samples.size();
    }
    if (!m_connectivity_samples.empty()) {
        double sum = 0;
        for (double v : m_connectivity_samples) sum += v;
        N.avg_connectivity_ratio = sum / m_connectivity_samples.size();
    }

    // ---- B: Security ----
    auto& S = m_summary.security;
    if (!m_key_estab.empty()) {
        double sum = 0, mx = 0;
        for (const auto& r : m_key_estab) {
            sum += r.latency_ms;
            if (r.latency_ms > mx) mx = r.latency_ms;
        }
        S.avg_key_estab_ms   = sum / m_key_estab.size();
        S.max_key_estab_ms   = mx;
        S.total_key_estabs   = (uint32_t)m_key_estab.size();
    }
    if (!m_rekeys.empty()) {
        double sum = 0, mx = 0, cost_sum = 0;
        for (const auto& r : m_rekeys) {
            sum      += r.latency_ms;
            if (r.latency_ms > mx) mx = r.latency_ms;
            cost_sum += r.msg_cost;
            if (r.cluster_id < NUM_CLUSTERS)
                S.rekeys_per_cluster[r.cluster_id]++;
        }
        S.avg_rekey_latency_ms     = sum / m_rekeys.size();
        S.max_rekey_latency_ms     = mx;
        S.total_rekeys             = (uint32_t)m_rekeys.size();
        S.avg_rekey_msg_cost_bytes = cost_sum / m_rekeys.size();
    }
    if (!m_auth.empty()) {
        uint32_t ok = 0;
        for (const auto& r : m_auth) if (r.success) ok++;
        S.auth_attempts     = (uint32_t)m_auth.size();
        S.auth_successes    = ok;
        S.auth_success_rate = (double)ok / m_auth.size();
    }
    if (!m_secrecy.empty()) {
        uint32_t fwd = 0, bwd = 0;
        for (const auto& r : m_secrecy) {
            if (r.forward_ok)  fwd++;
            if (r.backward_ok) bwd++;
        }
        S.secrecy_checks        = (uint32_t)m_secrecy.size();
        S.forward_secrecy_rate  = (double)fwd / m_secrecy.size();
        S.backward_secrecy_rate = (double)bwd / m_secrecy.size();
    }
    if (!m_replay.empty()) {
        uint32_t tp = 0, fp = 0, fn = 0, tn = 0;
        for (const auto& r : m_replay) {
            if (r.was_replay  &&  r.detected) tp++;
            if (!r.was_replay &&  r.detected) fp++;
            if (r.was_replay  && !r.detected) fn++;
            if (!r.was_replay && !r.detected) tn++;
        }
        S.replay_attacks        = tp + fn;
        S.replay_detected       = tp;
        S.replay_detection_rate = (tp + fn) ? (double)tp / (tp + fn) : 0.0;
        S.replay_false_pos_rate = (fp + tn) ? (double)fp / (fp + tn) : 0.0;
    }
    if (!m_healing.empty()) {
        double sum = 0; uint32_t ok = 0;
        for (const auto& r : m_healing) {
            sum += r.recovery_latency_ms;
            if (r.recovered) ok++;
        }
        S.avg_recovery_ms      = sum / m_healing.size();
        S.healing_success_rate = (double)ok / m_healing.size();
        S.healing_events       = (uint32_t)m_healing.size();
    }

    // ---- C: Overhead ----
    auto& OH = m_summary.overhead;
    if (!m_overhead_samples.empty()) {
        uint64_t tot = 0, ctrl = 0, rk = 0, hdr = 0, hmac = 0, mtk = 0;
        for (const auto& s : m_overhead_samples) {
            tot  += s.data_bytes + s.ctrl_bytes + s.rekey_bytes
                  + s.header_bytes + s.hmac_bytes + s.mtk_bytes;
            ctrl += s.ctrl_bytes;
            rk   += s.rekey_bytes;
            hdr  += s.header_bytes;
            hmac += s.hmac_bytes;
            mtk  += s.mtk_bytes;
        }
        uint64_t overhead = ctrl + rk + hdr + hmac + mtk;
        OH.comm_overhead_ratio   = tot ? (double)overhead / tot : 0.0;
        OH.rekey_overhead_ratio  = tot ? (double)rk / tot : 0.0;
        OH.header_overhead_ratio = tot ? (double)hdr / tot : 0.0;
        OH.hmac_overhead_ratio   = tot ? (double)hmac / tot : 0.0;
        OH.ctrl_bytes_per_sec    = sim_dur_s > 0
            ? (double)(ctrl + rk) / sim_dur_s : 0.0;
    }
    if (!m_rekeys.empty()) {
        double cost_sum = 0;
        for (const auto& r : m_rekeys) cost_sum += r.msg_cost;
        OH.rekey_bytes_per_rekey = cost_sum / m_rekeys.size();
    }
    // Storage overhead per UAV:
    //   TEK (32B) + slave key ~512B + replay cache 64×16B = ~1568B
    OH.storage_per_uav_bytes = 32.0 + 512.0 + 64 * 16.0;
    // Compute timings by operation
    std::unordered_map<std::string, std::vector<double>> op_times;
    for (const auto& r : m_compute_timings)
        op_times[r.operation].push_back(r.wall_us);
    auto mean_op = [&](const std::string& op) {
        auto it = op_times.find(op);
        if (it == op_times.end() || it->second.empty()) return 0.0;
        double s = 0;
        for (double v : it->second) s += v;
        return s / it->second.size();
    };
    OH.avg_aes_enc_us      = mean_op("AES_ENC");
    OH.avg_aes_dec_us      = mean_op("AES_DEC");
    OH.avg_hmac_us         = mean_op("HMAC");
    OH.avg_crt_verify_us   = mean_op("CRT_VERIFY");
    OH.avg_rekey_compute_us = mean_op("REKEY");

    // ---- D: Denied ----
    auto& D = m_summary.denied;
    if (!m_sinr_samples.empty()) {
        double sum = 0, sq = 0;
        // uint32_t jammed = 0; // removed unused
        D.min_sinr_db = 1e9;
        std::set<uint32_t> ever_jammed;
        for (const auto& s : m_sinr_samples) {
            sum += s.sinr_db;
            sq  += s.sinr_db * s.sinr_db;
            if (s.sinr_db < D.min_sinr_db) D.min_sinr_db = s.sinr_db;
            if (s.jammed) ever_jammed.insert(s.uav_id);
        }
        double n = m_sinr_samples.size();
        D.avg_sinr_db         = sum / n;
        double var            = sq / n - D.avg_sinr_db * D.avg_sinr_db;
        D.sinr_stddev_db      = var > 0 ? std::sqrt(var) : 0.0;
        D.jammed_uav_ratio    = (double)ever_jammed.size() / TOTAL_UAVS;
    }
    if (!m_jammer_recovery_ms.empty()) {
        double sum = 0;
        for (const auto& kv : m_jammer_recovery_ms) sum += kv.second;
        D.avg_recovery_after_jam_ms = sum / m_jammer_recovery_ms.size();
    }
    D.total_link_failures = (uint32_t)m_link_failures.size();
    D.link_failure_rate   = sim_dur_s > 0
        ? (double)D.total_link_failures / sim_dur_s : 0.0;
    // Interference impact: PDR degradation (jammed UAVs vs overall)
    if (D.jammed_uav_ratio > 0) {
        double jammed_pdr = 0, total = 0;
        for (const auto& s : m_sinr_samples) {
            if (s.jammed && s.uav_id < TOTAL_UAVS) {
                jammed_pdr += m_pkt_uav[s.uav_id].PDR();
                total++;
            }
        }
        double jammed_avg = total ? jammed_pdr / total : 0.0;
        D.interference_impact = N.global_pdr - jammed_avg;
        if (D.interference_impact < 0) D.interference_impact = 0;
    }

    // ---- E: Mobility ----
    auto& M = m_summary.mobility;
    // Cluster head stability = fraction of samples where SKDC reachable
    if (!m_cluster_head.empty()) {
        uint32_t ok = 0;
        for (const auto& r : m_cluster_head) if (r.skdc_reachable) ok++;
        M.cluster_head_stability = (double)ok / m_cluster_head.size();
    }
    M.total_route_breaks = (uint32_t)m_route_breaks.size();
    M.avg_route_break_freq = sim_dur_s > 0
        ? (double)M.total_route_breaks / (TOTAL_UAVS * sim_dur_s) : 0.0;

    // Mobility-rekey correlation: Pearson(velocity, triggered_rekey)
    if (m_route_breaks.size() > 2) {
        std::vector<double> vel, rk;
        for (const auto& r : m_route_breaks) {
            vel.push_back(r.velocity_mps);
            rk.push_back(r.triggered_rekey ? 1.0 : 0.0);
        }
        double n = vel.size();
        double sv = std::accumulate(vel.begin(), vel.end(), 0.0) / n;
        double sr = std::accumulate(rk.begin(), rk.end(), 0.0) / n;
        double cov = 0, varv = 0, varr = 0;
        for (size_t i = 0; i < vel.size(); ++i) {
            cov  += (vel[i]-sv)*(rk[i]-sr);
            varv += (vel[i]-sv)*(vel[i]-sv);
            varr += (rk[i]-sr)*(rk[i]-sr);
        }
        double denom = std::sqrt(varv * varr);
        M.mobility_rekey_corr = denom > 1e-9 ? cov / denom : 0.0;
    }

    if (!m_swarm_snaps.empty()) {
        double sum = 0, conn = 0;
        for (const auto& s : m_swarm_snaps) {
            sum  += s.survivability_ratio;
            conn += s.connectivity_ratio;
        }
        M.swarm_survivability   = sum / m_swarm_snaps.size();
        M.avg_connectivity_ratio = conn / m_swarm_snaps.size();
    }

    uint32_t handovers = 0;
    for (const auto& r : m_rekeys)
        if (r.trigger == "HANDOVER_OLD" || r.trigger == "HANDOVER_NEW")
            handovers++;
    M.handover_trigger_rate = sim_dur_s > 0
        ? (double)handovers / sim_dur_s : 0.0;

    m_finalized = true;

    NS_LOG_UNCOND(
        "\n========== METRICS SUMMARY ==========\n"
        << "  [A] PDR:              " << N.global_pdr << "\n"
        << "  [A] Throughput kbps:  " << N.global_throughput_kbps << "\n"
        << "  [A] Avg delay ms:     " << N.global_avg_delay_ms << "\n"
        << "  [A] Loss ratio:       " << N.global_loss_ratio << "\n"
        << "  [A] Route stability:  " << N.avg_routing_stability << "\n"
        << "  [A] Connectivity:     " << N.avg_connectivity_ratio << "\n"
        << "  [B] Avg key estab ms: " << S.avg_key_estab_ms << "\n"
        << "  [B] Avg rekey ms:     " << S.avg_rekey_latency_ms << "\n"
        << "  [B] Total rekeys:     " << S.total_rekeys << "\n"
        << "  [B] Auth success:     " << S.auth_success_rate << "\n"
        << "  [B] Fwd secrecy:      " << S.forward_secrecy_rate << "\n"
        << "  [B] Bwd secrecy:      " << S.backward_secrecy_rate << "\n"
        << "  [B] Replay det rate:  " << S.replay_detection_rate << "\n"
        << "  [B] Healing success:  " << S.healing_success_rate << "\n"
        << "  [C] Comm overhead:    " << OH.comm_overhead_ratio << "\n"
        << "  [C] Rekey overhead:   " << OH.rekey_overhead_ratio << "\n"
        << "  [C] Storage/UAV B:    " << OH.storage_per_uav_bytes << "\n"
        << "  [D] Avg SINR dB:      " << D.avg_sinr_db << "\n"
        << "  [D] Jammed UAV ratio: " << D.jammed_uav_ratio << "\n"
        << "  [D] Link fail rate:   " << D.link_failure_rate << "\n"
        << "  [E] CH stability:     " << M.cluster_head_stability << "\n"
        << "  [E] Route break freq: " << M.avg_route_break_freq << "\n"
        << "  [E] Survivability:    " << M.swarm_survivability << "\n"
        << "======================================");
}

// ============================================================================
// Accessor implementations
// ============================================================================
double MetricsFramework::GetClusterPdr(uint32_t c) const {
    return c < NUM_CLUSTERS ? m_pkt_cluster[c].PDR() : 0.0;
}
double MetricsFramework::GetClusterThroughput(uint32_t c) const {
    double dur = m_snapshot_count * m_snapshot_interval_s;
    return c < NUM_CLUSTERS
        ? m_pkt_cluster[c].ThroughputKbps(dur > 0 ? dur : 1.0) : 0.0;
}
double MetricsFramework::GetClusterAvgDelay(uint32_t c) const {
    return c < NUM_CLUSTERS ? m_delay_cluster[c].Avg() : 0.0;
}
double MetricsFramework::GetRekeyLatencyAvg() const {
    return m_summary.security.avg_rekey_latency_ms;
}
double MetricsFramework::GetAuthSuccessRate() const {
    return m_summary.security.auth_success_rate;
}
double MetricsFramework::GetForwardSecrecyRate() const {
    return m_summary.security.forward_secrecy_rate;
}
double MetricsFramework::GetBackwardSecrecyRate() const {
    return m_summary.security.backward_secrecy_rate;
}
double MetricsFramework::GetReplayDetectionRate() const {
    return m_summary.security.replay_detection_rate;
}
double MetricsFramework::GetSwarmSurvivability() const {
    return m_summary.mobility.swarm_survivability;
}
double MetricsFramework::GetClusterHeadStability(uint32_t c) const {
    if (m_cluster_head.empty()) return 1.0;
    uint32_t ok = 0, tot = 0;
    for (const auto& r : m_cluster_head) {
        if (r.cluster_id != c) continue;
        ++tot;
        if (r.skdc_reachable) ++ok;
    }
    return tot ? (double)ok / tot : 1.0;
}

// ============================================================================
// EXPORT — all CSV files
// ============================================================================
void MetricsFramework::ExportAll() const
{
    ExportNetworkCsv();
    ExportSecurityCsv();
    ExportOverheadCsv();
    ExportDeniedEnvCsv();
    ExportMobilityCsv();
    ExportFullReportCsv();
    ExportTimeSeries();
    ExportPerUavCsv();
    ExportPerClusterCsv();
    NS_LOG_INFO("MetricsFramework: exported all CSV files to "
        << m_output_dir);
}

void MetricsFramework::ExportNetworkCsv() const
{
    std::ofstream f(Path("metrics_network.csv"));
    if (!f.is_open()) return;
    const auto& N = m_summary.network;
    f << "metric,value\n";
    f << "global_pdr,"            << N.global_pdr            << "\n";
    f << "global_throughput_kbps,"<< N.global_throughput_kbps<< "\n";
    f << "global_avg_delay_ms,"   << N.global_avg_delay_ms   << "\n";
    f << "global_jitter_ms,"      << N.global_jitter_ms      << "\n";
    f << "global_loss_ratio,"     << N.global_loss_ratio     << "\n";
    f << "avg_routing_stability," << N.avg_routing_stability << "\n";
    f << "avg_connectivity_ratio,"<< N.avg_connectivity_ratio<< "\n";
    f << "total_route_breaks,"    << N.total_route_breaks    << "\n";
    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
        f << "cluster" << c << "_pdr,"       << N.pdr_per_cluster[c]             << "\n";
        f << "cluster" << c << "_tput_kbps," << N.throughput_per_cluster_kbps[c] << "\n";
        f << "cluster" << c << "_delay_ms,"  << N.delay_per_cluster_ms[c]        << "\n";
        f << "cluster" << c << "_loss,"      << N.loss_per_cluster[c]            << "\n";
    }
    f.close();
}

void MetricsFramework::ExportSecurityCsv() const
{
    // --- rekey_latency_full.csv ---
    {
        std::ofstream f(Path("rekey_latency_full.csv"));
        if (f.is_open()) {
            f << "time_s,cluster_id,trigger,latency_ms,"
                 "tek_version,members,msg_cost_bytes\n";
            for (const auto& r : m_rekeys)
                f << r.time_s      << ","
                  << r.cluster_id  << ","
                  << r.trigger     << ","
                  << r.latency_ms  << ","
                  << r.tek_version << ","
                  << r.members     << ","
                  << r.msg_cost    << "\n";
        }
    }
    // --- auth_log.csv ---
    {
        std::ofstream f(Path("auth_log.csv"));
        if (f.is_open()) {
            f << "time_s,uav_id,cluster_id,success,reason\n";
            for (const auto& r : m_auth)
                f << r.time_s << ","
                  << r.uav_id << ","
                  << r.cluster_id << ","
                  << r.success << ","
                  << r.failure_reason << "\n";
        }
    }
    // --- secrecy_checks.csv ---
    {
        std::ofstream f(Path("secrecy_checks.csv"));
        if (f.is_open()) {
            f << "time_s,cluster_id,tek_version,"
                 "forward_ok,backward_ok,event_type\n";
            for (const auto& r : m_secrecy)
                f << r.time_s      << ","
                  << r.cluster_id  << ","
                  << r.tek_version << ","
                  << r.forward_ok  << ","
                  << r.backward_ok << ","
                  << r.event_type  << "\n";
        }
    }
    // --- replay_log.csv ---
    {
        std::ofstream f(Path("replay_log.csv"));
        if (f.is_open()) {
            f << "time_s,uav_id,seq_num,detected,was_replay\n";
            for (const auto& r : m_replay)
                f << r.time_s    << ","
                  << r.uav_id   << ","
                  << r.seq_num  << ","
                  << r.detected << ","
                  << r.was_replay << "\n";
        }
    }
    // --- healing_log.csv ---
    {
        std::ofstream f(Path("healing_log.csv"));
        if (f.is_open()) {
            f << "trigger_s,recovery_s,uav_id,cluster_id,"
                 "recovered,event_type,latency_ms\n";
            for (const auto& r : m_healing)
                f << r.trigger_time_s       << ","
                  << r.recovery_time_s      << ","
                  << r.uav_id               << ","
                  << r.cluster_id           << ","
                  << r.recovered            << ","
                  << r.event_type           << ","
                  << r.recovery_latency_ms  << "\n";
        }
    }
    // --- metrics_security_summary.csv ---
    {
        std::ofstream f(Path("metrics_security.csv"));
        if (f.is_open()) {
            const auto& S = m_summary.security;
            f << "metric,value\n";
            f << "avg_key_estab_ms,"       << S.avg_key_estab_ms       << "\n";
            f << "max_key_estab_ms,"       << S.max_key_estab_ms       << "\n";
            f << "total_key_estabs,"       << S.total_key_estabs       << "\n";
            f << "avg_rekey_latency_ms,"   << S.avg_rekey_latency_ms   << "\n";
            f << "max_rekey_latency_ms,"   << S.max_rekey_latency_ms   << "\n";
            f << "total_rekeys,"           << S.total_rekeys           << "\n";
            f << "avg_rekey_msg_cost_B,"   << S.avg_rekey_msg_cost_bytes << "\n";
            f << "auth_success_rate,"      << S.auth_success_rate      << "\n";
            f << "auth_attempts,"          << S.auth_attempts          << "\n";
            f << "forward_secrecy_rate,"   << S.forward_secrecy_rate   << "\n";
            f << "backward_secrecy_rate,"  << S.backward_secrecy_rate  << "\n";
            f << "replay_detection_rate,"  << S.replay_detection_rate  << "\n";
            f << "replay_false_pos_rate,"  << S.replay_false_pos_rate  << "\n";
            f << "replay_attacks,"         << S.replay_attacks         << "\n";
            f << "healing_success_rate,"   << S.healing_success_rate   << "\n";
            f << "avg_recovery_ms,"        << S.avg_recovery_ms        << "\n";
            f << "healing_events,"         << S.healing_events         << "\n";
        }
    }
}

void MetricsFramework::ExportOverheadCsv() const
{
    // --- compute_timings.csv ---
    {
        std::ofstream f(Path("compute_timings.csv"));
        if (f.is_open()) {
            f << "operation,uav_id,wall_us\n";
            for (const auto& r : m_compute_timings)
                f << r.operation << "," << r.uav_id
                  << "," << r.wall_us << "\n";
        }
    }
    // --- overhead_summary.csv ---
    {
        std::ofstream f(Path("metrics_overhead.csv"));
        if (f.is_open()) {
            const auto& OH = m_summary.overhead;
            f << "metric,value\n";
            f << "comm_overhead_ratio,"   << OH.comm_overhead_ratio   << "\n";
            f << "rekey_overhead_ratio,"  << OH.rekey_overhead_ratio  << "\n";
            f << "header_overhead_ratio," << OH.header_overhead_ratio << "\n";
            f << "hmac_overhead_ratio,"   << OH.hmac_overhead_ratio   << "\n";
            f << "ctrl_bytes_per_sec,"    << OH.ctrl_bytes_per_sec    << "\n";
            f << "rekey_bytes_per_rekey," << OH.rekey_bytes_per_rekey << "\n";
            f << "avg_aes_enc_us,"        << OH.avg_aes_enc_us        << "\n";
            f << "avg_aes_dec_us,"        << OH.avg_aes_dec_us        << "\n";
            f << "avg_hmac_us,"           << OH.avg_hmac_us           << "\n";
            f << "avg_crt_verify_us,"     << OH.avg_crt_verify_us     << "\n";
            f << "avg_rekey_compute_us,"  << OH.avg_rekey_compute_us  << "\n";
            f << "storage_per_uav_bytes," << OH.storage_per_uav_bytes << "\n";
        }
    }
}

void MetricsFramework::ExportDeniedEnvCsv() const
{
    // --- sinr_log.csv ---
    {
        std::ofstream f(Path("sinr_log.csv"));
        if (f.is_open()) {
            f << "time_s,uav_id,cluster_id,sinr_db,jammed,drop_prob\n";
            for (const auto& s : m_sinr_samples)
                f << s.time_s    << ","
                  << s.uav_id   << ","
                  << s.cluster_id << ","
                  << s.sinr_db  << ","
                  << s.jammed   << ","
                  << s.drop_prob<< "\n";
        }
    }
    // --- link_failures.csv ---
    {
        std::ofstream f(Path("link_failures.csv"));
        if (f.is_open()) {
            f << "time_s,uav_id,cluster_id,cause,recovered,duration_ms\n";
            for (const auto& r : m_link_failures)
                f << r.time_s      << ","
                  << r.uav_id      << ","
                  << r.cluster_id  << ","
                  << r.cause       << ","
                  << r.recovered   << ","
                  << r.duration_ms << "\n";
        }
    }
    // --- metrics_denied.csv ---
    {
        std::ofstream f(Path("metrics_denied.csv"));
        if (f.is_open()) {
            const auto& D = m_summary.denied;
            f << "metric,value\n";
            f << "avg_sinr_db,"               << D.avg_sinr_db              << "\n";
            f << "min_sinr_db,"               << D.min_sinr_db              << "\n";
            f << "sinr_stddev_db,"            << D.sinr_stddev_db           << "\n";
            f << "jammed_uav_ratio,"          << D.jammed_uav_ratio         << "\n";
            f << "avg_recovery_after_jam_ms," << D.avg_recovery_after_jam_ms<< "\n";
            f << "link_failure_rate,"         << D.link_failure_rate        << "\n";
            f << "total_link_failures,"       << D.total_link_failures      << "\n";
            f << "interference_impact,"       << D.interference_impact      << "\n";
        }
    }
}

void MetricsFramework::ExportMobilityCsv() const
{
    // --- route_breaks.csv ---
    {
        std::ofstream f(Path("route_breaks.csv"));
        if (f.is_open()) {
            f << "time_s,uav_id,cluster_id,velocity_mps,triggered_rekey\n";
            for (const auto& r : m_route_breaks)
                f << r.time_s          << ","
                  << r.uav_id          << ","
                  << r.cluster_id      << ","
                  << r.velocity_mps    << ","
                  << r.triggered_rekey << "\n";
        }
    }
    // --- swarm_survivability.csv ---
    {
        std::ofstream f(Path("swarm_survivability.csv"));
        if (f.is_open()) {
            f << "time_s,active,jammed,compromised,disconnected,"
                 "survivability,connectivity\n";
            for (const auto& s : m_swarm_snaps)
                f << s.time_s              << ","
                  << s.active_uavs         << ","
                  << s.jammed_uavs         << ","
                  << s.compromised_uavs    << ","
                  << s.disconnected_uavs   << ","
                  << s.survivability_ratio << ","
                  << s.connectivity_ratio  << "\n";
        }
    }
    // --- cluster_head_stability.csv ---
    {
        std::ofstream f(Path("cluster_head_stability.csv"));
        if (f.is_open()) {
            f << "time_s,cluster_id,skdc_node,members,"
                 "reachable,avg_dist_m\n";
            for (const auto& r : m_cluster_head)
                f << r.time_s             << ","
                  << r.cluster_id         << ","
                  << r.skdc_node_id       << ","
                  << r.active_members     << ","
                  << r.skdc_reachable     << ","
                  << r.avg_member_dist_m  << "\n";
        }
    }
    // --- metrics_mobility.csv ---
    {
        std::ofstream f(Path("metrics_mobility.csv"));
        if (f.is_open()) {
            const auto& M = m_summary.mobility;
            f << "metric,value\n";
            f << "cluster_head_stability," << M.cluster_head_stability  << "\n";
            f << "avg_route_break_freq,"   << M.avg_route_break_freq    << "\n";
            f << "total_route_breaks,"     << M.total_route_breaks      << "\n";
            f << "mobility_rekey_corr,"    << M.mobility_rekey_corr     << "\n";
            f << "swarm_survivability,"    << M.swarm_survivability     << "\n";
            f << "avg_connectivity_ratio," << M.avg_connectivity_ratio  << "\n";
            f << "handover_trigger_rate,"  << M.handover_trigger_rate   << "\n";
        }
    }
}

void MetricsFramework::ExportFullReportCsv() const
{
    std::ofstream f(Path("metrics_full_report.csv"));
    if (!f.is_open()) return;

    f << "category,metric,value\n";
    const auto& N  = m_summary.network;
    const auto& S  = m_summary.security;
    const auto& OH = m_summary.overhead;
    const auto& D  = m_summary.denied;
    const auto& M  = m_summary.mobility;

    // A
    f<<"A,pdr,"<<N.global_pdr<<"\n";
    f<<"A,throughput_kbps,"<<N.global_throughput_kbps<<"\n";
    f<<"A,avg_delay_ms,"<<N.global_avg_delay_ms<<"\n";
    f<<"A,jitter_ms,"<<N.global_jitter_ms<<"\n";
    f<<"A,loss_ratio,"<<N.global_loss_ratio<<"\n";
    f<<"A,routing_stability,"<<N.avg_routing_stability<<"\n";
    f<<"A,connectivity_ratio,"<<N.avg_connectivity_ratio<<"\n";
    // B
    f<<"B,key_estab_ms,"<<S.avg_key_estab_ms<<"\n";
    f<<"B,rekey_latency_ms,"<<S.avg_rekey_latency_ms<<"\n";
    f<<"B,total_rekeys,"<<S.total_rekeys<<"\n";
    f<<"B,auth_success_rate,"<<S.auth_success_rate<<"\n";
    f<<"B,forward_secrecy,"<<S.forward_secrecy_rate<<"\n";
    f<<"B,backward_secrecy,"<<S.backward_secrecy_rate<<"\n";
    f<<"B,replay_detection_rate,"<<S.replay_detection_rate<<"\n";
    f<<"B,healing_success_rate,"<<S.healing_success_rate<<"\n";
    f<<"B,avg_session_recovery_ms,"<<S.avg_recovery_ms<<"\n";
    // C
    f<<"C,comm_overhead,"<<OH.comm_overhead_ratio<<"\n";
    f<<"C,rekey_overhead,"<<OH.rekey_overhead_ratio<<"\n";
    f<<"C,storage_per_uav_bytes,"<<OH.storage_per_uav_bytes<<"\n";
    f<<"C,ctrl_bytes_per_sec,"<<OH.ctrl_bytes_per_sec<<"\n";
    f<<"C,rekey_msg_cost_bytes,"<<OH.rekey_bytes_per_rekey<<"\n";
    f<<"C,aes_enc_us,"<<OH.avg_aes_enc_us<<"\n";
    f<<"C,aes_dec_us,"<<OH.avg_aes_dec_us<<"\n";
    f<<"C,hmac_us,"<<OH.avg_hmac_us<<"\n";
    f<<"C,crt_verify_us,"<<OH.avg_crt_verify_us<<"\n";
    // D
    f<<"D,avg_sinr_db,"<<D.avg_sinr_db<<"\n";
    f<<"D,min_sinr_db,"<<D.min_sinr_db<<"\n";
    f<<"D,sinr_stddev_db,"<<D.sinr_stddev_db<<"\n";
    f<<"D,jammed_uav_ratio,"<<D.jammed_uav_ratio<<"\n";
    f<<"D,recovery_after_jam_ms,"<<D.avg_recovery_after_jam_ms<<"\n";
    f<<"D,link_failure_rate,"<<D.link_failure_rate<<"\n";
    f<<"D,interference_impact,"<<D.interference_impact<<"\n";
    // E
    f<<"E,cluster_head_stability,"<<M.cluster_head_stability<<"\n";
    f<<"E,route_break_freq,"<<M.avg_route_break_freq<<"\n";
    f<<"E,mobility_rekey_corr,"<<M.mobility_rekey_corr<<"\n";
    f<<"E,swarm_survivability,"<<M.swarm_survivability<<"\n";
    f<<"E,handover_trigger_rate,"<<M.handover_trigger_rate<<"\n";
    f.close();
}

void MetricsFramework::ExportTimeSeries() const
{
    std::ofstream f(Path("timeseries.csv"));
    if (!f.is_open()) return;
    f << "time_s,pdr,throughput_kbps,avg_delay_ms,"
         "sinr_db,total_rekeys,survivability,"
         "connectivity,overhead_ratio\n";
    for (const auto& p : m_timeseries)
        f << p.t            << ","
          << p.pdr          << ","
          << p.throughput   << ","
          << p.delay_ms     << ","
          << p.sinr_db      << ","
          << p.rekeys       << ","
          << p.survivability<< ","
          << p.connectivity << ","
          << p.overhead_ratio << "\n";
    f.close();
}

void MetricsFramework::ExportPerUavCsv() const
{
    std::ofstream f(Path("metrics_per_uav.csv"));
    if (!f.is_open()) return;
    f << "uav_id,cluster_id,pdr,throughput_kbps,"
         "avg_delay_ms,loss_ratio\n";
    const auto& N = m_summary.network;
    for (uint32_t u = 0; u < TOTAL_UAVS; ++u)
        f << u              << ","
          << (u/UAVS_PER_CLUS) << ","
          << N.pdr_per_uav[u]             << ","
          << N.throughput_per_uav_kbps[u] << ","
          << N.delay_per_uav_ms[u]        << ","
          << m_pkt_uav[u].LossRatio()     << "\n";
    f.close();
}

void MetricsFramework::ExportPerClusterCsv() const
{
    std::ofstream f(Path("metrics_per_cluster.csv"));
    if (!f.is_open()) return;
    f << "cluster_id,avg_pdr,throughput_kbps,"
         "avg_delay_ms,loss_ratio,rekeys,"
         "ch_stability\n";
    const auto& N = m_summary.network;
    const auto& S = m_summary.security;
    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c)
        f << c                                   << ","
          << N.pdr_per_cluster[c]               << ","
          << N.throughput_per_cluster_kbps[c]   << ","
          << N.delay_per_cluster_ms[c]          << ","
          << N.loss_per_cluster[c]              << ","
          << S.rekeys_per_cluster[c]            << ","
          << GetClusterHeadStability(c)         << "\n";
    f.close();
}

} // namespace metrics
} // namespace uav
