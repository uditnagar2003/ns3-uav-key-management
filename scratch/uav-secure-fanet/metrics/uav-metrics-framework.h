/**
 * metrics/uav-metrics-framework.h
 *
 * COMPLETE PERFORMANCE EVALUATION FRAMEWORK
 * Hierarchical CRT-GCRT UAV Swarm Multicast Key Management
 *
 * Covers ALL metric categories:
 *
 *   CATEGORY A — NETWORK METRICS
 *     A1. Packet Delivery Ratio (PDR)
 *     A2. Throughput (per-UAV, per-cluster, global)
 *     A3. End-to-End Delay
 *     A4. Packet Loss Ratio
 *     A5. Routing Stability Index
 *     A6. Swarm Connectivity Ratio
 *
 *   CATEGORY B — SECURITY & KEY MANAGEMENT METRICS
 *     B1.  Key Establishment Time
 *     B2.  Rekeying Delay
 *     B3.  Authentication Success Rate
 *     B4.  Forward Secrecy Validation
 *     B5.  Backward Secrecy Validation
 *     B6.  Replay Attack Detection Rate
 *     B7.  Mutual-Healing Recovery Success
 *     B8.  Secure Session Recovery Time
 *
 *   CATEGORY C — OVERHEAD METRICS
 *     C1. Communication Overhead
 *     C2. Computational Overhead
 *     C3. Storage Overhead
 *     C4. Control Packet Overhead
 *     C5. Rekeying Message Cost
 *
 *   CATEGORY D — DENIED ENVIRONMENT METRICS
 *     D1. SINR per UAV
 *     D2. Jammed UAV Ratio
 *     D3. Recovery Time after Jamming
 *     D4. Link Failure Rate
 *     D5. Interference Impact Analysis
 *
 *   CATEGORY E — MOBILITY & SWARM METRICS
 *     E1. Cluster Head Stability
 *     E2. Route Break Frequency
 *     E3. UAV Mobility Impact on Rekeying
 *     E4. Swarm Survivability Index
 *
 * INTEGRATION:
 *   All categories feed CsvExportManager (Module 59).
 *   All categories exported to metrics_full_report.csv.
 *   All timers use NS-3 Simulator::Now().
 *
 * USAGE (in main.cc):
 *   uav::metrics::MetricsFramework mf(topo, output_dir);
 *   mf.Initialize();
 *   // Hook callbacks from apps:
 *   mf.RecordKeyEstablishment(uav_id, latency_ms);
 *   mf.RecordRekey(cluster, trigger, latency_ms);
 *   mf.RecordAuthAttempt(uav_id, success);
 *   mf.RecordReplayDetection(uav_id, detected);
 *   mf.RecordJammerImpact(uav_id, sinr_db);
 *   mf.RecordLinkFailure(uav_id);
 *   mf.RecordHandover(uav_id, old_cluster, new_cluster, latency_ms);
 *   mf.RecordRouteBreak(uav_id);
 *   mf.RecordCompromise(uav_id, recovered);
 *   // At simulation end:
 *   mf.Finalize(sim_duration_s);
 *   mf.ExportAll();
 */

#ifndef UAV_METRICS_FRAMEWORK_H
#define UAV_METRICS_FRAMEWORK_H

#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "routing/uav-topology.h"

#include "ns3/core-module.h"
#include "ns3/simulator.h"

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <mutex>

namespace uav {
namespace metrics {

// ============================================================================
// Constants
// ============================================================================
static constexpr uint32_t NUM_CLUSTERS   = 3;
static constexpr uint32_t UAVS_PER_CLUS  = 6;
static constexpr uint32_t TOTAL_UAVS     = 18;

// ============================================================================
// A — NETWORK METRICS STRUCTS
// ============================================================================

/// Per-UAV packet counters
struct PacketCounter {
    uint64_t tx      = 0;  ///< transmitted
    uint64_t rx      = 0;  ///< received
    uint64_t lost    = 0;  ///< lost
    uint64_t ctrl_tx = 0;  ///< control packets transmitted
    uint64_t ctrl_rx = 0;  ///< control packets received
    double   bytes_tx   = 0.0;
    double   bytes_rx   = 0.0;

    double PDR()       const { return tx ? (double)rx / tx : 0.0; }
    double LossRatio() const { return tx ? (double)lost / tx : 0.0; }
    double ThroughputKbps(double dur_s) const {
        return dur_s > 0 ? (bytes_rx * 8.0 / 1000.0) / dur_s : 0.0;
    }
};

/// Per-UAV delay tracker
struct DelayAccumulator {
    double   sum_ms       = 0.0;
    double   sum_sq_ms    = 0.0;
    uint64_t count        = 0;
    double   min_ms       = 1e9;
    double   max_ms       = 0.0;

    void Record(double delay_ms) {
        sum_ms    += delay_ms;
        sum_sq_ms += delay_ms * delay_ms;
        ++count;
        if (delay_ms < min_ms) min_ms = delay_ms;
        if (delay_ms > max_ms) max_ms = delay_ms;
    }
    double Avg()    const { return count ? sum_ms / count : 0.0; }
    double Jitter() const {
        if (count < 2) return 0.0;
        double mean = Avg();
        double var  = sum_sq_ms / count - mean * mean;
        return var > 0 ? std::sqrt(var) : 0.0;
    }
};

/// Routing topology stability sample
struct RoutingStabilitySample {
    double time_s         = 0.0;
    uint32_t active_routes = 0;
    uint32_t broken_routes = 0;
    uint32_t total_nodes   = 0;
    double   stability_idx = 0.0; ///< active/total_possible
};

// ============================================================================
// B — SECURITY & KEY MANAGEMENT METRIC STRUCTS
// ============================================================================

/// Key establishment event record
struct KeyEstabRecord {
    double   time_s      = 0.0;
    uint32_t uav_id      = 0;
    uint32_t cluster_id  = 0;
    double   latency_ms  = 0.0;
    bool     success     = true;
};

/// Rekey event record
struct RekeyRecord {
    double      time_s      = 0.0;
    uint32_t    cluster_id  = 0;
    std::string trigger;           ///< JOIN, LEAVE, COMPROMISE, PERIODIC, BATCH
    double      latency_ms  = 0.0;
    uint32_t    tek_version = 0;
    uint32_t    members     = 0;   ///< members at time of rekey
    double      msg_cost    = 0.0; ///< bytes used for this rekey
};

/// Authentication attempt record
struct AuthRecord {
    double   time_s     = 0.0;
    uint32_t uav_id     = 0;
    uint32_t cluster_id = 0;
    bool     success    = false;
    std::string failure_reason;    ///< HMAC_FAIL, REPLAY, EXPIRED, OK
};

/// Replay attack detection record
struct ReplayRecord {
    double   time_s     = 0.0;
    uint32_t uav_id     = 0;
    uint32_t seq_num    = 0;
    bool     detected   = false;  ///< true = correctly blocked
    bool     was_replay = false;  ///< ground truth (injected by jammer)
};

/// Forward/Backward secrecy validation record
struct SecrecyRecord {
    double   time_s          = 0.0;
    uint32_t cluster_id      = 0;
    uint32_t tek_version     = 0;
    bool     forward_ok      = false; ///< old TEK cannot decrypt new MT_K
    bool     backward_ok     = false; ///< new TEK cannot decrypt old MT_K
    std::string event_type;           ///< JOIN, LEAVE, HANDOVER
};

/// Mutual-healing / session recovery record
struct HealingRecord {
    double   trigger_time_s   = 0.0;
    double   recovery_time_s  = 0.0;
    uint32_t uav_id           = 0;
    uint32_t cluster_id       = 0;
    bool     recovered        = false;
    std::string event_type;          ///< COMPROMISE, DISCONNECT, REJOIN
    double   recovery_latency_ms = 0.0;
};

// ============================================================================
// C — OVERHEAD METRIC STRUCTS
// ============================================================================

/// Per-packet overhead tracking
struct OverheadSample {
    double   time_s          = 0.0;
    uint32_t cluster_id      = 0;
    uint64_t data_bytes      = 0;     ///< application payload bytes
    uint64_t ctrl_bytes      = 0;     ///< control/security overhead bytes
    uint64_t rekey_bytes     = 0;     ///< bytes used for rekey messages
    uint64_t header_bytes    = 0;     ///< packet header overhead
    uint64_t hmac_bytes      = 0;     ///< HMAC tag bytes (32 per pkt)
    uint64_t mtk_bytes       = 0;     ///< MT_K field bytes
};

/// Per-operation CPU timing (wall-clock, not simulated time)
struct ComputeTimingRecord {
    std::string operation;     ///< AES_ENC, AES_DEC, HMAC, CRT_VERIFY, REKEY
    double      wall_us  = 0.0;
    uint32_t    uav_id   = 0;
};

// ============================================================================
// D — DENIED ENVIRONMENT METRIC STRUCTS
// ============================================================================

/// Per-UAV SINR sample
struct MfSinrSample {
    double   time_s        = 0.0;
    uint32_t uav_id        = 0;
    uint32_t cluster_id    = 0;
    double   sinr_db       = 0.0;
    bool     jammed        = false;  ///< sinr_db < threshold (8 dB)
    double   drop_prob     = 0.0;    ///< estimated packet drop probability
};

/// Jammer attack event
struct JammerEvent {
    double   start_s       = 0.0;
    double   end_s         = 0.0;
    uint32_t affected_uavs = 0;
    double   avg_sinr_db   = 0.0;
    double   recovery_ms   = 0.0;  ///< time until all affected UAVs recovered
};

/// Link failure record
struct LinkFailureRecord {
    double   time_s      = 0.0;
    uint32_t uav_id      = 0;
    uint32_t cluster_id  = 0;
    std::string cause;            ///< MOBILITY, JAMMER, INTERFERENCE
    double   duration_ms = 0.0;  ///< how long link was down
    bool     recovered   = false;
};

// ============================================================================
// E — MOBILITY & SWARM METRIC STRUCTS
// ============================================================================

/// Route break event
struct RouteBreakRecord {
    double   time_s          = 0.0;
    uint32_t uav_id          = 0;
    uint32_t cluster_id      = 0;
    double   velocity_mps    = 0.0;  ///< UAV speed at break time
    bool     triggered_rekey = false;
};

/// Swarm survivability snapshot
struct SwarmSurvivabilitySnapshot {
    double   time_s              = 0.0;
    uint32_t total_uavs          = 0;
    uint32_t active_uavs         = 0;     ///< connected + authenticated
    uint32_t jammed_uavs         = 0;
    uint32_t compromised_uavs    = 0;
    uint32_t disconnected_uavs   = 0;
    double   survivability_ratio = 0.0;   ///< active/total
    double   connectivity_ratio  = 0.0;   ///< connected_pairs / max_pairs
};

/// Cluster head (SKDC) stability record
struct ClusterHeadStabilityRecord {
    double   time_s         = 0.0;
    uint32_t cluster_id     = 0;
    uint32_t skdc_node_id   = 0;
    uint32_t active_members = 0;
    bool     skdc_reachable = true;
    double   avg_member_dist_m = 0.0; ///< avg distance from SKDC to members
};

// ============================================================================
// SUMMARY STRUCTS — Computed at finalization
// ============================================================================

struct NetworkMetricsSummary {
    // PDR
    double global_pdr            = 0.0;
    double pdr_per_cluster[3]    = {};
    double pdr_per_uav[18]       = {};

    // Throughput
    double global_throughput_kbps           = 0.0;
    double throughput_per_cluster_kbps[3]   = {};
    double throughput_per_uav_kbps[18]      = {};

    // Delay
    double global_avg_delay_ms   = 0.0;
    double global_jitter_ms      = 0.0;
    double delay_per_cluster_ms[3] = {};
    double delay_per_uav_ms[18]  = {};

    // Loss
    double global_loss_ratio     = 0.0;
    double loss_per_cluster[3]   = {};

    // Stability
    double avg_routing_stability  = 0.0;
    double avg_connectivity_ratio = 0.0;
    uint32_t total_route_breaks   = 0;
};

struct SecurityMetricsSummary {
    // Key establishment
    double avg_key_estab_ms       = 0.0;
    double max_key_estab_ms       = 0.0;
    uint32_t total_key_estabs     = 0;

    // Rekeying
    double avg_rekey_latency_ms   = 0.0;
    double max_rekey_latency_ms   = 0.0;
    uint32_t total_rekeys         = 0;
    uint32_t rekeys_per_cluster[3] = {};
    double avg_rekey_msg_cost_bytes = 0.0;

    // Authentication
    double auth_success_rate      = 0.0;  ///< 0.0-1.0
    uint32_t auth_attempts        = 0;
    uint32_t auth_successes       = 0;

    // Secrecy
    double forward_secrecy_rate   = 0.0;  ///< fraction of events where FS held
    double backward_secrecy_rate  = 0.0;
    uint32_t secrecy_checks       = 0;

    // Replay
    double replay_detection_rate  = 0.0;  ///< TP / (TP+FN)
    double replay_false_pos_rate  = 0.0;  ///< FP / (FP+TN)
    uint32_t replay_attacks       = 0;
    uint32_t replay_detected      = 0;

    // Healing
    double avg_recovery_ms        = 0.0;
    double healing_success_rate   = 0.0;
    uint32_t healing_events       = 0;
};

struct OverheadMetricsSummary {
    double comm_overhead_ratio    = 0.0;  ///< ctrl_bytes / total_bytes
    double rekey_overhead_ratio   = 0.0;  ///< rekey_bytes / total_bytes
    double header_overhead_ratio  = 0.0;
    double hmac_overhead_ratio    = 0.0;

    double ctrl_bytes_per_sec     = 0.0;
    double rekey_bytes_per_rekey  = 0.0;

    double avg_aes_enc_us         = 0.0;  ///< computational overhead
    double avg_aes_dec_us         = 0.0;
    double avg_hmac_us            = 0.0;
    double avg_crt_verify_us      = 0.0;
    double avg_rekey_compute_us   = 0.0;

    double storage_per_uav_bytes  = 0.0;  ///< TEK + slave key + replay cache
};

struct DeniedEnvMetricsSummary {
    double avg_sinr_db            = 0.0;
    double min_sinr_db            = 1e9;
    double sinr_stddev_db         = 0.0;
    double jammed_uav_ratio       = 0.0;  ///< fraction of UAVs ever jammed
    double avg_recovery_after_jam_ms  = 0.0;
    double link_failure_rate      = 0.0;  ///< failures per second
    uint32_t total_link_failures  = 0;
    double interference_impact    = 0.0;  ///< PDR degradation due to jammer
};

struct MobilityMetricsSummary {
    double cluster_head_stability  = 0.0; ///< fraction of time SKDC reachable
    double avg_route_break_freq    = 0.0; ///< breaks per UAV per second
    uint32_t total_route_breaks    = 0;
    double mobility_rekey_corr     = 0.0; ///< Pearson correlation(speed, rekeys)
    double swarm_survivability     = 0.0; ///< avg survivability over sim
    double avg_connectivity_ratio  = 0.0;
    double handover_trigger_rate   = 0.0; ///< handovers per second
};

/// Master summary of ALL categories
struct FullMetricsSummary {
    NetworkMetricsSummary  network;
    SecurityMetricsSummary security;
    OverheadMetricsSummary overhead;
    DeniedEnvMetricsSummary denied;
    MobilityMetricsSummary  mobility;

    double simulation_duration_s = 0.0;
    uint32_t seed                = 0;
    uint32_t run_index           = 0;
};

// ============================================================================
// MetricsFramework — Central collection and export manager
// ============================================================================
class MetricsFramework {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    MetricsFramework(
        const routing::TopologyResult* topo,
        const std::string& output_dir,
        uint32_t seed = 42);

    ~MetricsFramework() = default;

    /// Schedule periodic snapshots (every 1s)
    void Initialize(double snapshot_interval_s = 1.0);

    // -----------------------------------------------------------------------
    // A — NETWORK METRIC HOOKS
    // -----------------------------------------------------------------------

    /// Called by UavApplication on every data packet TX
    void RecordTx(uint32_t uav_id, uint32_t bytes,
                  bool is_ctrl = false);

    /// Called on successful packet RX
    void RecordRx(uint32_t uav_id, uint32_t bytes,
                  double delay_ms, bool is_ctrl = false);

    /// Called on detected packet loss
    void RecordLoss(uint32_t uav_id, uint32_t bytes);

    /// Called by OLSR manager on route table update
    void RecordRoutingUpdate(uint32_t active_routes,
                              uint32_t broken_routes);

    /// Called when two nodes are connectivity-checked
    void RecordConnectivitySample(uint32_t connected_pairs,
                                   uint32_t total_possible_pairs);

    // -----------------------------------------------------------------------
    // B — SECURITY & KEY MANAGEMENT HOOKS
    // -----------------------------------------------------------------------

    /// Called when SKDC completes UAV key establishment (Join event)
    void RecordKeyEstablishment(uint32_t uav_id,
                                 uint32_t cluster_id,
                                 double latency_ms,
                                 bool success = true);

    /// Called after each rekey broadcast completes
    void RecordRekey(uint32_t cluster_id,
                     const std::string& trigger,
                     double latency_ms,
                     uint32_t tek_version,
                     uint32_t members,
                     double msg_cost_bytes);

    /// Called on every authentication attempt
    void RecordAuthAttempt(uint32_t uav_id,
                            uint32_t cluster_id,
                            bool success,
                            const std::string& failure_reason = "OK");

    /// Called after each TEK rotation to check secrecy properties
    /// forward_ok: old TEK decrypt of new MT_K returns wrong value
    /// backward_ok: new TEK decrypt of old MT_K returns wrong value
    void RecordSecrecyCheck(uint32_t cluster_id,
                             uint32_t tek_version,
                             bool forward_ok,
                             bool backward_ok,
                             const std::string& event_type);

    /// Called when replay protection module fires
    void RecordReplayDetection(uint32_t uav_id,
                                uint32_t seq_num,
                                bool detected,
                                bool was_actual_replay);

    /// Called when a compromised/disconnected UAV reconnects
    void RecordHealingAttempt(uint32_t uav_id,
                               uint32_t cluster_id,
                               double trigger_time_s,
                               bool recovered,
                               const std::string& event_type);

    // -----------------------------------------------------------------------
    // C — OVERHEAD HOOKS
    // -----------------------------------------------------------------------

    /// Called per packet to track byte-level overhead categories
    void RecordPacketOverhead(uint32_t cluster_id,
                               uint64_t data_bytes,
                               uint64_t header_bytes,
                               uint64_t hmac_bytes,
                               uint64_t mtk_bytes,
                               uint64_t ctrl_bytes,
                               uint64_t rekey_bytes);

    /// Called around crypto operations (wall-clock timing)
    void RecordComputeTiming(const std::string& operation,
                              uint32_t uav_id,
                              double wall_us);

    // -----------------------------------------------------------------------
    // D — DENIED ENVIRONMENT HOOKS
    // -----------------------------------------------------------------------

    /// Called by JammerManager/SinrMetrics on each PHY sample
    void RecordSinrSample(uint32_t uav_id,
                           uint32_t cluster_id,
                           double sinr_db,
                           double threshold_db = 8.0);

    /// Called when jammer attack starts/ends
    void RecordJammerEvent(double start_s, double end_s,
                            uint32_t affected_uavs,
                            double avg_sinr_db);

    /// Called when UAV recovers link after jammer event
    void RecordJammerRecovery(uint32_t uav_id,
                               double recovery_latency_ms);

    /// Called on link failure detection
    void RecordLinkFailure(uint32_t uav_id,
                            uint32_t cluster_id,
                            const std::string& cause,
                            bool recovered,
                            double duration_ms);

    // -----------------------------------------------------------------------
    // E — MOBILITY & SWARM HOOKS
    // -----------------------------------------------------------------------

    /// Called when OLSR detects route break
    void RecordRouteBreak(uint32_t uav_id,
                           uint32_t cluster_id,
                           double velocity_mps,
                           bool triggered_rekey);

    /// Called every snapshot interval for swarm-level aggregation
    void RecordSwarmSnapshot(uint32_t active_uavs,
                              uint32_t jammed_uavs,
                              uint32_t compromised_uavs,
                              uint32_t disconnected_uavs,
                              uint32_t connected_pairs);

    /// Called periodically from SKDC to record cluster head status
    void RecordClusterHeadStatus(uint32_t cluster_id,
                                  uint32_t skdc_node_id,
                                  uint32_t active_members,
                                  bool skdc_reachable,
                                  double avg_member_dist_m);

    // -----------------------------------------------------------------------
    // Finalization & Export
    // -----------------------------------------------------------------------

    /// Compute all summaries. Call after Simulator::Run().
    void Finalize(double sim_duration_s, uint32_t run_index = 0);

    /// Export all CSV files
    void ExportAll() const;

    /// Get computed summary (after Finalize)
    const FullMetricsSummary& GetSummary() const { return m_summary; }

    // -----------------------------------------------------------------------
    // Convenience per-cluster accessors
    // -----------------------------------------------------------------------
    double GetClusterPdr(uint32_t c) const;
    double GetClusterThroughput(uint32_t c) const;
    double GetClusterAvgDelay(uint32_t c) const;
    double GetRekeyLatencyAvg() const;
    double GetAuthSuccessRate() const;
    double GetForwardSecrecyRate() const;
    double GetBackwardSecrecyRate() const;
    double GetReplayDetectionRate() const;
    double GetSwarmSurvivability() const;
    double GetClusterHeadStability(uint32_t c) const;

    // -----------------------------------------------------------------------
    // NetAnim annotation support
    // -----------------------------------------------------------------------
    void SetAnimationPtr(void* anim) { m_anim = anim; }

private:
    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------
    void PeriodicSnapshot();
    void ExportNetworkCsv()    const;
    void ExportSecurityCsv()   const;
    void ExportOverheadCsv()   const;
    void ExportDeniedEnvCsv()  const;
    void ExportMobilityCsv()   const;
    void ExportFullReportCsv() const;
    void ExportTimeSeries()    const;
    void ExportPerUavCsv()     const;
    void ExportPerClusterCsv() const;

    std::string Path(const std::string& f) const {
        return m_output_dir + "/" + f;
    }
    uint32_t ClusterId(uint32_t uav_id) const {
        return (uav_id < TOTAL_UAVS) ? uav_id / UAVS_PER_CLUS : 0;
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    const routing::TopologyResult* m_topo;
    std::string                    m_output_dir;
    uint32_t                       m_seed;
    void*                          m_anim = nullptr;

    // A — Network
    PacketCounter   m_pkt_global;
    PacketCounter   m_pkt_cluster[NUM_CLUSTERS];
    PacketCounter   m_pkt_uav[TOTAL_UAVS];
    DelayAccumulator m_delay_global;
    DelayAccumulator m_delay_cluster[NUM_CLUSTERS];
    DelayAccumulator m_delay_uav[TOTAL_UAVS];

    std::vector<RoutingStabilitySample> m_stability_samples;
    std::vector<double>                 m_connectivity_samples;

    // B — Security
    std::vector<KeyEstabRecord>   m_key_estab;
    std::vector<RekeyRecord>      m_rekeys;
    std::vector<AuthRecord>       m_auth;
    std::vector<SecrecyRecord>    m_secrecy;
    std::vector<ReplayRecord>     m_replay;
    std::vector<HealingRecord>    m_healing;

    // C — Overhead
    std::vector<OverheadSample>       m_overhead_samples;
    std::vector<ComputeTimingRecord>  m_compute_timings;

    // D — Denied
    std::vector<MfSinrSample>        m_sinr_samples;
    std::vector<JammerEvent>       m_jammer_events;
    std::vector<LinkFailureRecord> m_link_failures;
    std::unordered_map<uint32_t, double> m_jammer_recovery_ms;

    // E — Mobility
    std::vector<RouteBreakRecord>          m_route_breaks;
    std::vector<SwarmSurvivabilitySnapshot> m_swarm_snaps;
    std::vector<ClusterHeadStabilityRecord> m_cluster_head;

    // Time-series for CSV export (1s interval)
    struct TimeSeriesPoint {
        double   t          = 0.0;
        double   pdr        = 0.0;
        double   throughput = 0.0;
        double   delay_ms   = 0.0;
        double   sinr_db    = 0.0;
        uint32_t rekeys     = 0;
        double   survivability = 0.0;
        double   connectivity  = 0.0;
        double   overhead_ratio = 0.0;
    };
    std::vector<TimeSeriesPoint>  m_timeseries;

    // Snapshot counters
    double   m_snapshot_interval_s = 1.0;
    uint32_t m_snapshot_count      = 0;

    // Finalized summary
    FullMetricsSummary m_summary;
    bool               m_finalized = false;
};

} // namespace metrics
} // namespace uav

#endif // UAV_METRICS_FRAMEWORK_H
