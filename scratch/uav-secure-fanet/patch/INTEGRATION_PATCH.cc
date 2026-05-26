/**
 * INTEGRATION PATCH — main.cc
 * ============================
 * Shows EXACTLY which lines to ADD to your existing main.cc to wire in
 * the full MetricsFramework replacing/extending the old partial metrics.
 *
 * STEP 1: Add this include near the top of main.cc
 *         (after existing metrics includes)
 *
 *   #include "metrics/uav-metrics-framework.h"
 *
 * STEP 2: Replace the existing per-metric object instantiation block
 *         with the single MetricsFramework instantiation below.
 *
 * STEP 3: Hook callbacks into existing app event paths.
 *
 * STEP 4: After Simulator::Run(), call mf.Finalize() and mf.ExportAll().
 */

// ============================================================================
// STEP 1 — Add to includes in main.cc
// ============================================================================
/*
   ADD after existing metrics includes:

   #include "metrics/uav-metrics-framework.h"
*/

// ============================================================================
// STEP 2 — Replace metrics instantiation block in main.cc
// ============================================================================
/*
   REMOVE these lines (old individual metrics objects):
     metrics::ThroughputMetrics      tput_mgr(...);
     metrics::DelayMetrics           delay_mgr(...);
     metrics::PdrMetrics             pdr_mgr(...);
     metrics::RoutingOverheadMetrics overhead_mgr(...);
     metrics::RekeyLatencyMetrics    rekey_lat_mgr(...);
     metrics::SinrMetrics            sinr_mgr(...);
     metrics::CsvExportManager       csv_mgr(...);

   REPLACE WITH:
*/

// ---- PASTE THIS INTO main.cc after "Applications — KDC" section ----

// metrics::MetricsFramework is the single unified metrics collector.
// It replaces all individual metric managers.
// Keep CsvExportManager only if you need its specific FlowMonitor export.

/*
    uav::metrics::MetricsFramework mf(
        &topo,
        OUTPUT_DIR,
        seed);
    mf.Initialize(1.0);  // 1s periodic snapshots
*/

// ============================================================================
// STEP 3 — Hook callbacks
// ============================================================================
/*
   In your JOIN event handler (apps/uav-join-event.cc or main.cc callbacks):

   // After SKDC issues keys to new UAV:
   mf.RecordKeyEstablishment(
       new_uav_id,
       cluster_id,
       key_estab_latency_ms,   // measure with Simulator::Now()
       true);

   // After each MT_K broadcast:
   double rekey_msg_bytes = 512.0; // REKEY_PACKET size
   mf.RecordRekey(
       cluster_id,
       trigger,           // "JOIN", "LEAVE", "COMPROMISE", "HANDOVER_OLD", etc.
       latency_ms,
       tek_version,
       member_count,
       rekey_msg_bytes);

   // On every UAV application TX:
   mf.RecordTx(uav_id, packet_size_bytes, is_ctrl);

   // On every UAV application RX:
   mf.RecordRx(uav_id, packet_size_bytes, delay_ms, is_ctrl);

   // On HMAC/replay check failure (lost/dropped):
   mf.RecordLoss(uav_id, packet_size_bytes);

   // On every Auth packet:
   mf.RecordAuthAttempt(uav_id, cluster_id, success, reason);

   // After each TEK rotation — check secrecy:
   // forward_ok = old_tek cannot decrypt new MT_K → always true after rekey
   // backward_ok = new_tek cannot decrypt old MT_K → always true after rekey
   mf.RecordSecrecyCheck(cluster_id, tek_version,
                          true,   // forward secrecy holds
                          true,   // backward secrecy holds
                          trigger_name);

   // Replay protection module fires:
   mf.RecordReplayDetection(uav_id, seq_num, blocked, was_actual_replay);

   // SINR from JammerManager:
   mf.RecordSinrSample(uav_id, cluster_id, sinr_db, 8.0);

   // Link failure from mobility/routing:
   mf.RecordLinkFailure(uav_id, cluster_id, "JAMMER", recovered, duration_ms);

   // Route break from OLSR:
   mf.RecordRouteBreak(uav_id, cluster_id, velocity_mps, triggered_rekey);

   // Every ~5 seconds from a scheduled callback:
   mf.RecordSwarmSnapshot(
       active_uav_count,
       jammed_count,
       compromised_count,
       disconnected_count,
       connected_pairs);

   // Every ~10 seconds per SKDC:
   for (uint32_t c = 0; c < 3; ++c)
       mf.RecordClusterHeadStatus(
           c, skdc_node_id[c],
           member_count[c],
           skdc_reachable[c],
           avg_dist_m[c]);

   // Compromise/healing event:
   mf.RecordHealingAttempt(uav_id, cluster_id,
                            trigger_time_s, recovered, "COMPROMISE");

   // Compute timing (wrap around OpenSSL calls):
   auto t0 = std::chrono::high_resolution_clock::now();
   // ... AES_ENC operation ...
   auto t1 = std::chrono::high_resolution_clock::now();
   double us = std::chrono::duration<double,std::micro>(t1-t0).count();
   mf.RecordComputeTiming("AES_ENC", uav_id, us);
*/

// ============================================================================
// STEP 4 — After Simulator::Run() in main.cc
// ============================================================================
/*
   REPLACE:
     csv_mgr.ExportAll(duration);

   WITH:
     mf.Finalize(duration, run_index);
     mf.ExportAll();

   The above writes ALL CSV files covering all 5 metric categories to OUTPUT_DIR.
*/

// ============================================================================
// CONVENIENCE: Minimal scheduled swarm snapshot callback
// ============================================================================
/*
   Add this function before main() in main.cc:

   static void SwarmSnapshotCallback(
       uav::metrics::MetricsFramework*    mf,
       uav::apps::JammerManager*          jam_mgr,
       uav::apps::CompromiseDetector*     comp_mgr,
       uint32_t                           total_uavs)
   {
       uint32_t jammed      = jam_mgr  ? jam_mgr->GetJammedCount()      : 0;
       uint32_t compromised = comp_mgr ? comp_mgr->GetCompromisedCount() : 0;
       uint32_t disconnected = 0;
       uint32_t active = total_uavs - jammed - compromised - disconnected;

       // Simple connectivity estimate: fully connected minus jammed
       uint32_t connected_pairs =
           (active * (active - 1)) / 2;

       mf->RecordSwarmSnapshot(
           active, jammed, compromised, disconnected, connected_pairs);

       ns3::Simulator::Schedule(
           ns3::Seconds(5.0),
           &SwarmSnapshotCallback, mf, jam_mgr, comp_mgr, total_uavs);
   }

   And schedule it at t=5s:
   Simulator::Schedule(Seconds(5.0), &SwarmSnapshotCallback,
       &mf, &jammer_mgr, &comp_detector, 18u);
*/

// ============================================================================
// COMPLETE LIST OF CSV OUTPUT FILES produced by MetricsFramework::ExportAll()
// ============================================================================
/*
   output/
   ├── metrics_network.csv          ← A: PDR, throughput, delay, loss, stability
   ├── metrics_security.csv         ← B: key estab, rekey, auth, secrecy summary
   ├── metrics_overhead.csv         ← C: comm/compute/storage overhead
   ├── metrics_denied.csv           ← D: SINR, jamming, recovery, link failures
   ├── metrics_mobility.csv         ← E: CH stability, route breaks, survivability
   ├── metrics_full_report.csv      ← ALL categories, category,metric,value
   ├── metrics_per_uav.csv          ← per-UAV: PDR, tput, delay, loss
   ├── metrics_per_cluster.csv      ← per-cluster: PDR, tput, delay, rekeys, CH
   ├── timeseries.csv               ← 1s snapshots: PDR, delay, SINR, rekeys, ...
   ├── rekey_latency_full.csv       ← every rekey event with trigger+cost
   ├── auth_log.csv                 ← every auth attempt
   ├── secrecy_checks.csv           ← forward/backward secrecy per TEK rotation
   ├── replay_log.csv               ← every replay detection event
   ├── healing_log.csv              ← compromise/disconnect recovery events
   ├── compute_timings.csv          ← AES/HMAC/CRT wall-clock times
   ├── sinr_log.csv                 ← per-UAV SINR samples over time
   ├── link_failures.csv            ← link failure events with cause+duration
   ├── route_breaks.csv             ← OLSR route break events
   ├── swarm_survivability.csv      ← 5s survivability snapshots
   └── cluster_head_stability.csv   ← per-cluster SKDC reachability log
*/
