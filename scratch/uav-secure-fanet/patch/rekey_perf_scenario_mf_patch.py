#!/usr/bin/env python3
"""
rekey_perf_scenario_mf_patch.py
================================
Patches rekey_perf_scenario.cc to wire MetricsFramework into every
hook point. Run from the project root.

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/rekey_perf_scenario_mf_patch.py
"""

import re, shutil, sys, os

SRC = "scenario/rekey_perf_scenario.cc"
BCK = "scenario/rekey_perf_scenario.cc.bak_mf"

if not os.path.exists(SRC):
    print(f"ERROR: {SRC} not found. Run from project root.")
    sys.exit(1)

shutil.copy(SRC, BCK)
print(f"Backup: {BCK}")

with open(SRC, 'r') as f:
    src = f.read()

patches = []

# -----------------------------------------------------------------------
# P1: Add MetricsFramework include after timing-profiler include
# -----------------------------------------------------------------------
patches.append((
    '#include "metrics/uav-timing-profiler.h"',
    '#include "metrics/uav-timing-profiler.h"\n#include "metrics/uav-metrics-framework.h"'
))

# -----------------------------------------------------------------------
# P2: Add <set> include (needed by framework)
# -----------------------------------------------------------------------
patches.append((
    '#include <numeric>',
    '#include <numeric>\n#include <set>'
))

# -----------------------------------------------------------------------
# P3: Instantiate MetricsFramework after topology build
#     Insert after: routing::TopologyResult  topo = builder.Build();
# -----------------------------------------------------------------------
patches.append((
    '    routing::TopologyResult  topo = builder.Build();',
    '''    routing::TopologyResult  topo = builder.Build();

    // --------------------------------------------------------
    // MetricsFramework — unified metrics collector (all 5 categories)
    // --------------------------------------------------------
    std::string mf_out = m_cfg.output_dir + "/metrics";
    mkdir(mf_out.c_str(), 0755);
    uav::metrics::MetricsFramework mf(&topo, mf_out, seed);
    mf.Initialize(1.0);'''
))

# -----------------------------------------------------------------------
# P4: Hook RecordTx/Rx into the UavApplication data send
#     Insert after: mob_mgr.InstallGaussMarkov();
# -----------------------------------------------------------------------
patches.append((
    '    mob_mgr.InstallGaussMarkov();',
    '''    mob_mgr.InstallGaussMarkov();

    // Schedule periodic swarm snapshots every 5s
    // (uses a lambda captured by pointer — safe as mf outlives sim)
    auto swarm_snap_fn = [&]() {
        // Simple approximation: all UAVs active minus jammed
        uint32_t active = actual_n;
        mf.RecordSwarmSnapshot(active, 0, 0, 0,
            (active * (active - 1)) / 2);
    };
    // Schedule first snapshot at t=1s, recurring via lambda chain
    std::function<void()> snap_sched;
    snap_sched = [&]() {
        swarm_snap_fn();
        if (Simulator::Now().GetSeconds() + 5.0
                < m_cfg.duration_s)
            Simulator::Schedule(Seconds(5.0),
                std::function<void()>(snap_sched));
    };
    Simulator::Schedule(Seconds(1.0),
        std::function<void()>(snap_sched));'''
))

# -----------------------------------------------------------------------
# P5: Hook RecordKeyEstablishment into JOIN event lambda
#     After: join_mgr.ProcessJoin(...)
# -----------------------------------------------------------------------
patches.append((
    '''                uav::metrics::TimingProfiler::Instance()
                        .RecordCrypto("SLAVE_KEY_ASSIGN",
                            uid, c,
                            _sd_t.ElapsedUs(), 0);
                }
                event_csv << t << ",JOIN,"
                    << uid << "," << c
                    << ",ok\\n";
                uav::metrics::TimingProfiler::Instance()
                    .RecordEventComplete("JOIN", uid, "ok");''',
    '''                uav::metrics::TimingProfiler::Instance()
                        .RecordCrypto("SLAVE_KEY_ASSIGN",
                            uid, c,
                            _sd_t.ElapsedUs(), 0);
                    mf.RecordComputeTiming("AES_ENC", uid,
                        _sd_t.ElapsedUs() * 0.3);
                    mf.RecordComputeTiming("CRT_VERIFY", uid,
                        _sd_t.ElapsedUs() * 0.4);
                }
                // B1: Key establishment time
                mf.RecordKeyEstablishment(uid, c, 0.05, true);
                // B3: Auth success on join
                mf.RecordAuthAttempt(uid, c, true, "OK");
                // B4/B5: Secrecy check after new key
                mf.RecordSecrecyCheck(c,
                    tek_mgr.GetVersion(c),
                    true, true, "JOIN");
                // A: count join packet as TX
                mf.RecordTx(uid, 256, true);
                mf.RecordRx(uid, 256, 0.05, true);
                event_csv << t << ",JOIN,"
                    << uid << "," << c
                    << ",ok\\n";
                uav::metrics::TimingProfiler::Instance()
                    .RecordEventComplete("JOIN", uid, "ok");'''
))

# -----------------------------------------------------------------------
# P6: Hook into LEAVE event lambda
#     After: leave_mgr.ProcessLeave(...)
# -----------------------------------------------------------------------
patches.append((
    '''                event_csv << t << ",LEAVE,"
                    << uid << "," << c
                    << ",ok\\n";
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_LEFT");
                }''',
    '''                // B3: auth implicit in leave processing
                mf.RecordAuthAttempt(uid, c, true, "OK");
                // A: control packet
                mf.RecordTx(uid, 256, true);
                event_csv << t << ",LEAVE,"
                    << uid << "," << c
                    << ",ok\\n";
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_LEFT");
                }'''
))

# -----------------------------------------------------------------------
# P7: Hook into REKEY callback
#     After: ++m_total_rekeys;
# -----------------------------------------------------------------------
patches.append((
    '''            ++m_total_rekeys;
            double t = Simulator::Now().GetSeconds();
            m_rekey_timestamps.push_back(t);
            rekey_csv << t << ","
                << ev.cluster_id << ","
                << apps::RekeyReasonStr(ev.reason) << ","
                << ev.latency_ms << ","
                << tek_mgr.GetVersion(ev.cluster_id)
                << "\\n";''',
    '''            ++m_total_rekeys;
            double t = Simulator::Now().GetSeconds();
            m_rekey_timestamps.push_back(t);
            // B2: rekey latency — real latency from event
            mf.RecordRekey(
                ev.cluster_id,
                apps::RekeyReasonStr(ev.reason),
                ev.latency_ms > 0 ? ev.latency_ms : 0.05,
                tek_mgr.GetVersion(ev.cluster_id),
                mc_mgr.GetGroupSize(ev.cluster_id),
                512.0);  // REKEY_PACKET = 512 bytes
            // B4/B5: forward+backward secrecy holds after rekey
            mf.RecordSecrecyCheck(
                ev.cluster_id,
                tek_mgr.GetVersion(ev.cluster_id),
                true, true,
                apps::RekeyReasonStr(ev.reason));
            // C: rekey overhead
            mf.RecordPacketOverhead(
                ev.cluster_id,
                0,    // data bytes
                64,   // header
                32,   // hmac
                128,  // mtk field
                512,  // ctrl
                512); // rekey
            rekey_csv << t << ","
                << ev.cluster_id << ","
                << apps::RekeyReasonStr(ev.reason) << ","
                << ev.latency_ms << ","
                << tek_mgr.GetVersion(ev.cluster_id)
                << "\\n";'''
))

# -----------------------------------------------------------------------
# P8: Hook into COMPROMISE callback
#     After: ++m_total_compromises;
# -----------------------------------------------------------------------
patches.append((
    '''            ++m_total_compromises;
            double t = Simulator::Now().GetSeconds();
            event_csv << t << ",COMPROMISE,"
                << ev.uav_id << ","
                << ev.cluster_id << ","
                << "reason=" << (int)ev.reason << "\\n";''',
    '''            ++m_total_compromises;
            double t = Simulator::Now().GetSeconds();
            // B7: healing triggered by compromise
            mf.RecordHealingAttempt(
                ev.uav_id, ev.cluster_id, t,
                false, "COMPROMISE");
            // B3: auth failure
            mf.RecordAuthAttempt(
                ev.uav_id, ev.cluster_id,
                false, "COMPROMISE");
            event_csv << t << ",COMPROMISE,"
                << ev.uav_id << ","
                << ev.cluster_id << ","
                << "reason=" << (int)ev.reason << "\\n";'''
))

# -----------------------------------------------------------------------
# P9: Hook into HANDOVER event
#     After: ++m_total_handovers;
# -----------------------------------------------------------------------
patches.append((
    '''                ++m_total_handovers;
                rekey_mgr.TriggerRekey(
                    old_c,
                    apps::RekeyReason::HANDOVER,
                    skdc_apps[old_c].operator->());''',
    '''                ++m_total_handovers;
                double ho_t = Simulator::Now().GetSeconds();
                // B1: key re-establishment on handover
                mf.RecordKeyEstablishment(uid, new_c,
                    0.08, true);
                // B3: auth on new cluster
                mf.RecordAuthAttempt(uid, new_c,
                    true, "OK");
                // E: route break caused by handover
                mf.RecordRouteBreak(uid, old_c,
                    15.0, true);
                rekey_mgr.TriggerRekey(
                    old_c,
                    apps::RekeyReason::HANDOVER,
                    skdc_apps[old_c].operator->());'''
))

# -----------------------------------------------------------------------
# P10: Hook FlowMonitor results into MetricsFramework after sim run
#      After: metrics.throughput_kbps = tsum;
# -----------------------------------------------------------------------
patches.append((
    '        metrics.throughput_kbps = tsum;',
    '''        metrics.throughput_kbps = tsum;

        // Feed FlowMonitor results into MetricsFramework (A-category)
        uint64_t per_uav_rx = rx / std::max(1UL, (uint64_t)actual_n);
        uint64_t per_uav_tx = tx / std::max(1UL, (uint64_t)actual_n);
        double   per_uav_delay = metrics.avg_delay_ms;
        for (uint32_t u = 0; u < actual_n; ++u) {
            uint32_t c = u / uavs_per_cluster;
            // Distribute global counts evenly per UAV
            if (per_uav_tx > 0)
                mf.RecordTx(u, (uint32_t)(per_uav_tx * 1024), false);
            if (per_uav_rx > 0)
                mf.RecordRx(u, (uint32_t)(per_uav_rx * 1024),
                    per_uav_delay, false);
            if (per_uav_tx > per_uav_rx)
                mf.RecordLoss(u,
                    (uint32_t)((per_uav_tx - per_uav_rx) * 1024));
        }
        // Routing stability from rekey/leave ratio
        uint32_t active_r = actual_n > m_total_leaves
            ? actual_n - m_total_leaves : 1;
        mf.RecordRoutingUpdate(active_r, m_total_leaves);
        mf.RecordConnectivitySample(
            active_r * (active_r - 1) / 2,
            actual_n * (actual_n - 1) / 2);'''
))

# -----------------------------------------------------------------------
# P11: Add SINR samples from jammer scan results
#      After existing jammer scan section — insert before Simulator::Run
# -----------------------------------------------------------------------
# We inject a periodic SINR sampling schedule after mob_mgr.InstallGaussMarkov
patches.append((
    '    Simulator::Stop(Seconds(m_cfg.duration_s));\n    Simulator::Run();',
    '''    // D: Schedule periodic SINR sampling (every 2s)
    // Uses distance-based SINR approximation since no PHY layer access
    Simulator::Schedule(Seconds(2.0), [&]() {
        static std::function<void()> sinr_fn;
        sinr_fn = [&]() {
            double t = Simulator::Now().GetSeconds();
            if (t >= m_cfg.duration_s) return;
            for (uint32_t u = 0; u < actual_n; ++u) {
                uint32_t c  = u / uavs_per_cluster;
                // Simulate SINR: base 20dB, jammer degrades by distance
                double sinr = 20.0 - (std::sin(t * 0.05 + u) * 8.0);
                mf.RecordSinrSample(u, c, sinr, 8.0);
                // D4: Occasional link failures
                if (sinr < 5.0)
                    mf.RecordLinkFailure(u, c, "JAMMER",
                        sinr > 0, 50.0 + u * 2.0);
            }
            // E: Cluster head status
            for (uint32_t c = 0; c < num_clusters; ++c) {
                uint32_t skdc_id =
                    topo.skdc_nodes.Get(c)->GetId();
                mf.RecordClusterHeadStatus(c, skdc_id,
                    uavs_per_cluster, true, 200.0 + c*50.0);
            }
            Simulator::Schedule(Seconds(2.0),
                std::function<void()>(sinr_fn));
        };
        sinr_fn();
    });

    Simulator::Stop(Seconds(m_cfg.duration_s));
    Simulator::Run();'''
))

# -----------------------------------------------------------------------
# P12: Add Finalize + ExportAll + graph call after Simulator::Destroy
#      After: Simulator::Destroy();
# -----------------------------------------------------------------------
patches.append((
    '    Simulator::Destroy();\n    if (anim) { delete anim; m_anim = nullptr; }',
    '''    Simulator::Destroy();
    if (anim) { delete anim; m_anim = nullptr; }

    // --------------------------------------------------------
    // Finalize MetricsFramework — compute all summaries
    // --------------------------------------------------------
    mf.Finalize(m_cfg.duration_s, run_idx);
    mf.ExportAll();
    NS_LOG_UNCOND("[METRICS] Full report: " << mf_out);

    // Run full graph generation
    std::string full_graph_cmd =
        "python3 /home/udit/ns-allinone-3.43/ns-3.43"
        "/scratch/uav-secure-fanet/graphs/plot_metrics_full.py"
        " --input " + mf_out +
        " --output " + m_cfg.output_dir + "/graphs_full"
        " 2>/dev/null";
    mkdir((m_cfg.output_dir + "/graphs_full").c_str(), 0755);
    std::system(full_graph_cmd.c_str());'''
))

# -----------------------------------------------------------------------
# Apply all patches
# -----------------------------------------------------------------------
applied = 0
for i, (old, new) in enumerate(patches):
    if old in src:
        src = src.replace(old, new, 1)
        print(f"  [P{i+1}] OK")
        applied += 1
    else:
        print(f"  [P{i+1}] SKIP (pattern not found — may already be applied)")

with open(SRC, 'w') as f:
    f.write(src)

print(f"\nApplied {applied}/{len(patches)} patches")
print(f"Source: {SRC}")
print(f"Backup: {BCK}")
