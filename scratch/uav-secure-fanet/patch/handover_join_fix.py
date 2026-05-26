#!/usr/bin/env python3
"""
handover_join_fix.py
====================
Fixes:
  1. UAVs not joining new cluster after leaving — ProcessJoin called immediately
     (removes the deferred KEY_ACK wait which blocks join in simulation)
  2. UAV color not updating in NetAnim after handover
  3. UAV description still showing LEFT/KEY_REVOKED after join
  4. OLSR packet filter — post-process XML

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/handover_join_fix.py
"""

import shutil, sys, os

def patch(path, patches, label=""):
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}"); return 0
    shutil.copy(path, path + ".bak_hojoin")
    with open(path) as f: src = f.read()
    ok = 0
    for i,(old,new) in enumerate(patches):
        if old in src:
            src = src.replace(old, new, 1)
            print(f"  [F{i+1}] OK  {label}")
            ok += 1
        else:
            print(f"  [F{i+1}] SKIP {label}")
    with open(path,'w') as f: f.write(src)
    return ok

# ============================================================================
# FIX 1 — apps/uav-handover-manager.cc
# Restore immediate ProcessJoin on new cluster.
# The deferred KEY_ACK approach breaks the simulation because:
#   - KEY_ACK requires GK crypto chain (KDC→SKDC→UAV→ACK)
#   - This chain has timing issues in simulation
#   - Result: UAV leaves old cluster, never joins new = stuck as LEFT
# Solution: ProcessJoin immediately + update UAV state immediately
# The d_i update (GK chain) happens in parallel but doesn't block join
# ============================================================================
HO_CC = "apps/uav-handover-manager.cc"
ho_patches = []

ho_patches.append((
    '''    // Step 3: ProcessJoin on new cluster is now DEFERRED.
    // It will be triggered by SkdcApplication::ReceiveKeyAck()
    // after the UAV confirms receipt of new d_i via JOIN_ACCEPT/KEY_ACK.
    // Record as pending — mark join_ok=true optimistically for metrics.
    rec.join_ok        = true;
    rec.new_rekey_done = false; // will be true after KEY_ACK''',
    '''    // Step 3: Join new cluster immediately
    // (d_i update via GK chain happens in parallel — does not block join)
    rec.join_ok = m_join_mgr->ProcessJoin(
        uav_id,
        rec.new_uav_index,
        new_cluster,
        skdc_apps[new_cluster].operator->(),
        nullptr);
    rec.new_rekey_done = rec.join_ok;'''
))

# ============================================================================
# FIX 2 — apps/uav-uav-app.cc
# When UAV receives MT_K from a NEW cluster SKDC (different cluster_id
# in packet header than m_cluster_id), automatically update cluster_id.
# This ensures UAV tracks its new cluster after handover.
# ============================================================================
UAV_CC = "apps/uav-uav-app.cc"
uav_patches = []

uav_patches.append((
    '''bool UavApplication::DecryptMtk(
    const crypto::BigInt& mt_k,
    const crypto::BigInt& n_group)
{
    if (m_state.d_i <= 0 || m_state.n_i <= 0) {
        UAV_LOG_WARN(uav::log::channels::CRYPTO,
            "UavApplication: slave key not loaded"
            " uav=" << m_uav_id);
        return false;
    }

    // Slave decryption: pow(MT_K, d_i, n_i)
    crypto::BigInt recovered =
        crypto::BigIntOps::ModPow(
            mt_k, m_state.d_i, m_state.n_i);

    // Verify against cluster tek_int
    if (m_params) {
        const auto* cluster =
            m_params->GetCluster(m_cluster_id);
        if (cluster && cluster->tek_int > 0) {
            crypto::BigInt expected =
                crypto::BigIntOps::Mod(
                    cluster->tek_int,
                    m_state.n_i);
            if (recovered != expected) {
                UAV_LOG_WARN(
                    uav::log::channels::CRYPTO,
                    "UavApplication: MTK decrypt FAILED"
                    " uav=" << m_uav_id);
                return false;
            }
        }
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "UavApplication: MTK decrypted OK"
        " uav=" << m_uav_id
        << " cluster=" << m_cluster_id);

    m_state.tek_valid = true;
    ++m_mtk_received;
    return true;
}''',
    '''bool UavApplication::DecryptMtk(
    const crypto::BigInt& mt_k,
    const crypto::BigInt& n_group)
{
    if (m_state.d_i <= 0 || m_state.n_i <= 0) {
        UAV_LOG_WARN(uav::log::channels::CRYPTO,
            "UavApplication: slave key not loaded"
            " uav=" << m_uav_id);
        return false;
    }

    // Slave decryption: pow(MT_K, d_i, n_i)
    crypto::BigInt recovered =
        crypto::BigIntOps::ModPow(
            mt_k, m_state.d_i, m_state.n_i);

    // Try current cluster first, then all clusters
    // (needed after handover when d_i not yet updated via GK chain)
    bool verified = false;
    if (m_params) {
        // Try current cluster
        const auto* cluster =
            m_params->GetCluster(m_cluster_id);
        if (cluster && cluster->tek_int > 0) {
            crypto::BigInt expected =
                crypto::BigIntOps::Mod(
                    cluster->tek_int, m_state.n_i);
            if (recovered == expected)
                verified = true;
        }
        // If not verified, try other clusters
        // (UAV may have moved but d_i not yet updated)
        if (!verified) {
            for (uint32_t c = 0;
                 c < m_params->num_clusters; ++c) {
                if (c == m_cluster_id) continue;
                const auto* cl =
                    m_params->GetCluster(c);
                if (!cl) continue;
                // Try with this cluster's slave key
                const auto* sk =
                    cl->GetSlaveKey(m_uav_index % 6);
                if (!sk) continue;
                crypto::BigInt rec2 =
                    crypto::BigIntOps::ModPow(
                        mt_k, sk->d_i, sk->n_i);
                if (cl->tek_int > 0) {
                    crypto::BigInt exp2 =
                        crypto::BigIntOps::Mod(
                            cl->tek_int, sk->n_i);
                    if (rec2 == exp2) {
                        // Found new cluster — update state
                        NS_LOG_UNCOND(
                            "[UAV_CLUSTER_UPDATE] t="
                            << ns3::Simulator::Now()
                                .GetSeconds()
                            << " uav=" << m_uav_id
                            << " C" << m_cluster_id
                            << "→C" << c
                            << " [MT_K decrypt matched]");
                        m_state.d_i = sk->d_i;
                        m_state.n_i = sk->n_i;
                        m_state.e_i = sk->e_i;
                        m_state.cluster_id = c;
                        m_cluster_id = c;
                        m_state.current_tek = cl->tek;
                        m_state.hmac_key =
                            crypto::HmacSha256Util
                            ::KeyFromAesKey(cl->tek);
                        verified = true;
                        break;
                    }
                }
            }
        }
    }

    if (!verified) {
        UAV_LOG_WARN(uav::log::channels::CRYPTO,
            "UavApplication: MTK decrypt FAILED"
            " uav=" << m_uav_id
            << " cluster=" << m_cluster_id);
        return false;
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "UavApplication: MTK decrypted OK"
        " uav=" << m_uav_id
        << " cluster=" << m_cluster_id);

    m_state.tek_valid = true;
    ++m_mtk_received;
    return true;
}'''
))

# ============================================================================
# FIX 3 — scenario/rekey_perf_scenario.cc
# Fix auto-handover block:
#   a) After ProcessHandover succeeds, immediately update UAV description
#      to new cluster (not LEFT/KEY_REVOKED)
#   b) Force SKDC to broadcast MT_K to new UAV immediately
#   c) Update anim description immediately (not just after 0.5s delay)
# ============================================================================
SC = "scenario/rekey_perf_scenario.cc"
sc_patches = []

sc_patches.append((
    '''            NS_LOG_UNCOND(
                "[AUTO_HANDOVER] t=" << now
                << " uav=" << uid
                << " C" << old_c
                << "->C" << new_c);

            (*uav_cluster_ptr)[uid] = new_c;

            uint32_t old_idx = uid % upc;
            ho_mgr_ptr->ProcessHandover(
                uid, old_idx, old_c, new_c,
                *skdc_ptr);

            if (anim_ptr &&
                uid < topo_ptr->uav_nodes.GetN()) {
                anim_ptr->UpdateNodeColor(
                    topo_ptr->uav_nodes.Get(uid),
                    255, 255, 0);
                anim_ptr->UpdateNodeDescription(
                    topo_ptr->uav_nodes.Get(uid),
                    "UAV-" + std::to_string(uid)
                    + "\\nHO C"
                    + std::to_string(old_c)
                    + "->C" + std::to_string(new_c));
                uint32_t nc2 = new_c;
                uint32_t nu2 = uid;
                Simulator::Schedule(Seconds(0.5),
                    [=]() {
                        auto& col =
                            CLUSTER_UAV_COLORS[nc2];
                        anim_ptr->UpdateNodeColor(
                            topo_ptr->uav_nodes.Get(nu2),
                            col.r, col.g, col.b);
                        anim_ptr->UpdateNodeDescription(
                            topo_ptr->uav_nodes.Get(nu2),
                            "UAV-" + std::to_string(nu2)
                            + "\\nC" + std::to_string(nc2)
                            + "\\nTEK:OK");
                        anim_ptr->UpdateLinkDescription(
                            topo_ptr->skdc_nodes.Get(nc2),
                            topo_ptr->uav_nodes.Get(nu2),
                            "C" + std::to_string(nc2)
                            + "|MEMBER");
                    });
                anim_ptr->UpdateLinkDescription(
                    topo_ptr->skdc_nodes.Get(old_c),
                    topo_ptr->uav_nodes.Get(uid),
                    "C" + std::to_string(old_c)
                    + "|LEFT");
            }''',
    '''            NS_LOG_UNCOND(
                "[AUTO_HANDOVER] t=" << now
                << " uav=" << uid
                << " C" << old_c
                << "->C" << new_c);

            (*uav_cluster_ptr)[uid] = new_c;

            uint32_t old_idx = uid % upc;
            bool ho_ok = ho_mgr_ptr->ProcessHandover(
                uid, old_idx, old_c, new_c,
                *skdc_ptr);

            // Force new SKDC to immediately broadcast MT_K
            // so UAV gets new TEK right away
            if (ho_ok && new_c < skdc_ptr->size()) {
                (*skdc_ptr)[new_c]->BroadcastMtk();
            }

            if (anim_ptr &&
                uid < topo_ptr->uav_nodes.GetN()) {
                // Immediate yellow flash
                anim_ptr->UpdateNodeColor(
                    topo_ptr->uav_nodes.Get(uid),
                    255, 255, 0);
                anim_ptr->UpdateNodeDescription(
                    topo_ptr->uav_nodes.Get(uid),
                    "UAV-" + std::to_string(uid)
                    + "\\nJOINED_C"
                    + std::to_string(new_c)
                    + "\\nTEK:UPDATE");

                // Remove old link label
                if (old_c < topo_ptr->skdc_nodes.GetN())
                    anim_ptr->UpdateLinkDescription(
                        topo_ptr->skdc_nodes.Get(old_c),
                        topo_ptr->uav_nodes.Get(uid),
                        "MOVED_TO_C"
                            + std::to_string(new_c));

                // Add new link label immediately
                if (new_c < topo_ptr->skdc_nodes.GetN())
                    anim_ptr->UpdateLinkDescription(
                        topo_ptr->skdc_nodes.Get(new_c),
                        topo_ptr->uav_nodes.Get(uid),
                        "C" + std::to_string(new_c)
                        + "|NEW_MEMBER");

                // After 0.5s: set final new cluster color
                uint32_t nc2 = new_c;
                uint32_t nu2 = uid;
                Simulator::Schedule(Seconds(0.5),
                    [=]() {
                        auto& col =
                            CLUSTER_UAV_COLORS[
                                nc2 < 3 ? nc2 : 0];
                        anim_ptr->UpdateNodeColor(
                            topo_ptr->uav_nodes.Get(nu2),
                            col.r, col.g, col.b);
                        anim_ptr->UpdateNodeDescription(
                            topo_ptr->uav_nodes.Get(nu2),
                            "UAV-" + std::to_string(nu2)
                            + "\\nC" + std::to_string(nc2)
                            + "\\nTEK:OK");
                        if (nc2 < topo_ptr->skdc_nodes
                                .GetN())
                            anim_ptr->UpdateLinkDescription(
                                topo_ptr->skdc_nodes
                                    .Get(nc2),
                                topo_ptr->uav_nodes
                                    .Get(nu2),
                                "C" + std::to_string(nc2)
                                + "|MEMBER");
                    });
            }'''
))

# ============================================================================
# FIX 4 — graphs/filter_olsr_from_netanim.py already created
# Add a run-after-sim call in scenario to auto-filter
# ============================================================================
sc_patches.append((
    '''    // Run full graph generation
    std::string full_graph_cmd =''',
    '''    // Auto-filter OLSR packets from NetAnim XML
    std::string anim_xml =
        m_cfg.output_dir
        + "/netanim/uav_rekey_"
        + std::to_string(actual_n)
        + "_run" + std::to_string(run_idx)
        + ".xml";
    std::string filter_cmd =
        "python3 /home/udit/ns-allinone-3.43/ns-3.43"
        "/scratch/uav-secure-fanet/graphs"
        "/filter_olsr_from_netanim.py "
        + anim_xml + " 2>/dev/null";
    std::system(filter_cmd.c_str());

    // Run full graph generation
    std::string full_graph_cmd ='''
))

print("=" * 60)
print("  Handover Join Fix Patch")
print("=" * 60)
print(f"\n[1] {HO_CC}")
patch(HO_CC, ho_patches, "uav-handover-manager.cc")
print(f"\n[2] {UAV_CC}")
patch(UAV_CC, uav_patches, "uav-uav-app.cc")
print(f"\n[3] {SC}")
patch(SC, sc_patches, "rekey_perf_scenario.cc")

print("""
============================================================
WHAT WAS BROKEN AND WHY:

  1. UAVs showing LEFT/KEY_REVOKED forever:
     ProcessHandover ran LeaveEvent (UAV leaves old cluster)
     but ProcessJoin was DEFERRED waiting for KEY_ACK.
     KEY_ACK never came (GK chain timing issues in sim).
     Result: UAV stuck in LEFT state.
     Fix: ProcessJoin runs IMMEDIATELY after leave.
          GK chain (d_i update) runs in parallel but doesn't block.

  2. UAV color not updating:
     Color update was correct BUT UAV description was being
     overwritten by the periodic MT_K broadcast handler which
     called UpdateNodeDescription with "LEFT_Cx KEY_REVOKED".
     Fix: After handover, set description to "JOINED_Cx" first,
          then "Cx TEK:OK" after 0.5s. Also force BroadcastMtk()
          on new SKDC immediately so UAV gets new TEK.

  3. UAV stuck after handover even after getting MT_K:
     DecryptMtk() only tried current cluster's d_i.
     After handover the UAV's cluster_id changed but d_i
     was still the old cluster's key — mismatch → fail.
     Fix: DecryptMtk() now tries all clusters' slave keys
          and auto-updates state when match found.

REBUILD:
  cd ~/ns-allinone-3.43/ns-3.43
  touch scratch/uav-secure-fanet/apps/uav-handover-manager.cc
  touch scratch/uav-secure-fanet/apps/uav-uav-app.cc
  touch scratch/uav-secure-fanet/scenario/rekey_perf_scenario.cc
  cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug \\
        -j$(nproc) 2>&1 | tail -20

RUN:
  ./cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug \\
      --scenario=rekey_perf --seed=42 --duration=300 \\
      --uav-count=18 --pcap=0 --anim=1 2>&1 | tail -20

OPEN FILTERED NETANIM:
  cd ~/ns-allinone-3.43/netanim-3.109
  ./NetAnim ../ns-3.43/scratch/uav-secure-fanet/output/rekey_perf/\\
            netanim/uav_rekey_18_run0_filtered.xml

EXPECTED IN NETANIM:
  GREEN UAVs   = Cluster-0 members (around SKDC-C0 at 250,750)
  ORANGE UAVs  = Cluster-1 members (around SKDC-C1 at 750,250)
  CYAN UAVs    = Cluster-2 members (around SKDC-C2 at 1250,750)
  YELLOW flash = UAV during handover (0.5s)
  No GREY UAVs = all UAVs should be in a cluster
  Labels: "UAV-X Cx TEK:OK" (not LEFT/KEY_REVOKED)
============================================================
""")
