#!/usr/bin/env python3
"""
netanim_visual_patch.py
========================
Patches rekey_perf_scenario.cc to add:

  1. Visible UAV→SKDC connection lines at initialization
     (persistent link labels showing which UAV belongs to which SKDC)

  2. DATA packet transmission visualization
     (link label flashes when UAV sends data to SKDC)

  3. UAV color changes to new cluster color on handover
     (already partially implemented — this ensures it fires correctly
      from the scenario's handover event, not just the enhancer)

  4. Periodic connection line refresh
     (every 10s, redraws SKDC→UAV association lines so they
      remain visible as UAVs move)

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/netanim_visual_patch.py
"""

import shutil, sys, os

SRC = "scenario/rekey_perf_scenario.cc"
BCK = SRC + ".bak_visual"

if not os.path.exists(SRC):
    print(f"ERROR: {SRC} not found. Run from project root.")
    sys.exit(1)

shutil.copy(SRC, BCK)
print(f"Backup: {BCK}")

with open(SRC, 'r') as f:
    src = f.read()

patches = []

# -----------------------------------------------------------------------
# P1: After UAV node color setup in NetAnim initialization block,
#     add persistent SKDC→UAV connection lines with cluster-color labels
# -----------------------------------------------------------------------
patches.append((
    '''        // UAVs — cluster color
        for (uint32_t i = 0;
             i < topo.uav_nodes.GetN(); ++i) {
            uint32_t c = i / uavs_per_cluster;
            auto& col  = CLUSTER_COLORS[
                std::min(c, 2u)];
            anim->UpdateNodeColor(
                topo.uav_nodes.Get(i),
                col.r, col.g, col.b);
            anim->UpdateNodeDescription(
                topo.uav_nodes.Get(i),
                "UAV" + std::to_string(i)
                + "_C" + std::to_string(c));
        }
        m_anim = anim;''',
    '''        // UAVs — cluster color + connection lines to SKDC
        for (uint32_t i = 0;
             i < topo.uav_nodes.GetN(); ++i) {
            uint32_t c = i / uavs_per_cluster;
            auto& col  = CLUSTER_COLORS[
                std::min(c, 2u)];
            anim->UpdateNodeColor(
                topo.uav_nodes.Get(i),
                col.r, col.g, col.b);
            anim->UpdateNodeDescription(
                topo.uav_nodes.Get(i),
                "UAV-" + std::to_string(i)
                + "\\nC" + std::to_string(c)
                + "\\nTEK:OK");
            // ── Persistent connection line: UAV → SKDC ──
            // Shows cluster membership visually in NetAnim
            if (c < topo.skdc_nodes.GetN()) {
                anim->UpdateLinkDescription(
                    topo.skdc_nodes.Get(c),
                    topo.uav_nodes.Get(i),
                    "C" + std::to_string(c)
                    + "|MEMBER");
            }
        }
        m_anim = anim;

        // ── Periodic connection line refresh (every 10s) ──
        // Redraws association lines so they stay visible as UAVs move
        Simulator::Schedule(Seconds(10.0),
            std::function<void()>([&, anim]() {
                static std::function<void()> refresh_fn;
                refresh_fn = [&, anim]() {
                    if (!anim) return;
                    double now =
                        Simulator::Now().GetSeconds();
                    for (uint32_t i = 0;
                         i < topo.uav_nodes.GetN();
                         ++i) {
                        uint32_t c =
                            i / uavs_per_cluster;
                        if (c >=
                            topo.skdc_nodes.GetN())
                            continue;
                        anim->UpdateLinkDescription(
                            topo.skdc_nodes.Get(c),
                            topo.uav_nodes.Get(i),
                            "C" + std::to_string(c)
                            + "|t="
                            + std::to_string(
                                (int)now));
                    }
                    if (now + 10.0 < m_cfg.duration_s)
                        Simulator::Schedule(
                            Seconds(10.0),
                            std::function<void()>(
                                refresh_fn));
                };
                refresh_fn();
            }));'''
))

# -----------------------------------------------------------------------
# P2: Add DATA packet visualization in the DATA_RX callback
#     After the existing DATA_RX NS_LOG_UNCOND, animate the link
# -----------------------------------------------------------------------
patches.append((
    '''        NS_LOG_UNCOND("[DATA_RX] t=" << t
            << "s cluster=" << m_cluster_id
            << " size=" << sz << "B"
            << " from=" << src_ip
            << " total_rx=" << m_data_rx_count);''',
    '''        NS_LOG_UNCOND("[DATA_RX] t=" << t
            << "s cluster=" << m_cluster_id
            << " size=" << sz << "B"
            << " from=" << src_ip
            << " total_rx=" << m_data_rx_count);

        // ── NetAnim: animate DATA packet on SKDC→UAV link ──
        // Find UAV index from src_ip (10.1.1.x where x=4..21)
        // UAV WiFi IPs: 10.1.1.4 to 10.1.1.21
        // (SKDC0=.1, SKDC1=.2, SKDC2=.3, UAV0=.4 ... UAV17=.21)
        if (m_anim_ptr) {
            // Extract last octet to get UAV index
            uint32_t ip_int =
                src_ip.Get(); // host byte order
            uint32_t last_octet = ip_int & 0xFF;
            // last_octet: SKDC=1,2,3 → UAV=4..21
            if (last_octet >= 4) {
                uint32_t uid = last_octet - 4;
                if (uid < m_topo->uav_nodes.GetN()) {
                    // Flash link: UAV→SKDC data flow
                    m_anim_ptr->UpdateLinkDescription(
                        m_topo->uav_nodes.Get(uid),
                        GetNode(),
                        ">>>DATA>>>"
                        + std::to_string(sz) + "B");
                    // Schedule restore after 0.5s
                    uint32_t cid = m_cluster_id;
                    Simulator::Schedule(
                        Seconds(0.5),
                        [this, uid, cid]() {
                            if (!m_anim_ptr) return;
                            uint32_t upc =
                                m_topo->uav_nodes
                                .GetN() /
                                m_topo->skdc_nodes
                                .GetN();
                            uint32_t c =
                                uid / (upc > 0
                                    ? upc : 6);
                            m_anim_ptr
                                ->UpdateLinkDescription(
                                m_topo->skdc_nodes
                                    .Get(cid),
                                m_topo->uav_nodes
                                    .Get(uid),
                                "C"
                                + std::to_string(c)
                                + "|MEMBER");
                        });
                }
            }
        }'''
))

# -----------------------------------------------------------------------
# P3: Store anim pointer in SKDC app for use in ReceiveDataFromUav
#     Add m_anim_ptr member access — pass anim to SKDC after creation
# -----------------------------------------------------------------------
# We inject the anim pointer set right after SKDC apps are created
patches.append((
    '''    // Initial MTK broadcast + MTokenGen timing
    {
        uav::metrics::ScopeTimer _t;
        dist_mgr.BroadcastAll(skdc_apps);''',
    '''    // Pass anim pointer to SKDC apps for data visualization
    if (anim) {
        for (uint32_t c = 0; c < num_clusters; ++c) {
            skdc_apps[c]->SetAnimPtr(
                anim, &topo,
                uavs_per_cluster);
        }
    }

    // Initial MTK broadcast + MTokenGen timing
    {
        uav::metrics::ScopeTimer _t;
        dist_mgr.BroadcastAll(skdc_apps);'''
))

# -----------------------------------------------------------------------
# P4: Handover — change UAV color to new cluster color immediately
#     (enhance the existing handover event block in scenario)
# -----------------------------------------------------------------------
patches.append((
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeColor(
                        topo.uav_nodes.Get(uid),
                        255, 255, 0); // yellow
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_HANDOVER_C"
                        + std::to_string(old_c)
                        + "→C"
                        + std::to_string(new_c));
                }''',
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    // Step 1: Yellow flash during handover
                    anim->UpdateNodeColor(
                        topo.uav_nodes.Get(uid),
                        255, 255, 0);
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV-" + std::to_string(uid)
                        + "\\nHANDOVER"
                        + "\\nC" + std::to_string(old_c)
                        + "→C" + std::to_string(new_c));

                    // Remove old cluster link label
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(old_c),
                        topo.uav_nodes.Get(uid),
                        "C" + std::to_string(old_c)
                        + "|LEFT");

                    // Step 2: After 0.5s — new cluster color
                    Simulator::Schedule(Seconds(0.5),
                        [=]() {
                            // New cluster color
                            auto& nc =
                                CLUSTER_COLORS[
                                    std::min(new_c,2u)];
                            anim->UpdateNodeColor(
                                topo.uav_nodes.Get(uid),
                                nc.r, nc.g, nc.b);
                            anim->UpdateNodeDescription(
                                topo.uav_nodes.Get(uid),
                                "UAV-" + std::to_string(uid)
                                + "\\nC" + std::to_string(new_c)
                                + "\\nJOINED");
                            // New cluster connection line
                            if (new_c < topo.skdc_nodes
                                    .GetN()) {
                                anim->UpdateLinkDescription(
                                    topo.skdc_nodes
                                        .Get(new_c),
                                    topo.uav_nodes
                                        .Get(uid),
                                    "C"
                                    + std::to_string(new_c)
                                    + "|NEW_MEMBER");
                            }
                        });
                }'''
))

# -----------------------------------------------------------------------
# P5: Add SetAnimPtr method to SkdcApplication header
# -----------------------------------------------------------------------
SKDC_H = "apps/uav-skdc-app.h"

skdc_h_patches = []
skdc_h_patches.append((
    '''    ns3::Ptr<ns3::Socket> m_forward_socket; // forward telemetry to KDC (port 9300)
    ns3::Ipv4Address      m_kdc_csma_addr;  // KDC CSMA address''',
    '''    ns3::Ptr<ns3::Socket> m_forward_socket; // forward telemetry to KDC (port 9300)
    ns3::Ipv4Address      m_kdc_csma_addr;  // KDC CSMA address

    // NetAnim pointer for data packet visualization
    ns3::AnimationInterface*       m_anim_ptr       = nullptr;
    const routing::TopologyResult* m_anim_topo      = nullptr;
    uint32_t                       m_uavs_per_clus  = 6;'''
))

skdc_h_patches.append((
    '    void SetClusterId(utils::u32 cluster_id);',
    '''    void SetClusterId(utils::u32 cluster_id);

    /// Set NetAnim pointer for data packet visualization
    void SetAnimPtr(
        ns3::AnimationInterface*       anim,
        const routing::TopologyResult* topo,
        uint32_t                       uavs_per_cluster) {
        m_anim_ptr      = anim;
        m_anim_topo     = topo;
        m_uavs_per_clus = uavs_per_cluster;
    }'''
))

# Also need AnimationInterface include in skdc header
skdc_h_patches.append((
    '#include "ns3/application.h"',
    '#include "ns3/application.h"\n#include "ns3/netanim-module.h"'
))

# -----------------------------------------------------------------------
# P6: Update ReceiveDataFromUav in skdc-app.cc to use m_anim_ptr
#     (replace the hardcoded m_anim_ptr references)
# -----------------------------------------------------------------------
SKDC_CC = "apps/uav-skdc-app.cc"
skdc_cc_patches = []

skdc_cc_patches.append((
    '        // ── NetAnim: animate DATA packet on SKDC→UAV link ──\n        // Find UAV index from src_ip (10.1.1.x where x=4..21)\n        // UAV WiFi IPs: 10.1.1.4 to 10.1.1.21\n        // (SKDC0=.1, SKDC1=.2, SKDC2=.3, UAV0=.4 ... UAV17=.21)\n        if (m_anim_ptr) {',
    '''        // ── NetAnim: animate DATA packet on SKDC→UAV link ──
        if (m_anim_ptr && m_anim_topo) {'''
))

skdc_cc_patches.append((
    '                    if (uid < m_topo->uav_nodes.GetN()) {',
    '                    if (uid < m_anim_topo->uav_nodes.GetN()) {'
))

skdc_cc_patches.append((
    '                    m_anim_ptr->UpdateLinkDescription(\n                        m_topo->uav_nodes.Get(uid),\n                        GetNode(),\n                        ">>>DATA>>>"\n                        + std::to_string(sz) + "B");',
    '''                    m_anim_ptr->UpdateLinkDescription(
                        m_anim_topo->uav_nodes
                            .Get(uid),
                        GetNode(),
                        ">>>DATA>>>"
                        + std::to_string(sz) + "B");'''
))

skdc_cc_patches.append((
    '                            if (!m_anim_ptr) return;\n                            uint32_t upc =\n                                m_topo->uav_nodes\n                                .GetN() /\n                                m_topo->skdc_nodes\n                                .GetN();\n                            uint32_t c =\n                                uid / (upc > 0\n                                    ? upc : 6);\n                            m_anim_ptr\n                                ->UpdateLinkDescription(\n                                m_topo->skdc_nodes\n                                    .Get(cid),\n                                m_topo->uav_nodes\n                                    .Get(uid),\n                                "C"\n                                + std::to_string(c)\n                                + "|MEMBER");',
    '''                            if (!m_anim_ptr || !m_anim_topo) return;
                            uint32_t upc = m_uavs_per_clus;
                            uint32_t c = uid / (upc > 0 ? upc : 6);
                            m_anim_ptr->UpdateLinkDescription(
                                m_anim_topo->skdc_nodes.Get(cid),
                                m_anim_topo->uav_nodes.Get(uid),
                                "C" + std::to_string(c)
                                + "|MEMBER");'''
))

# -----------------------------------------------------------------------
# APPLY ALL PATCHES
# -----------------------------------------------------------------------
def apply(path, plist, label=""):
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}")
        return
    bck2 = path + ".bak_vis"
    shutil.copy(path, bck2)
    with open(path) as f:
        s = f.read()
    ok = 0
    for i, (old, new) in enumerate(plist):
        if old in s:
            s = s.replace(old, new, 1)
            print(f"  [P{i+1}] OK  {label or path}")
            ok += 1
        else:
            print(f"  [P{i+1}] SKIP {label or path}")
    with open(path, 'w') as f:
        f.write(s)
    print(f"  ({ok}/{len(plist)} applied)")

print("=" * 60)
print("  NetAnim Visual Patch")
print("=" * 60)

print(f"\n[1] {SRC}")
apply(SRC, patches, "rekey_perf_scenario.cc")

print(f"\n[2] {SKDC_H}")
apply(SKDC_H, skdc_h_patches, "uav-skdc-app.h")

print(f"\n[3] {SKDC_CC}")
apply(SKDC_CC, skdc_cc_patches, "uav-skdc-app.cc")

print("""
============================================================
Rebuild:
  cd ~/ns-allinone-3.43/ns-3.43
  touch scratch/uav-secure-fanet/apps/uav-skdc-app.cc
  touch scratch/uav-secure-fanet/apps/uav-skdc-app.h
  touch scratch/uav-secure-fanet/scenario/rekey_perf_scenario.cc
  cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug \\
        -j$(nproc) 2>&1 | tail -20

Run with NetAnim:
  ./cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug \\
      --scenario=rekey_perf --seed=42 --duration=300 --pcap=0 --anim=1

Open NetAnim:
  cd ~/ns-allinone-3.43/netanim-3.109
  ./NetAnim ../ns-3.43/scratch/uav-secure-fanet/output/rekey_perf/netanim/uav_rekey_18_run0.xml

WHAT YOU WILL SEE IN NETANIM:
  Node colors:
    RED node    = KDC
    ORANGE node = SKDC (3 nodes)
    GREEN node  = Cluster-0 UAVs (6 nodes)
    ORANGE node = Cluster-1 UAVs (6 nodes)  [same orange as SKDC — adjust if needed]
    CYAN node   = Cluster-2 UAVs (6 nodes)

  Connection lines (persistent):
    SKDC-0 ↔ UAV 0..5   labeled "C0|MEMBER"
    SKDC-1 ↔ UAV 6..11  labeled "C1|MEMBER"
    SKDC-2 ↔ UAV 12..17 labeled "C2|MEMBER"
    Refreshed every 10s with current sim time

  Data transmission:
    When UAV sends data → link label flashes ">>>DATA>>>144B"
    After 0.5s → restores to "C0|MEMBER"

  Handover:
    UAV turns YELLOW during handover
    After 0.5s → changes to NEW CLUSTER COLOR
    Old SKDC link labeled "C0|LEFT"
    New SKDC link labeled "C1|NEW_MEMBER"

  Rekey broadcast:
    SKDC turns RED briefly
    All member links flash ">>> NEW_MT_K_v2 >>>"
    After 0.3s → restores to "MT_K_v2|AES256"

  Key distribution:
    t=1s: KDC→SKDC links show ">>> TEK_DIST >>>"
    t=2s: SKDC→UAV links show ">>> MT_K >>>"
    t=3s: restores to "MT_K_v1|AES256"

  OLSR filter:
    In NetAnim: Packet Filter → Min Packet Size = 200
    (hides OLSR HELLO/TC, shows only key+data packets)
============================================================
""")
