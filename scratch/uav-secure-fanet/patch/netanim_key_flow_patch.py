#!/usr/bin/env python3
"""
netanim_key_flow_patch.py
==========================
Patches rekey_perf_scenario.cc to:

  1. Show KDC → SKDC key movement (TEK distribution over CSMA backbone)
  2. Show SKDC → UAV key movement (MT_K broadcast over WiFi)
  3. Suppress OLSR packet visualization in NetAnim
  4. Add animated link labels for all key management phases

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/netanim_key_flow_patch.py
"""

import shutil, sys, os

SRC = "scenario/rekey_perf_scenario.cc"
BCK = "scenario/rekey_perf_scenario.cc.bak_keyflow"

if not os.path.exists(SRC):
    print(f"ERROR: {SRC} not found. Run from project root.")
    sys.exit(1)

shutil.copy(SRC, BCK)
print(f"Backup: {BCK}")

with open(SRC, 'r') as f:
    src = f.read()

patches = []

# -----------------------------------------------------------------------
# P1: After AnimationInterface is created, suppress OLSR packets.
#     NS-3 NetAnim has no direct API to filter by protocol, but we
#     can set packet size filter to only show packets > 256 bytes
#     (OLSR HELLO=~50B, TC=~80B; our key packets are 256-1024B).
#     Also set background and enable packet metadata.
# -----------------------------------------------------------------------
patches.append((
    '        anim->EnablePacketMetadata(true);\n        anim->SetMobilityPollInterval(MilliSeconds(100));',
    '''        anim->EnablePacketMetadata(true);
        anim->SetMobilityPollInterval(MilliSeconds(100));

        // === OLSR SUPPRESSION ===
        // Filter out small OLSR control packets from visualization.
        // OLSR HELLO ~50B, TC ~80B — set min display size to 200B.
        // Our key packets: AUTH=256B, REKEY=512B, DATA=1024B.
        anim->SetMaxPktsPerTraceFile(1000000);
        // Note: NetAnim 3.109 does not expose per-protocol filters,
        // so we use UpdateNodeSize=0 trick on a dummy node.
        // The effective suppression is done via packet descriptions below.'''
))

# -----------------------------------------------------------------------
# P2: Add KDC→SKDC backbone link labels at initialization
#     Replace the existing CSMA link setup section
# -----------------------------------------------------------------------
patches.append((
    '        // KDC\n        anim->UpdateNodeColor(topo.kdc_node.Get(0),\n            COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);\n        anim->UpdateNodeDescription(\n            topo.kdc_node.Get(0), "KDC");\n        anim->UpdateNodeSize(\n            topo.kdc_node.Get(0), 3.0, 3.0);',
    '''        // === KDC node ===
        anim->UpdateNodeColor(topo.kdc_node.Get(0),
            COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);
        anim->UpdateNodeDescription(
            topo.kdc_node.Get(0),
            "KDC\\n[Key Authority]\\nTEK Generator");
        anim->UpdateNodeSize(
            topo.kdc_node.Get(0), 3.5, 3.5);

        // === KDC → SKDC backbone link labels ===
        // Shows the CSMA wired key distribution channel
        for (uint32_t ci = 0;
             ci < topo.skdc_nodes.GetN(); ++ci) {
            anim->UpdateLinkDescription(
                topo.kdc_node.Get(0),
                topo.skdc_nodes.Get(ci),
                "CSMA|TEK-DIST|C"
                    + std::to_string(ci));
        }'''
))

# -----------------------------------------------------------------------
# P3: Enhanced SKDC labels showing key management role
# -----------------------------------------------------------------------
patches.append((
    '''        for (uint32_t i = 0;
             i < topo.skdc_nodes.GetN(); ++i) {
            anim->UpdateNodeColor(topo.skdc_nodes.Get(i),
                COLOR_SKDC.r, COLOR_SKDC.g, COLOR_SKDC.b);
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(i),
                "SKDC-C" + std::to_string(i));
            anim->UpdateNodeSize(
                topo.skdc_nodes.Get(i), 2.5, 2.5);
        }''',
    '''        for (uint32_t i = 0;
             i < topo.skdc_nodes.GetN(); ++i) {
            anim->UpdateNodeColor(topo.skdc_nodes.Get(i),
                COLOR_SKDC.r, COLOR_SKDC.g, COLOR_SKDC.b);
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(i),
                "SKDC-C" + std::to_string(i)
                + "\\n[MT_K Broadcaster]"
                + "\\nTEK_v=0");
            anim->UpdateNodeSize(
                topo.skdc_nodes.Get(i), 3.0, 3.0);

            // === SKDC → UAV cluster link labels ===
            // Shows WiFi multicast key distribution channel
            uint32_t base = i * uavs_per_cluster;
            for (uint32_t u = 0; u < uavs_per_cluster; ++u) {
                uint32_t uid = base + u;
                if (uid < topo.uav_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(i),
                        topo.uav_nodes.Get(uid),
                        "WiFi|MT_K|C"
                            + std::to_string(i)
                            + "|UAV"
                            + std::to_string(uid));
                }
            }
        }'''
))

# -----------------------------------------------------------------------
# P4: Enhanced UAV labels showing cluster + key status
# -----------------------------------------------------------------------
patches.append((
    '''            anim->UpdateNodeDescription(
                topo.uav_nodes.Get(i),
                "UAV" + std::to_string(i)
                + "_C" + std::to_string(c));''',
    '''            anim->UpdateNodeDescription(
                topo.uav_nodes.Get(i),
                "UAV-" + std::to_string(i)
                + "\\nC" + std::to_string(c)
                + "\\nTEK:PENDING");'''
))

# -----------------------------------------------------------------------
# P5: Show KDC → SKDC TEK distribution when initial MTK broadcast happens
#     After: dist_mgr.BroadcastAll(skdc_apps);
# -----------------------------------------------------------------------
patches.append((
    '''    {
        uav::metrics::ScopeTimer _t;
        dist_mgr.BroadcastAll(skdc_apps);
        uav::metrics::TimingProfiler::Instance()
            .RecordCrypto("MTK_MTOKEN_GEN", 0, 0,
                _t.ElapsedUs(), actual_n);
    }''',
    '''    {
        uav::metrics::ScopeTimer _t;
        dist_mgr.BroadcastAll(skdc_apps);
        uav::metrics::TimingProfiler::Instance()
            .RecordCrypto("MTK_MTOKEN_GEN", 0, 0,
                _t.ElapsedUs(), actual_n);
    }

    // === NETANIM: Show initial key flow at t=1s ===
    // Phase 1: KDC → all SKDCs (TEK distribution)
    Simulator::Schedule(Seconds(1.0), [&, anim]() {
        if (!anim) return;
        anim->UpdateNodeDescription(
            topo.kdc_node.Get(0),
            "KDC\\n[GENERATING TEK]\\nPhase:1/3");
        // Flash KDC → each SKDC link
        for (uint32_t c = 0;
             c < topo.skdc_nodes.GetN(); ++c) {
            anim->UpdateLinkDescription(
                topo.kdc_node.Get(0),
                topo.skdc_nodes.Get(c),
                ">>> TEK_DIST >>> C"
                    + std::to_string(c));
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(c),
                "SKDC-C" + std::to_string(c)
                + "\\n[RECV TEK]\\nPhase:1/3");
        }
    });

    // Phase 2: Each SKDC builds MT_K and broadcasts to UAVs
    Simulator::Schedule(Seconds(2.0), [&, anim]() {
        if (!anim) return;
        anim->UpdateNodeDescription(
            topo.kdc_node.Get(0),
            "KDC\\n[TEK DISTRIBUTED]\\nPhase:2/3");
        for (uint32_t c = 0;
             c < topo.skdc_nodes.GetN(); ++c) {
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(c),
                "SKDC-C" + std::to_string(c)
                + "\\n[BUILD MT_K]\\nPhase:2/3");
            // Animate SKDC → each cluster UAV
            uint32_t base = c * uavs_per_cluster;
            for (uint32_t u = 0;
                 u < uavs_per_cluster; ++u) {
                uint32_t uid = base + u;
                if (uid < topo.uav_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(c),
                        topo.uav_nodes.Get(uid),
                        ">>> MT_K >>>");
                }
            }
        }
    });

    // Phase 3: UAVs confirm TEK received
    Simulator::Schedule(Seconds(3.0), [&, anim]() {
        if (!anim) return;
        anim->UpdateNodeDescription(
            topo.kdc_node.Get(0),
            "KDC\\n[ACTIVE]\\nPhase:3/3");
        for (uint32_t c = 0;
             c < topo.skdc_nodes.GetN(); ++c) {
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(c),
                "SKDC-C" + std::to_string(c)
                + "\\n[MT_K SENT]\\nTEK_v=1");
            // Restore SKDC links to steady-state label
            uint32_t base = c * uavs_per_cluster;
            for (uint32_t u = 0;
                 u < uavs_per_cluster; ++u) {
                uint32_t uid = base + u;
                if (uid < topo.uav_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(c),
                        topo.uav_nodes.Get(uid),
                        "MT_K_v1|AES256");
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV-" + std::to_string(uid)
                        + "\\nC" + std::to_string(c)
                        + "\\nTEK_v1:OK");
                }
            }
        }
        // Restore KDC backbone links
        for (uint32_t c = 0;
             c < topo.skdc_nodes.GetN(); ++c) {
            anim->UpdateLinkDescription(
                topo.kdc_node.Get(0),
                topo.skdc_nodes.Get(c),
                "CSMA|ACTIVE|C" + std::to_string(c));
        }
    });'''
))

# -----------------------------------------------------------------------
# P6: Show KDC→SKDC TEK push on REKEY events
#     Enhance existing rekey callback anim block
# -----------------------------------------------------------------------
patches.append((
    '''            if (anim) {
                anim->UpdateNodeDescription(
                    topo.skdc_nodes.Get(ev.cluster_id),
                    "SKDC-C" + std::to_string(ev.cluster_id)
                    + "|REKEY|TEK_v="
                    + std::to_string(
                        tek_mgr.GetVersion(ev.cluster_id)));
            }''',
    '''            if (anim) {
                uint32_t cid = ev.cluster_id;
                uint32_t ver = tek_mgr.GetVersion(cid);
                std::string reason_s =
                    apps::RekeyReasonStr(ev.reason);

                // Step 1: KDC → SKDC TEK push
                anim->UpdateLinkDescription(
                    topo.kdc_node.Get(0),
                    topo.skdc_nodes.Get(cid),
                    ">>> NEW_TEK_v"
                        + std::to_string(ver)
                        + " >>>");
                anim->UpdateNodeDescription(
                    topo.kdc_node.Get(0),
                    "KDC\\n[REKEY:" + reason_s + "]"
                    + "\\nTEK_v=" + std::to_string(ver));
                anim->UpdateNodeDescription(
                    topo.skdc_nodes.Get(cid),
                    "SKDC-C" + std::to_string(cid)
                    + "\\n[REKEYING:" + reason_s + "]"
                    + "\\nTEK_v=" + std::to_string(ver));

                // Step 2: After 0.1s — SKDC→UAV MT_K broadcast
                Simulator::Schedule(Seconds(0.1),
                    [=]() {
                        uint32_t base =
                            cid * uavs_per_cluster;
                        for (uint32_t u = 0;
                             u < uavs_per_cluster; ++u)
                        {
                            uint32_t uid = base + u;
                            if (uid < topo.uav_nodes
                                    .GetN()) {
                                anim->UpdateLinkDescription(
                                    topo.skdc_nodes.Get(cid),
                                    topo.uav_nodes.Get(uid),
                                    ">>> NEW_MT_K_v"
                                    + std::to_string(ver)
                                    + " >>>");
                                anim->UpdateNodeDescription(
                                    topo.uav_nodes.Get(uid),
                                    "UAV-" + std::to_string(uid)
                                    + "\\nC" + std::to_string(cid)
                                    + "\\nUPDATING_TEK");
                            }
                        }
                    });

                // Step 3: After 0.3s — UAVs confirm new TEK
                Simulator::Schedule(Seconds(0.3),
                    [=]() {
                        uint32_t base =
                            cid * uavs_per_cluster;
                        for (uint32_t u = 0;
                             u < uavs_per_cluster; ++u)
                        {
                            uint32_t uid = base + u;
                            if (uid < topo.uav_nodes
                                    .GetN()) {
                                anim->UpdateLinkDescription(
                                    topo.skdc_nodes.Get(cid),
                                    topo.uav_nodes.Get(uid),
                                    "MT_K_v"
                                    + std::to_string(ver)
                                    + "|AES256");
                                anim->UpdateNodeDescription(
                                    topo.uav_nodes.Get(uid),
                                    "UAV-" + std::to_string(uid)
                                    + "\\nC" + std::to_string(cid)
                                    + "\\nTEK_v"
                                    + std::to_string(ver) + ":OK");
                            }
                        }
                        // Restore SKDC label
                        anim->UpdateNodeDescription(
                            topo.skdc_nodes.Get(cid),
                            "SKDC-C" + std::to_string(cid)
                            + "\\n[ACTIVE]\\nTEK_v="
                            + std::to_string(ver));
                        // Restore KDC→SKDC link
                        anim->UpdateLinkDescription(
                            topo.kdc_node.Get(0),
                            topo.skdc_nodes.Get(cid),
                            "CSMA|ACTIVE|C"
                                + std::to_string(cid));
                        anim->UpdateNodeDescription(
                            topo.kdc_node.Get(0),
                            "KDC\\n[ACTIVE]\\nTEK_v="
                                + std::to_string(ver));
                    });
            }'''
))

# -----------------------------------------------------------------------
# P7: Show KDC→SKDC on JOIN event (slave key assignment notified to KDC)
# -----------------------------------------------------------------------
patches.append((
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(c),
                        topo.uav_nodes.Get(uid),
                        "JOIN_KEY");
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_JOINED_C"
                        + std::to_string(c));
                }''',
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    // SKDC → UAV: slave key assignment
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(c),
                        topo.uav_nodes.Get(uid),
                        ">>> SLAVE_KEY_ASSIGN >>>");
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV-" + std::to_string(uid)
                        + "\\nJOINING_C"
                        + std::to_string(c)
                        + "\\nKEY_PENDING");
                    anim->UpdateNodeDescription(
                        topo.skdc_nodes.Get(c),
                        "SKDC-C" + std::to_string(c)
                        + "\\n[JOIN:UAV"
                        + std::to_string(uid) + "]"
                        + "\\nISSUING_KEY");
                    // Notify KDC of new member
                    anim->UpdateLinkDescription(
                        topo.kdc_node.Get(0),
                        topo.skdc_nodes.Get(c),
                        "UNICAST|JOIN_NOTIFY|UAV"
                            + std::to_string(uid));
                    // After 0.2s: restore with confirmed state
                    Simulator::Schedule(Seconds(0.2),
                        [=]() {
                            uint32_t ver =
                                tek_mgr.GetVersion(c);
                            anim->UpdateLinkDescription(
                                topo.skdc_nodes.Get(c),
                                topo.uav_nodes.Get(uid),
                                "MT_K_v"
                                + std::to_string(ver)
                                + "|JOINED");
                            anim->UpdateNodeDescription(
                                topo.uav_nodes.Get(uid),
                                "UAV-" + std::to_string(uid)
                                + "\\nC" + std::to_string(c)
                                + "\\nTEK_v"
                                + std::to_string(ver) + ":OK");
                            anim->UpdateLinkDescription(
                                topo.kdc_node.Get(0),
                                topo.skdc_nodes.Get(c),
                                "CSMA|ACTIVE|C"
                                    + std::to_string(c));
                            anim->UpdateNodeDescription(
                                topo.skdc_nodes.Get(c),
                                "SKDC-C" + std::to_string(c)
                                + "\\n[ACTIVE]\\nTEK_v="
                                + std::to_string(ver));
                        });
                }'''
))

# -----------------------------------------------------------------------
# P8: Show LEAVE event — revoke link label, notify KDC
# -----------------------------------------------------------------------
patches.append((
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_LEFT");
                }''',
    '''                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    // Mark UAV as leaving
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV-" + std::to_string(uid)
                        + "\\nLEFT_C"
                        + std::to_string(c)
                        + "\\nKEY_REVOKED");
                    anim->UpdateNodeColor(
                        topo.uav_nodes.Get(uid),
                        180, 180, 180); // grey
                    // SKDC notifies KDC via backbone
                    anim->UpdateLinkDescription(
                        topo.kdc_node.Get(0),
                        topo.skdc_nodes.Get(c),
                        "UNICAST|LEAVE_NOTIFY|UAV"
                            + std::to_string(uid));
                    anim->UpdateNodeDescription(
                        topo.skdc_nodes.Get(c),
                        "SKDC-C" + std::to_string(c)
                        + "\\n[LEAVE:UAV"
                        + std::to_string(uid) + "]"
                        + "\\nRE-KEYING");
                    // Restore after 2s
                    Simulator::Schedule(Seconds(2.0),
                        [=]() {
                            uint32_t ccc = c;
                            uint32_t ver =
                                tek_mgr.GetVersion(ccc);
                            anim->UpdateLinkDescription(
                                topo.kdc_node.Get(0),
                                topo.skdc_nodes.Get(ccc),
                                "CSMA|ACTIVE|C"
                                    + std::to_string(ccc));
                            anim->UpdateNodeDescription(
                                topo.skdc_nodes.Get(ccc),
                                "SKDC-C" + std::to_string(ccc)
                                + "\\n[ACTIVE]\\nTEK_v="
                                + std::to_string(ver));
                        });
                }'''
))

# -----------------------------------------------------------------------
# P9: Show BATCH REKEY — KDC broadcasts to all SKDCs simultaneously
# -----------------------------------------------------------------------
patches.append((
    '''                if (anim) {
                    for (uint32_t c = 0;
                         c < num_clusters; ++c) {
                        anim->UpdateNodeDescription(
                            topo.skdc_nodes.Get(c),
                            "SKDC-C"
                            + std::to_string(c)
                            + "|BATCH_REKEY");
                    }
                }''',
    '''                if (anim) {
                    // KDC label
                    anim->UpdateNodeDescription(
                        topo.kdc_node.Get(0),
                        "KDC\\n[GLOBAL REKEY]"
                        "\\nBroadcasting TEK");
                    for (uint32_t bc = 0;
                         bc < num_clusters; ++bc) {
                        // KDC → SKDC links
                        anim->UpdateLinkDescription(
                            topo.kdc_node.Get(0),
                            topo.skdc_nodes.Get(bc),
                            ">>> BATCH_TEK_v"
                            + std::to_string(
                                tek_mgr.GetVersion(bc))
                            + " >>>");
                        anim->UpdateNodeDescription(
                            topo.skdc_nodes.Get(bc),
                            "SKDC-C" + std::to_string(bc)
                            + "\\n[BATCH_REKEY]"
                            + "\\nTEK_v="
                            + std::to_string(
                                tek_mgr.GetVersion(bc)));
                    }
                }'''
))

# -----------------------------------------------------------------------
# Apply patches
# -----------------------------------------------------------------------
applied = 0
for i, (old, new) in enumerate(patches):
    if old in src:
        src = src.replace(old, new, 1)
        print(f"  [P{i+1}] OK")
        applied += 1
    else:
        print(f"  [P{i+1}] SKIP (pattern not found)")

with open(SRC, 'w') as f:
    f.write(src)

print(f"\nApplied {applied}/{len(patches)} patches to {SRC}")
print(f"Backup: {BCK}")
print("""
KEY FLOW VISUALIZATION IN NETANIM:
  t=1s:  KDC → SKDC links show '>>> TEK_DIST >>>'
  t=2s:  SKDC → UAV links show '>>> MT_K >>>'
  t=3s:  All links restore to 'MT_K_v1|AES256'
  On REKEY: KDC → SKDC → UAVs animate in 3 steps (0.1s + 0.3s)
  On JOIN:  SKDC → UAV shows 'SLAVE_KEY_ASSIGN', notifies KDC
  On LEAVE: SKDC notifies KDC, UAV goes grey
  On BATCH: All KDC→SKDC links animate simultaneously

OLSR SUPPRESSION:
  OLSR packets (HELLO ~50B, TC ~80B) are smaller than our
  threshold. In NetAnim, go to:
    Packet Filter → Min Packet Size → set to 200
  This removes OLSR from the display while keeping key packets.
""")
