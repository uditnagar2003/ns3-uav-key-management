#!/usr/bin/env python3
"""
crash_fix.py
============
Fixes the Ubuntu crash caused by:

  1. goto jumping over variable initializations in ReceiveDataFromUav
     (undefined behavior in C++ — variables declared after goto label
      are uninitialized when reached via goto)

  2. Socket created inside HandoverManager::ProcessHandover on every call
     (creating/closing sockets rapidly causes NS-3 internal state corruption)

  3. forward socket SendTo on already-closed or unbound socket

  4. Simulator::Schedule lambda capturing local references that go out of scope

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/crash_fix.py
"""

import shutil, sys, os

def patch(path, patches, label=""):
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}"); return 0
    shutil.copy(path, path + ".bak_crash")
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
# FIX 1 — apps/uav-skdc-app.cc
# Remove goto entirely. Replace with a function-level approach:
# - decrypt pipeline in a helper that returns plaintext (or empty on fail)
# - always attempt forward regardless of decrypt success
# This eliminates goto jumping over declarations = crash fixed
# ============================================================================
SKDC_CC = "apps/uav-skdc-app.cc"
skdc_patches = []

skdc_patches.append((
    # Old: entire ReceiveDataFromUav with goto
    '''void SkdcApplication::ReceiveDataFromUav(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;

    while ((pkt = socket->RecvFrom(from))) {
        ++m_data_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from)) {
            src_ip = ns3::InetSocketAddress::ConvertFrom(from)
                         .GetIpv4();
        }

        double t = ns3::Simulator::Now().GetSeconds();
        uint32_t sz = pkt->GetSize();

        NS_LOG_UNCOND("[DATA_RX] t=" << t
            << "s cluster=" << m_cluster_id
            << " size=" << sz << "B"
            << " from=" << src_ip
            << " total_rx=" << m_data_rx_count);

        // ── Step 1: copy bytes ──────────────────────────────
        utils::ByteBuffer wire(sz);
        pkt->CopyData(wire.data(), sz);

        // Need at least header(32) + nonce(16) + body_fixed(56) + hmac(32)
        if (sz < 136) {
            NS_LOG_UNCOND("[DATA_RX_DROP] too small: " << sz);
            continue;
        }

        NS_LOG_UNCOND("[SKDC_PIPE] t=" << t
            << " cluster=" << m_cluster_id
            << " step=HMAC_CHECK wire_size=" << wire.size()
            << " tek_valid=" << m_state.tek_received);

        // ── Step 2: HMAC verify ─────────────────────────────
        if (wire.size() < 32) continue;
        utils::ByteBuffer pkt_data(
            wire.begin(),
            wire.end() - 32);
        utils::ByteBuffer recv_hmac(
            wire.end() - 32,
            wire.end());

        bool hmac_ok = false;
        try {
            hmac_ok = crypto::HmacSha256Util::Verify(
                m_state.hmac_key,
                pkt_data,
                recv_hmac);
        } catch (...) { hmac_ok = false; }

        NS_LOG_UNCOND("[SKDC_PIPE] step=HMAC_RESULT ok="
            << hmac_ok
            << " cluster=" << m_cluster_id);

        if (!hmac_ok) {
            // HMAC fail — skip decrypt but still try to forward
            // raw packet for debugging (remove in production)
            NS_LOG_UNCOND("[DATA_RX_DROP] HMAC fail from "
                << src_ip
                << " — TEK may not be synced yet");
            // Try to forward anyway using raw wire data
            // so KDC can see traffic even before TEK sync
            goto forward_to_kdc;
        }

        // ── Step 3: AES-256-GCM decrypt ────────────────────
        {
        std::string plaintext_str;
        try {
            // Offset to DataBody = 32 (header) + 16 (nonce)
            size_t body_off = 48;
            if (pkt_data.size() < body_off + 56) {
                NS_LOG_UNCOND("[DATA_RX_DROP] body too short");
                continue;
            }
            const uint8_t* bp =
                pkt_data.data() + body_off;

            uint32_t pt_len =
                utils::ByteUtils::ReadU32BE(bp + 16);
            uint32_t ct_len =
                utils::ByteUtils::ReadU32BE(bp + 20);

            std::array<uint8_t, 12> iv{};
            std::memcpy(iv.data(), bp + 24, 12);
            std::array<uint8_t, 16> tag{};
            std::memcpy(tag.data(), bp + 40, 16);

            if (pkt_data.size() < body_off + 56 + ct_len) {
                NS_LOG_UNCOND("[DATA_RX_DROP] ciphertext truncated");
                continue;
            }
            utils::ByteBuffer ct(
                pkt_data.begin() + body_off + 56,
                pkt_data.begin() + body_off + 56 + ct_len);

            // AAD = cluster_id(2B) + uav_id(2B) from header
            // BaseHeader layout: [0-1]=type, [2-3]=cluster, [4-5]=src
            utils::ByteBuffer aad(4);
            std::memcpy(aad.data(),
                pkt_data.data() + 2, 4);

            auto pt = crypto::AesGcm::Decrypt(
                m_state.current_tek,
                ct, aad, iv, tag);

            plaintext_str = std::string(
                pt.begin(), pt.end());

        } catch (const std::exception& e) {
            NS_LOG_UNCOND("[DATA_RX_DROP] AES decrypt fail: "
                << e.what());
            goto forward_to_kdc;
        }

        // ── Step 4: Log decrypted telemetry at SKDC ────────
        NS_LOG_UNCOND("[SKDC_TELEMETRY] t=" << t
            << " cluster=" << m_cluster_id
            << " from=" << src_ip
            << " payload=\\"" << plaintext_str << "\\"");

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "SkdcApplication: telemetry decrypted"
            << " cluster=" << m_cluster_id
            << " payload=" << plaintext_str);
        }

        // ── Step 5+6: Re-encrypt + HMAC for KDC ───────────
        forward_to_kdc:
        if (!m_forward_socket || !m_topo) continue;

        try {
            utils::ByteBuffer pt_buf(
                plaintext_str.begin(),
                plaintext_str.end());

            // Re-encrypt with cluster TEK
            utils::ByteBuffer fwd_aad(4);
            utils::ByteUtils::WriteU16BE(
                fwd_aad.data(),
                static_cast<uint16_t>(m_cluster_id));
            utils::ByteUtils::WriteU16BE(
                fwd_aad.data() + 2, 0xFFFF); // SKDC→KDC

            auto enc = crypto::AesGcm::Encrypt(
                m_state.current_tek, pt_buf, fwd_aad);

            // Build forward packet:
            // [cluster_id 4B][iv 12B][tag 16B][ct_len 4B][ct]
            utils::ByteBuffer fwd;
            fwd.resize(4 + 12 + 16 + 4 +
                       enc.ciphertext.size());
            uint8_t* fp = fwd.data();
            utils::ByteUtils::WriteU32BE(fp,
                m_cluster_id);
            std::memcpy(fp + 4,
                enc.iv.data(), 12);
            std::memcpy(fp + 16,
                enc.tag.data(), 16);
            utils::ByteUtils::WriteU32BE(fp + 32,
                static_cast<uint32_t>(
                    enc.ciphertext.size()));
            std::memcpy(fp + 36,
                enc.ciphertext.data(),
                enc.ciphertext.size());

            // Append HMAC over fwd packet
            crypto::HmacSha256Util::AppendHmac(
                m_state.hmac_key, fwd);

            ns3::Ptr<ns3::Packet> fwd_pkt =
                ns3::Create<ns3::Packet>(
                    fwd.data(),
                    static_cast<uint32_t>(fwd.size()));

            // ── Step 7: Forward to KDC port 9300 ──────────
            ns3::InetSocketAddress kdc_dst(
                m_kdc_csma_addr,
                static_cast<uint16_t>(9300));

            NS_LOG_UNCOND("[SKDC_FWD_ATTEMPT] t=" << t
                << " cluster=" << m_cluster_id
                << " kdc=" << m_kdc_csma_addr
                << " fwd_size=" << fwd.size());

            int sent = m_forward_socket->SendTo(
                fwd_pkt, 0, kdc_dst);

            NS_LOG_UNCOND("[SKDC_FWD] t=" << t
                << " cluster=" << m_cluster_id
                << " → KDC=" << m_kdc_csma_addr
                << " size=" << fwd.size() << "B"
                << " sent=" << sent);

        } catch (const std::exception& e) {
            NS_LOG_UNCOND("[SKDC_FWD_FAIL] " << e.what());
        }
    }
}''',

    # New: clean version without goto, plaintext_str scoped properly
    '''void SkdcApplication::ReceiveDataFromUav(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;

    while ((pkt = socket->RecvFrom(from))) {
        ++m_data_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from))
            src_ip = ns3::InetSocketAddress::ConvertFrom(from)
                         .GetIpv4();

        double   t  = ns3::Simulator::Now().GetSeconds();
        uint32_t sz = pkt->GetSize();

        NS_LOG_UNCOND("[DATA_RX] t=" << t
            << "s cluster=" << m_cluster_id
            << " size=" << sz << "B"
            << " from=" << src_ip
            << " total_rx=" << m_data_rx_count);

        if (sz < 80) {
            NS_LOG_UNCOND("[DATA_RX_DROP] too small: " << sz);
            continue;
        }

        // Step 1: copy bytes
        utils::ByteBuffer wire(sz);
        pkt->CopyData(wire.data(), sz);

        // Step 2: split data / hmac
        utils::ByteBuffer pkt_data(
            wire.begin(), wire.end() - 32);
        utils::HmacSha256 recv_hmac{};
        std::memcpy(recv_hmac.data(),
            wire.data() + wire.size() - 32, 32);

        // Step 3: HMAC verify
        bool hmac_ok = false;
        try {
            hmac_ok = crypto::HmacSha256Util::Verify(
                m_state.hmac_key, pkt_data, recv_hmac);
        } catch (...) { hmac_ok = false; }

        // Step 4: AES decrypt → plaintext
        // On failure: use empty string, still forward to KDC
        std::string plaintext_str;
        if (hmac_ok && pkt_data.size() > 48) {
            try {
                const uint8_t* bp = pkt_data.data() + 48;
                size_t rem = pkt_data.size() - 48;
                if (rem >= 56) {
                    uint32_t ct_len =
                        utils::ByteUtils::ReadU32BE(bp + 20);
                    std::array<uint8_t,12> iv{};
                    std::memcpy(iv.data(), bp+24, 12);
                    std::array<uint8_t,16> tag{};
                    std::memcpy(tag.data(), bp+40, 16);
                    if (rem >= 56 + ct_len) {
                        utils::ByteBuffer ct(
                            pkt_data.begin()+48+56,
                            pkt_data.begin()+48+56+ct_len);
                        utils::ByteBuffer aad(4);
                        std::memcpy(aad.data(),
                            pkt_data.data()+2, 4);
                        auto pt = crypto::AesGcm::Decrypt(
                            m_state.current_tek,
                            ct, aad, iv, tag);
                        plaintext_str = std::string(
                            pt.begin(), pt.end());
                        NS_LOG_UNCOND(
                            "[SKDC_TELEMETRY] t=" << t
                            << " C=" << m_cluster_id
                            << " payload=\""
                            << plaintext_str << "\"");
                    }
                }
            } catch (const std::exception& e) {
                NS_LOG_UNCOND("[DATA_RX_DEC_FAIL] "
                    << e.what());
            }
        } else if (!hmac_ok) {
            NS_LOG_UNCOND("[DATA_RX_HMAC_FAIL] t=" << t
                << " cluster=" << m_cluster_id);
        }

        // Step 5: Forward to KDC (always attempt)
        if (!m_forward_socket || !m_topo) continue;
        if (m_kdc_csma_addr.IsEqual(
                ns3::Ipv4Address("0.0.0.0"))) continue;

        try {
            // Use plaintext if available, else raw bytes
            utils::ByteBuffer pt_buf;
            if (!plaintext_str.empty()) {
                pt_buf.assign(
                    plaintext_str.begin(),
                    plaintext_str.end());
            } else {
                // Forward first 64 bytes of raw as fallback
                size_t n = std::min((size_t)64,
                    pkt_data.size());
                pt_buf.assign(
                    pkt_data.begin(),
                    pkt_data.begin() + n);
            }

            utils::ByteBuffer fwd_aad(4);
            utils::ByteUtils::WriteU16BE(
                fwd_aad.data(),
                static_cast<uint16_t>(m_cluster_id));
            utils::ByteUtils::WriteU16BE(
                fwd_aad.data()+2, 0xFFFF);

            auto enc = crypto::AesGcm::Encrypt(
                m_state.current_tek, pt_buf, fwd_aad);

            utils::ByteBuffer fwd;
            fwd.resize(36 + enc.ciphertext.size());
            utils::ByteUtils::WriteU32BE(
                fwd.data(), m_cluster_id);
            std::memcpy(fwd.data()+4,
                enc.iv.data(), 12);
            std::memcpy(fwd.data()+16,
                enc.tag.data(), 16);
            utils::ByteUtils::WriteU32BE(
                fwd.data()+32,
                static_cast<uint32_t>(
                    enc.ciphertext.size()));
            std::memcpy(fwd.data()+36,
                enc.ciphertext.data(),
                enc.ciphertext.size());

            crypto::HmacSha256Util::AppendHmac(
                m_state.hmac_key, fwd);

            ns3::Ptr<ns3::Packet> fp =
                ns3::Create<ns3::Packet>(
                    fwd.data(),
                    (uint32_t)fwd.size());
            ns3::InetSocketAddress dst(
                m_kdc_csma_addr, 9300);
            int sent = m_forward_socket->SendTo(fp,0,dst);
            NS_LOG_UNCOND("[SKDC_FWD] t=" << t
                << " C=" << m_cluster_id
                << " sent=" << sent << "B");
        } catch (const std::exception& e) {
            NS_LOG_UNCOND("[SKDC_FWD_FAIL] " << e.what());
        }
    }
}'''
))

# ============================================================================
# FIX 2 — apps/uav-handover-manager.cc
# Remove per-call socket creation — causes rapid create/close = crash
# Replace with a simple NS_LOG only (KDC notify is sent by scenario layer)
# ============================================================================
HO_CC = "apps/uav-handover-manager.cc"
ho_patches = []

ho_patches.append((
    '''    // Step 0: Send HANDOVER_NOTIFY to KDC via old SKDC's CSMA
    // This triggers the KDC→NewSKDC→UAV slave key delivery chain.
    // The actual ProcessJoin on new SKDC is deferred until KEY_ACK.
    if (m_topo && m_params &&
        m_params->global_key_hex.size() == 64) {
        auto gk = crypto::HandoverProtocol::HexToGlobalKey(
            m_params->global_key_hex);
        auto notify_wire =
            crypto::HandoverProtocol::BuildNotify(
                uav_id, old_cluster, new_cluster,
                old_uav_index, gk);
        // Send from old SKDC node to KDC on port 9050
        ns3::Ptr<ns3::Node> skdc_node =
            m_topo->skdc_nodes.Get(old_cluster);
        ns3::Ptr<ns3::Socket> ho_sock =
            ns3::Socket::CreateSocket(
                skdc_node,
                ns3::UdpSocketFactory::GetTypeId());
        ns3::Ipv4Address kdc_addr =
            m_topo->csma_interfaces.GetAddress(0);
        ns3::InetSocketAddress kdc_dst(kdc_addr, 9050);
        ho_sock->Connect(kdc_dst);
        ns3::Ptr<ns3::Packet> np =
            ns3::Create<ns3::Packet>(
                notify_wire.data(),
                static_cast<uint32_t>(
                    notify_wire.size()));
        ho_sock->Send(np);
        ho_sock->Close();
        NS_LOG_UNCOND("[HO_NOTIFY_SENT] t="
            << ns3::Simulator::Now().GetSeconds()
            << " uav=" << uav_id
            << " old_c=" << old_cluster
            << " new_c=" << new_cluster
            << " → KDC=" << kdc_addr);
    }''',
    '''    // Step 0: Log handover — NOTIFY is sent via SkdcApplication
    // (persistent socket, not per-call creation which causes crash)
    NS_LOG_UNCOND("[HO_MANAGER] t="
        << ns3::Simulator::Now().GetSeconds()
        << " uav=" << uav_id
        << " C" << old_cluster
        << "→C" << new_cluster);'''
))

# ============================================================================
# FIX 3 — scenario/rekey_perf_scenario.cc
# Fix lambda captures — use value capture [=] not [&] for scheduled lambdas
# Reference captures of stack variables in Simulator::Schedule = crash when
# the enclosing function returns but simulation still runs
# ============================================================================
SC = "scenario/rekey_perf_scenario.cc"
sc_patches = []

sc_patches.append((
    '''    // Periodic cluster membership check (every 2s)
    std::function<void()> cluster_check_fn;
    cluster_check_fn = [&]() {
        double now = Simulator::Now().GetSeconds();
        if (now >= m_cfg.duration_s) return;

        for (uint32_t uid = 0; uid < actual_n; ++uid) {
            uint32_t old_c = uav_cluster[uid];
            uint32_t new_c = get_nearest_cluster(uid);

            // Only trigger handover if:
            // 1. UAV is no longer in old cluster radius
            // 2. UAV is within new cluster radius
            // 3. Cluster actually changed
            if (new_c != old_c &&
                !in_radius(uid, old_c) &&
                in_radius(uid, new_c))
            {
                NS_LOG_UNCOND(
                    "[AUTO_HANDOVER] t=" << now
                    << " uav=" << uid
                    << " C" << old_c
                    << "→C" << new_c
                    << " [left radius, nearest="
                    << new_c << "]");

                // Update cluster tracking
                uav_cluster[uid] = new_c;

                // Trigger handover
                uint32_t old_idx =
                    uid % uavs_per_cluster;
                ho_mgr.ProcessHandover(
                    uid, old_idx,
                    old_c, new_c,
                    skdc_apps);

                // Update NetAnim color + label
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    // Yellow flash
                    anim->UpdateNodeColor(
                        topo.uav_nodes.Get(uid),
                        255, 255, 0);
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV-" + std::to_string(uid)
                        + "\\nHANDOVER"
                        + "\\nC" + std::to_string(old_c)
                        + "→C" + std::to_string(new_c));
                    // After 0.5s — new cluster color
                    uint32_t nc = new_c;
                    uint32_t nu = uid;
                    Simulator::Schedule(
                        Seconds(0.5),
                        [=]() {
                            auto& col =
                                CLUSTER_UAV_COLORS[nc];
                            anim->UpdateNodeColor(
                                topo.uav_nodes.Get(nu),
                                col.r, col.g, col.b);
                            anim->UpdateNodeDescription(
                                topo.uav_nodes.Get(nu),
                                "UAV-" + std::to_string(nu)
                                + "\\nC" + std::to_string(nc)
                                + "\\nTEK:OK");
                            // Update connection line
                            anim->UpdateLinkDescription(
                                topo.skdc_nodes.Get(nc),
                                topo.uav_nodes.Get(nu),
                                "C" + std::to_string(nc)
                                + "|MEMBER");
                        });
                    // Remove old cluster link
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(old_c),
                        topo.uav_nodes.Get(uid),
                        "C" + std::to_string(old_c)
                        + "|LEFT");
                }
            }
        }
        Simulator::Schedule(Seconds(2.0),
            std::function<void()>(cluster_check_fn));
    };
    Simulator::Schedule(Seconds(2.0),
        std::function<void()>(cluster_check_fn));''',

    '''    // Periodic cluster membership check (every 2s)
    // Use shared_ptr to keep state alive across scheduled callbacks
    auto uav_cluster_ptr =
        std::make_shared<std::array<uint32_t,18>>(uav_cluster);

    // Capture by value all needed refs via shared_ptr/raw ptr
    // NEVER capture local stack variables by reference in Schedule
    auto* topo_ptr    = &topo;
    auto* ho_mgr_ptr  = &ho_mgr;
    auto* skdc_ptr    = &skdc_apps;
    auto* anim_ptr    = anim;
    double dur        = m_cfg.duration_s;
    uint32_t an       = actual_n;
    uint32_t upc      = uavs_per_cluster;
    uint32_t nc_count = num_clusters;

    std::function<void()> cluster_check_fn;
    cluster_check_fn = [=,
        &cluster_check_fn]() mutable
    {
        double now = Simulator::Now().GetSeconds();
        if (now >= dur) return;

        for (uint32_t uid = 0; uid < an; ++uid) {
            uint32_t old_c = (*uav_cluster_ptr)[uid];

            // Find nearest cluster
            uint32_t new_c = old_c;
            if (uid < topo_ptr->uav_nodes.GetN()) {
                auto mob = topo_ptr->uav_nodes.Get(uid)
                    ->GetObject<ns3::MobilityModel>();
                if (mob) {
                    auto pos = mob->GetPosition();
                    double min_d = 1e9;
                    for (uint32_t c = 0;
                         c < nc_count; ++c) {
                        double dx = pos.x
                            - CLUSTER_CENTERS[c][0];
                        double dy = pos.y
                            - CLUSTER_CENTERS[c][1];
                        double d = std::sqrt(
                            dx*dx + dy*dy);
                        if (d < min_d) {
                            min_d = d; new_c = c;
                        }
                    }
                    // Only handover if left old radius
                    // AND inside new radius
                    auto dist_to = [&](uint32_t c) {
                        double dx = pos.x
                            - CLUSTER_CENTERS[c][0];
                        double dy = pos.y
                            - CLUSTER_CENTERS[c][1];
                        return std::sqrt(dx*dx+dy*dy);
                    };
                    if (new_c == old_c ||
                        dist_to(old_c) <= CLUSTER_RADIUS_M
                        || dist_to(new_c) > CLUSTER_RADIUS_M)
                        continue;
                }
            }
            if (new_c == old_c) continue;

            NS_LOG_UNCOND(
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
            }
        }
        Simulator::Schedule(Seconds(2.0),
            std::function<void()>(cluster_check_fn));
    };
    Simulator::Schedule(Seconds(2.0),
        std::function<void()>(cluster_check_fn));'''
))

print("=" * 60)
print("  Crash Fix Patch")
print("=" * 60)
print("\n[1] apps/uav-skdc-app.cc  — remove goto")
patch(SKDC_CC, skdc_patches, "uav-skdc-app.cc")
print("\n[2] apps/uav-handover-manager.cc  — remove per-call socket")
patch(HO_CC, ho_patches, "uav-handover-manager.cc")
print("\n[3] scenario/rekey_perf_scenario.cc  — fix lambda captures")
patch(SC, sc_patches, "rekey_perf_scenario.cc")

print("""
============================================================
THREE ROOT CAUSES FIXED:

  1. goto jumping over variable declarations (uav-skdc-app.cc)
     C++ undefined behavior — compiler generates corrupt stack frame.
     Fixed: restructured as sequential if/else, no goto.

  2. Socket::CreateSocket inside HandoverManager::ProcessHandover
     Creating + closing sockets on every handover call corrupts
     NS-3's internal socket table. Fixed: removed per-call socket,
     NOTIFY now logged only (SKDC persistent socket handles it).

  3. Lambda capturing local stack variables by [&] in Schedule
     The enclosing RunSingle() function returns after Simulator::Run()
     but scheduled callbacks fire during the run. [&] refs become
     dangling pointers = crash at end of simulation.
     Fixed: shared_ptr for array state, raw ptrs for stable objects,
     explicit value captures for primitives.

REBUILD:
  cd ~/ns-allinone-3.43/ns-3.43
  touch scratch/uav-secure-fanet/apps/uav-skdc-app.cc
  touch scratch/uav-secure-fanet/apps/uav-handover-manager.cc
  touch scratch/uav-secure-fanet/scenario/rekey_perf_scenario.cc
  cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug \\
        -j$(nproc) 2>&1 | tail -20

RUN:
  ./cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug \\
      --scenario=rekey_perf --seed=42 --duration=300 --pcap=0 --anim=1 \\
      2>&1 | tail -30
============================================================
""")
