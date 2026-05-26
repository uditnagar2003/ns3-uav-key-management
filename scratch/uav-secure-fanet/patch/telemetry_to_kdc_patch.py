#!/usr/bin/env python3
"""
telemetry_to_kdc_patch.py
==========================
Patches 3 files to implement full telemetry flow:

  UAV → [AES-256-GCM TEK encrypted] → SKDC → [AES-256-GCM TEK encrypted] → KDC

Changes:
  1. apps/uav-uav-app.cc
       - SendTelemetry(): realistic payload (pos, vel, battery, seq)
       - StartApplication(): open m_kdc_send_socket (not used directly,
         routing goes via SKDC)

  2. apps/uav-skdc-app.cc
       - ReceiveDataFromUav(): decrypt with TEK, verify HMAC,
         re-encrypt with TEK, forward to KDC via CSMA on port 9300

  3. apps/uav-kdc-app.cc
       - StartApplication(): add listen socket on port 9300
       - Add ReceiveTelemetryFromSkdc(): decrypt, log to CSV

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/telemetry_to_kdc_patch.py
"""

import shutil, sys, os

def patch_file(path, patches):
    bck = path + ".bak_telkdc"
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}")
        return
    shutil.copy(path, bck)
    with open(path, 'r') as f:
        src = f.read()
    applied = 0
    for i, (old, new) in enumerate(patches):
        if old in src:
            src = src.replace(old, new, 1)
            print(f"  [P{i+1}] OK  — {path}")
            applied += 1
        else:
            print(f"  [P{i+1}] SKIP (pattern not found) — {path}")
    with open(path, 'w') as f:
        f.write(src)
    print(f"  Backup: {bck}  ({applied} patches applied)")

# ============================================================================
# FILE 1 — apps/uav-uav-app.cc
# ============================================================================
UAV_APP_CC = "apps/uav-uav-app.cc"

uav_patches = []

# P1: Replace SendTelemetry with realistic FANET telemetry payload
uav_patches.append((
    # OLD
    '''void UavApplication::SendTelemetry() {
    if (!m_state.tek_valid) {
        ScheduleTelemetry();
        return;
    }

    std::string msg = "UAV" +
        std::to_string(m_uav_id) +
        "@t=" +
        std::to_string(static_cast<int>(
            Simulator::Now().GetSeconds()));
    utils::ByteBuffer payload(msg.begin(),
                               msg.end());

    SendData(payload);
    ScheduleTelemetry();
}''',
    # NEW
    '''void UavApplication::SendTelemetry() {
    if (!m_state.tek_valid) {
        ScheduleTelemetry();
        return;
    }

    // Build realistic FANET telemetry payload
    // Fields: UAV_ID, cluster, sim_time, x, y, z,
    //         vx, vy, vz, battery_pct, seq, tek_version
    std::ostringstream oss;
    double t = Simulator::Now().GetSeconds();

    // Get position and velocity from mobility model
    double px = 0, py = 0, pz = 0;
    double vx = 0, vy = 0, vz = 0;
    Ptr<MobilityModel> mob =
        GetNode()->GetObject<MobilityModel>();
    if (mob) {
        auto pos = mob->GetPosition();
        auto vel = mob->GetVelocity();
        px = pos.x; py = pos.y; pz = pos.z;
        vx = vel.x; vy = vel.y; vz = vel.z;
    }

    // Battery: starts at 100%, drains 0.05%/s
    double bat = 100.0 - t * 0.05;
    if (bat < 0) bat = 0;

    oss << std::fixed << std::setprecision(2)
        << "ID:"  << m_uav_id
        << ",C:"  << m_cluster_id
        << ",T:"  << static_cast<int>(t)
        << ",X:"  << px
        << ",Y:"  << py
        << ",Z:"  << pz
        << ",VX:" << vx
        << ",VY:" << vy
        << ",VZ:" << vz
        << ",BAT:"<< bat
        << ",SEQ:"<< m_state.data_seq
        << ",TEK:"<< m_state.rekey_version;

    std::string msg = oss.str();
    utils::ByteBuffer payload(msg.begin(), msg.end());

    NS_LOG_UNCOND("[TELEMETRY_BUILD] t=" << t
        << " uav=" << m_uav_id
        << " payload=\"" << msg << "\""
        << " bytes=" << payload.size());

    SendData(payload);
    ScheduleTelemetry();
}'''
))

# P2: Add missing includes for ostringstream and MobilityModel
uav_patches.append((
    '#include "ns3/packet.h"\n\n#include <boost/multiprecision/cpp_int.hpp>',
    '''#include "ns3/packet.h"
#include "ns3/mobility-module.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>
#include <iomanip>'''
))

# ============================================================================
# FILE 2 — apps/uav-skdc-app.cc
# ============================================================================
SKDC_APP_CC = "apps/uav-skdc-app.cc"

skdc_patches = []

# P3: Add forward socket declaration in StartApplication
# Add m_forward_socket after m_data_socket setup
skdc_patches.append((
    '''    NS_LOG_UNCOND("[SKDC_DATA_READY] cluster=" << m_cluster_id
        << " listening on port 9100");

    // Initialize crypto state
    InitializeState();''',
    '''    NS_LOG_UNCOND("[SKDC_DATA_READY] cluster=" << m_cluster_id
        << " listening on port 9100");

    // Forward socket — send telemetry to KDC via CSMA on port 9300
    m_forward_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    // KDC CSMA address = csma_interfaces.GetAddress(0)
    if (m_topo) {
        m_kdc_csma_addr = m_topo->csma_interfaces.GetAddress(0);
        NS_LOG_UNCOND("[SKDC_FWD_READY] cluster=" << m_cluster_id
            << " will forward telemetry to KDC="
            << m_kdc_csma_addr << ":9300");
    }

    // Initialize crypto state
    InitializeState();'''
))

# P4: Replace ReceiveDataFromUav with full decrypt+verify+re-encrypt+forward
skdc_patches.append((
    '''// ===========================================================================
// ReceiveDataFromUav — receive encrypted DATA packets from UAVs on port 9100
// ===========================================================================
void SkdcApplication::ReceiveDataFromUav(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;

    while ((pkt = socket->RecvFrom(from))) {
        ++m_data_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from)) {
            src_ip = ns3::InetSocketAddress::ConvertFrom(from).GetIpv4();
        }

        NS_LOG_UNCOND("[DATA_RX] t="
            << ns3::Simulator::Now().GetSeconds() << "s"
            << " cluster=" << m_cluster_id
            << " size=" << pkt->GetSize() << "B"
            << " from=" << src_ip
            << " total_rx=" << m_data_rx_count);

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "SkdcApplication: DATA rx"
            << " cluster=" << m_cluster_id
            << " size=" << pkt->GetSize()
            << " from=" << src_ip
            << " total=" << m_data_rx_count);
    }
}''',
    '''// ===========================================================================
// ReceiveDataFromUav
// Full pipeline:
//   1. Copy NS-3 packet bytes
//   2. Verify outer HMAC
//   3. AES-256-GCM decrypt using cluster TEK → recover telemetry plaintext
//   4. Log decrypted telemetry at SKDC
//   5. Re-encrypt with same TEK
//   6. Append HMAC
//   7. Forward to KDC via CSMA port 9300
// ===========================================================================
void SkdcApplication::ReceiveDataFromUav(
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

        // ── Step 2: HMAC verify ─────────────────────────────
        // Last 32 bytes = HMAC; data = everything before
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

        if (!hmac_ok) {
            NS_LOG_UNCOND("[DATA_RX_DROP] HMAC fail from "
                << src_ip);
            continue;
        }

        // ── Step 3: AES-256-GCM decrypt ────────────────────
        // DataBody layout (from uav-data-packet.cc):
        // BASE_HEADER=32, NONCE=16, then DataBody:
        //   [0-3]  cluster_id u32
        //   [4-7]  seq        u32
        //   [8-15] ts_us      u64
        //   [16-19] pt_len    u32
        //   [20-23] ct_len    u32
        //   [24-35] aes_iv    12B
        //   [36-39] padding   4B
        //   [40-55] aes_tag   16B
        //   [56+]  ciphertext
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
            continue;
        }

        // ── Step 4: Log decrypted telemetry at SKDC ────────
        NS_LOG_UNCOND("[SKDC_TELEMETRY] t=" << t
            << " cluster=" << m_cluster_id
            << " from=" << src_ip
            << " payload=\"" << plaintext_str << "\"");

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "SkdcApplication: telemetry decrypted"
            << " cluster=" << m_cluster_id
            << " payload=" << plaintext_str);

        // ── Step 5+6: Re-encrypt + HMAC for KDC ───────────
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
}'''
))

# P5: Add m_forward_socket and m_kdc_csma_addr members to StopApplication cleanup
skdc_patches.append((
    '''    if (m_data_socket) {
        m_data_socket->Close();
        m_data_socket = nullptr;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: stopped cluster="''',
    '''    if (m_data_socket) {
        m_data_socket->Close();
        m_data_socket = nullptr;
    }
    if (m_forward_socket) {
        m_forward_socket->Close();
        m_forward_socket = nullptr;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: stopped cluster="'''
))

# ============================================================================
# FILE 3 — apps/uav-skdc-app.h  (add member declarations)
# ============================================================================
SKDC_APP_H = "apps/uav-skdc-app.h"

skdc_h_patches = []

skdc_h_patches.append((
    '''    ns3::Ptr<ns3::Socket> m_csma_socket;  // recv from KDC
    ns3::Ptr<ns3::Socket> m_wifi_socket;  // send to UAVs
    ns3::Ptr<ns3::Socket> m_data_socket;  // recv DATA from UAVs (port 9100)''',
    '''    ns3::Ptr<ns3::Socket> m_csma_socket;    // recv from KDC
    ns3::Ptr<ns3::Socket> m_wifi_socket;    // send to UAVs
    ns3::Ptr<ns3::Socket> m_data_socket;    // recv DATA from UAVs (port 9100)
    ns3::Ptr<ns3::Socket> m_forward_socket; // forward telemetry to KDC (port 9300)
    ns3::Ipv4Address      m_kdc_csma_addr;  // KDC CSMA address'''
))

# ============================================================================
# FILE 4 — apps/uav-kdc-app.cc  (add port 9300 listener + receiver)
# ============================================================================
KDC_APP_CC = "apps/uav-kdc-app.cc"

kdc_patches = []

# P6: Add telemetry receive socket in StartApplication
kdc_patches.append((
    '''    // Schedule initial TEK distribution
    Simulator::Schedule(
        Seconds(1.0),
        &KdcApplication::SendTekToAllSkdcs,
        this);''',
    '''    // Telemetry receive socket — SKDCs forward encrypted UAV telemetry
    m_telemetry_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    InetSocketAddress tel_local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9300));
    m_telemetry_socket->Bind(tel_local);
    m_telemetry_socket->SetRecvCallback(
        MakeCallback(
            &KdcApplication::ReceiveTelemetryFromSkdc,
            this));
    NS_LOG_UNCOND("[KDC_TEL_READY] listening on port 9300");

    // Schedule initial TEK distribution
    Simulator::Schedule(
        Seconds(1.0),
        &KdcApplication::SendTekToAllSkdcs,
        this);'''
))

# P7: Add telemetry socket close in StopApplication
kdc_patches.append((
    '''    if (m_socket) {
        m_socket->Close();
        m_socket = nullptr;
    }
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: stopped"''',
    '''    if (m_socket) {
        m_socket->Close();
        m_socket = nullptr;
    }
    if (m_telemetry_socket) {
        m_telemetry_socket->Close();
        m_telemetry_socket = nullptr;
    }
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: stopped"'''
))

# P8: Add ReceiveTelemetryFromSkdc implementation before closing namespace
kdc_patches.append((
    '} // namespace apps\n} // namespace uav',
    '''// ===========================================================================
// ReceiveTelemetryFromSkdc
// Receives AES-TEK-encrypted telemetry forwarded by SKDC on port 9300.
// Decrypts using cluster TEK, logs plaintext, writes to telemetry CSV.
// ===========================================================================
void KdcApplication::ReceiveTelemetryFromSkdc(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;

    while ((pkt = socket->RecvFrom(from))) {
        ++m_telemetry_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from))
            src_ip = ns3::InetSocketAddress::ConvertFrom(from)
                         .GetIpv4();

        double t = ns3::Simulator::Now().GetSeconds();
        uint32_t sz = pkt->GetSize();

        if (sz < 36 + 32) { // min: header(36) + hmac(32)
            NS_LOG_UNCOND("[KDC_TEL_DROP] too small: " << sz);
            continue;
        }

        utils::ByteBuffer wire(sz);
        pkt->CopyData(wire.data(), sz);

        // Verify HMAC (last 32 bytes)
        utils::ByteBuffer pkt_data(
            wire.begin(), wire.end() - 32);
        utils::ByteBuffer recv_hmac(
            wire.end() - 32, wire.end());

        // Find cluster id from first 4 bytes
        uint32_t cid =
            utils::ByteUtils::ReadU32BE(pkt_data.data());
        if (cid >= 3) {
            NS_LOG_UNCOND("[KDC_TEL_DROP] bad cluster=" << cid);
            continue;
        }

        // Verify HMAC using cluster TEK-derived key
        // Build hmac key same way SKDC does: KeyFromAesKey(TEK)
        auto hmac_key = crypto::HmacSha256Util::KeyFromAesKey(
            m_clusters[cid].current_tek);

        bool hmac_ok = false;
        try {
            hmac_ok = crypto::HmacSha256Util::Verify(
                hmac_key, pkt_data, recv_hmac);
        } catch (...) { hmac_ok = false; }

        if (!hmac_ok) {
            NS_LOG_UNCOND("[KDC_TEL_DROP] HMAC fail"
                << " cluster=" << cid
                << " from=" << src_ip);
            continue;
        }

        // Decrypt: layout [cluster 4B][iv 12B][tag 16B][ct_len 4B][ct]
        if (pkt_data.size() < 36) continue;
        const uint8_t* dp = pkt_data.data();

        std::array<uint8_t,12> iv{};
        std::memcpy(iv.data(), dp + 4, 12);
        std::array<uint8_t,16> tag{};
        std::memcpy(tag.data(), dp + 16, 16);
        uint32_t ct_len =
            utils::ByteUtils::ReadU32BE(dp + 32);

        if (pkt_data.size() < 36 + ct_len) {
            NS_LOG_UNCOND("[KDC_TEL_DROP] ct truncated");
            continue;
        }
        utils::ByteBuffer ct(
            pkt_data.begin() + 36,
            pkt_data.begin() + 36 + ct_len);

        utils::ByteBuffer aad(4);
        utils::ByteUtils::WriteU16BE(aad.data(),
            static_cast<uint16_t>(cid));
        utils::ByteUtils::WriteU16BE(aad.data() + 2,
            0xFFFF);

        std::string plaintext;
        try {
            auto pt = crypto::AesGcm::Decrypt(
                m_clusters[cid].current_tek,
                ct, aad, iv, tag);
            plaintext = std::string(pt.begin(), pt.end());
        } catch (const std::exception& e) {
            NS_LOG_UNCOND("[KDC_TEL_DROP] decrypt fail: "
                << e.what());
            continue;
        }

        // Log at KDC
        NS_LOG_UNCOND("[KDC_TELEMETRY] t=" << t
            << " cluster=" << cid
            << " from_skdc=" << src_ip
            << " payload=\"" << plaintext << "\"");

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "KdcApplication: telemetry received"
            << " cluster=" << cid
            << " payload=" << plaintext);

        // Write to CSV
        if (!m_tel_csv.is_open()) {
            std::string csv_path =
                std::string(UAV_OUTPUT_DIR)
                + "/kdc_telemetry.csv";
            m_tel_csv.open(csv_path, std::ios::app);
            if (m_tel_csv.is_open())
                m_tel_csv << "time_s,cluster,from_skdc,payload\\n";
        }
        if (m_tel_csv.is_open())
            m_tel_csv << t << ","
                      << cid << ","
                      << src_ip << ","
                      << plaintext << "\\n";
    }
}

} // namespace apps
} // namespace uav'''
))

# ============================================================================
# FILE 5 — apps/uav-kdc-app.h  (add member declarations)
# ============================================================================
KDC_APP_H = "apps/uav-kdc-app.h"

kdc_h_patches = []

kdc_h_patches.append((
    '    ns3::Ptr<ns3::Socket> m_socket;',
    '''    ns3::Ptr<ns3::Socket> m_socket;
    ns3::Ptr<ns3::Socket> m_telemetry_socket;  // recv telemetry from SKDC (9300)
    std::ofstream          m_tel_csv;           // kdc_telemetry.csv
    utils::u64             m_telemetry_rx_count = 0;'''
))

kdc_h_patches.append((
    '    void SendControlPacket(',
    '''    void ReceiveTelemetryFromSkdc(
        ns3::Ptr<ns3::Socket> socket);

    void SendControlPacket('''
))

# Also need fstream include in kdc header
kdc_h_patches.append((
    '#include <string>',
    '#include <string>\n#include <fstream>'
))

# ============================================================================
# APPLY ALL PATCHES
# ============================================================================
print("=" * 60)
print("  Telemetry-to-KDC patch")
print("=" * 60)

print(f"\n[1] {UAV_APP_CC}")
patch_file(UAV_APP_CC, uav_patches)

print(f"\n[2] {SKDC_APP_CC}")
patch_file(SKDC_APP_CC, skdc_patches)

print(f"\n[3] {SKDC_APP_H}")
patch_file(SKDC_APP_H, skdc_h_patches)

print(f"\n[4] {KDC_APP_CC}")
patch_file(KDC_APP_CC, kdc_patches)

print(f"\n[5] {KDC_APP_H}")
patch_file(KDC_APP_H, kdc_h_patches)

print("""
============================================================
  DONE. Rebuild:
    cd ~/ns-allinone-3.43/ns-3.43
    cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug -j$(nproc) 2>&1 | tail -30

  Expected log output after run:
    [TELEMETRY_BUILD] t=10 uav=3 payload="ID:3,C:0,T:10,X:..."
    [DATA_TX]         uav=3 → SKDC WiFi IP:9100
    [DATA_RX]         cluster=0 from=10.1.1.x
    [SKDC_TELEMETRY]  cluster=0 payload="ID:3,C:0,T:10,X:..."
    [SKDC_FWD]        cluster=0 → KDC=10.1.0.1:9300
    [KDC_TELEMETRY]   cluster=0 payload="ID:3,C:0,T:10,X:..."

  Output file:
    output/kdc_telemetry.csv
    Columns: time_s, cluster, from_skdc, payload

  Full flow:
    UAV
     └─[AES-256-GCM TEK + HMAC, WiFi, port 9100]─► SKDC
         └─[decrypt → verify → re-encrypt TEK + HMAC, CSMA, port 9300]─► KDC
             └─[decrypt → verify → log to kdc_telemetry.csv]
============================================================
""")
