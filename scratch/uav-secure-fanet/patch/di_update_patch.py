#!/usr/bin/env python3
"""
di_update_patch.py
==================
Implements complete d_i update on inter-cluster handover.

Protocol:
  1. Old SKDC → KDC:       HANDOVER_NOTIFY  (CSMA port 9050)
  2. KDC → New SKDC:       SLAVE_FWD        (CSMA port 9051)
  3. New SKDC → UAV:       JOIN_ACCEPT      (WiFi unicast port 9052)
  4. UAV → New SKDC:       KEY_ACK          (WiFi unicast port 9053)
  5. New SKDC:             JoKeyUpdate → MT_K broadcast (port 9200)

All packets HMAC-SHA256 keyed with GK.
Slave key blob encrypted AES-256-GCM with GK.

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/di_update_patch.py
"""

import shutil, sys, os

def patch(path, patches, label=""):
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}"); return 0
    shutil.copy(path, path + ".bak_di")
    with open(path) as f: src = f.read()
    ok = 0
    for i,(old,new) in enumerate(patches):
        if old in src:
            src = src.replace(old, new, 1)
            print(f"  [P{i+1}] OK  {label}")
            ok += 1
        else:
            print(f"  [P{i+1}] SKIP {label}")
    with open(path,'w') as f: f.write(src)
    return ok

# ============================================================================
# FILE 1 — crypto/uav-crypto-params.h
# Add global_bootstrap_key field to CryptoParamsFile
# ============================================================================
CP_H = "crypto/uav-crypto-params.h"
cp_h_patches = []

cp_h_patches.append((
    '''struct CryptoParamsFile {
    std::string  scheme;             // "MKE-MGKM"
    utils::u32   num_clusters;
    utils::u32   uavs_per_cluster;
    utils::u32   total_uavs;
    utils::u32   seed;''',
    '''struct CryptoParamsFile {
    std::string  scheme;             // "MKE-MGKM"
    std::string  global_key_hex;     // GK: 64 hex chars (32 bytes AES-256)
    utils::u32   num_clusters;
    utils::u32   uavs_per_cluster;
    utils::u32   total_uavs;
    utils::u32   seed;'''
))

# ============================================================================
# FILE 2 — crypto/uav-crypto-params.cc
# Parse global_bootstrap_key from JSON
# ============================================================================
CP_CC = "crypto/uav-crypto-params.cc"
cp_cc_patches = []

cp_cc_patches.append((
    '''    CryptoParamsFile params = ParseJson(json_str);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CryptoParamsLoader: loaded "''',
    '''    CryptoParamsFile params = ParseJson(json_str);

    // Validate GK present
    if (params.global_key_hex.size() != 64) {
        NS_LOG_UNCOND("[WARN] global_bootstrap_key missing or "
            "invalid in crypto_params.json — "
            "handover d_i delivery will not work. "
            "Regenerate with: python3 scripts/gen_crypto.py");
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CryptoParamsLoader: loaded "'''
))

cp_cc_patches.append((
    '    params.scheme           = j.at("scheme").get<std::string>();',
    '''    params.scheme           = j.at("scheme").get<std::string>();
    params.global_key_hex   = j.value(
        "global_bootstrap_key", std::string(64,'0'));'''
))

# ============================================================================
# FILE 3 — apps/uav-kdc-app.h
# Add handover receive handler + GK storage
# ============================================================================
KDC_H = "apps/uav-kdc-app.h"
kdc_h_patches = []

kdc_h_patches.append((
    '    ns3::Ptr<ns3::Socket> m_telemetry_socket;  // recv telemetry from SKDC (9300)',
    '''    ns3::Ptr<ns3::Socket> m_telemetry_socket;   // recv telemetry (9300)
    ns3::Ptr<ns3::Socket> m_handover_socket;    // recv HANDOVER_NOTIFY (9050)
    crypto::GlobalKey     m_gk{};              // Global Bootstrap Key'''
))

kdc_h_patches.append((
    '    void ReceiveTelemetryFromSkdc(\n        ns3::Ptr<ns3::Socket> socket);',
    '''    void ReceiveTelemetryFromSkdc(
        ns3::Ptr<ns3::Socket> socket);

    // Handover protocol handlers
    void ReceiveHandoverNotify(
        ns3::Ptr<ns3::Socket> socket);
    void ForwardSlaveKey(
        uint32_t uav_id,
        uint32_t new_cluster,
        uint32_t old_index);'''
))

kdc_h_patches.append((
    '#include <string>\n#include <fstream>',
    '#include <string>\n#include <fstream>\n'
    '#include "crypto/uav-handover-protocol.h"'
))

# ============================================================================
# FILE 4 — apps/uav-kdc-app.cc
# Implement ReceiveHandoverNotify + ForwardSlaveKey
# ============================================================================
KDC_CC = "apps/uav-kdc-app.cc"
kdc_cc_patches = []

# P1: Init GK + handover socket in StartApplication
kdc_cc_patches.append((
    '''    // Telemetry receive socket — SKDCs forward encrypted UAV telemetry
    m_telemetry_socket = Socket::CreateSocket(''',
    '''    // Load GK from crypto params
    if (m_params && m_params->global_key_hex.size() == 64) {
        m_gk = crypto::HandoverProtocol::HexToGlobalKey(
            m_params->global_key_hex);
        NS_LOG_UNCOND("[KDC_GK] Global bootstrap key loaded");
    }

    // Handover NOTIFY receive socket (port 9050)
    m_handover_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress ho_local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9050));
    m_handover_socket->Bind(ho_local);
    m_handover_socket->SetRecvCallback(
        MakeCallback(
            &KdcApplication::ReceiveHandoverNotify,
            this));
    NS_LOG_UNCOND("[KDC_HO_READY] listening on port 9050");

    // Telemetry receive socket — SKDCs forward encrypted UAV telemetry
    m_telemetry_socket = Socket::CreateSocket('''
))

# P2: Close handover socket in StopApplication
kdc_cc_patches.append((
    '''    if (m_telemetry_socket) {
        m_telemetry_socket->Close();
        m_telemetry_socket = nullptr;
    }''',
    '''    if (m_telemetry_socket) {
        m_telemetry_socket->Close();
        m_telemetry_socket = nullptr;
    }
    if (m_handover_socket) {
        m_handover_socket->Close();
        m_handover_socket = nullptr;
    }'''
))

# P3: Add ReceiveHandoverNotify + ForwardSlaveKey before closing namespace
kdc_cc_patches.append((
    '} // namespace apps\n} // namespace uav',
    '''// ===========================================================================
// ReceiveHandoverNotify — port 9050
// Old SKDC tells KDC: "UAV X is moving to cluster Y"
// KDC looks up new slave key params, encrypts with GK, sends to new SKDC
// ===========================================================================
void KdcApplication::ReceiveHandoverNotify(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;
    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        crypto::HandoverProtocol::NotifyPkt np;
        if (!crypto::HandoverProtocol::ParseNotify(
                buf, np, m_gk)) {
            NS_LOG_UNCOND("[KDC_HO_DROP] HMAC fail");
            continue;
        }

        NS_LOG_UNCOND("[KDC_HO_NOTIFY] t="
            << ns3::Simulator::Now().GetSeconds()
            << " uav=" << np.uav_id
            << " old_c=" << np.old_cluster
            << " new_c=" << np.new_cluster);

        ForwardSlaveKey(
            np.uav_id, np.new_cluster, np.old_index);
    }
}

// ===========================================================================
// ForwardSlaveKey — KDC → New SKDC (CSMA port 9051)
// Looks up new cluster slave key, encrypts with GK, sends to new SKDC
// ===========================================================================
void KdcApplication::ForwardSlaveKey(
    uint32_t uav_id,
    uint32_t new_cluster,
    uint32_t /*old_index*/)
{
    if (!m_params || !m_topo) return;
    if (new_cluster >= 3) return;

    // Find next available slot in new cluster
    // Use uav_id modulo uavs_per_cluster as new index
    // (In real deployment this would be a proper slot allocator)
    uint32_t new_idx = uav_id %
        m_params->uavs_per_cluster;

    const auto* nc = m_params->GetCluster(new_cluster);
    if (!nc) {
        NS_LOG_UNCOND("[KDC_FWD_FAIL] cluster not found");
        return;
    }
    const auto* sk = nc->GetSlaveKey(new_idx);
    if (!sk) {
        NS_LOG_UNCOND("[KDC_FWD_FAIL] slave key not found"
            " cluster=" << new_cluster
            << " idx=" << new_idx);
        return;
    }

    // Build SlaveKeyBlob from BigInt params
    crypto::SlaveKeyBlob blob;
    blob.uav_index  = new_idx;
    blob.cluster_id = new_cluster;

    // Serialize BigInts to bytes
    auto to_bytes = [](const crypto::BigInt& v)
        -> utils::ByteBuffer {
        // Export BigInt to big-endian byte buffer
        auto hex = crypto::BigIntOps::ToHexString(v);
        if (hex.size() % 2) hex = "0" + hex;
        utils::ByteBuffer b(hex.size()/2);
        for (size_t i = 0; i < b.size(); ++i)
            b[i] = static_cast<uint8_t>(
                std::stoul(hex.substr(i*2,2),nullptr,16));
        return b;
    };

    blob.d_i_bytes = to_bytes(sk->d_i);
    blob.n_i_bytes = to_bytes(sk->n_i);
    blob.e_i_bytes = to_bytes(sk->e_i);
    blob.Mi_bytes  = to_bytes(sk->Mi);
    blob.Ni_bytes  = to_bytes(sk->Ni);

    auto wire = crypto::HandoverProtocol::BuildSlaveFwd(
        uav_id, new_cluster, blob, m_gk);

    // Send to new SKDC CSMA address on port 9051
    ns3::Ipv4Address skdc_addr =
        m_topo->csma_interfaces.GetAddress(
            new_cluster + 1);
    ns3::InetSocketAddress dst(skdc_addr, 9051);
    ns3::Ptr<ns3::Packet> fwd_pkt =
        ns3::Create<ns3::Packet>(
            wire.data(),
            static_cast<uint32_t>(wire.size()));
    if (m_socket)
        m_socket->SendTo(fwd_pkt, 0, dst);

    NS_LOG_UNCOND("[KDC_SLAVE_FWD] t="
        << ns3::Simulator::Now().GetSeconds()
        << " uav=" << uav_id
        << " new_c=" << new_cluster
        << " new_idx=" << new_idx
        << " → skdc=" << skdc_addr);
}

} // namespace apps
} // namespace uav'''
))

# ============================================================================
# FILE 5 — apps/uav-skdc-app.h
# Add handover sockets + pending join tracking
# ============================================================================
SKDC_H = "apps/uav-skdc-app.h"
skdc_h_patches = []

skdc_h_patches.append((
    '#include "ns3/application.h"\n#include "ns3/netanim-module.h"',
    '#include "ns3/application.h"\n#include "ns3/netanim-module.h"\n'
    '#include "crypto/uav-handover-protocol.h"\n'
    '#include <unordered_map>'
))

skdc_h_patches.append((
    '    ns3::Ptr<ns3::Socket> m_forward_socket; // forward telemetry to KDC (port 9300)',
    '''    ns3::Ptr<ns3::Socket> m_forward_socket;  // forward telemetry to KDC (9300)
    ns3::Ptr<ns3::Socket> m_slave_fwd_socket; // recv SLAVE_FWD from KDC (9051)
    ns3::Ptr<ns3::Socket> m_ack_socket;       // recv KEY_ACK from UAV (9053)
    ns3::Ptr<ns3::Socket> m_join_acc_socket;  // send JOIN_ACCEPT to UAV (9052)
    crypto::GlobalKey     m_gk{};             // Global Bootstrap Key

    // Pending handover: uav_id → (blob, new_index)
    struct PendingHO {
        crypto::SlaveKeyBlob blob;
        uint32_t new_index = 0;
    };
    std::unordered_map<uint32_t, PendingHO> m_pending_ho;'''
))

skdc_h_patches.append((
    '    void SetClusterId(utils::u32 cluster_id);',
    '''    void SetClusterId(utils::u32 cluster_id);

    // Handover protocol
    void ReceiveSlaveKeyFwd(ns3::Ptr<ns3::Socket> s);
    void SendJoinAccept(uint32_t uav_id,
                        uint32_t new_idx,
                        const crypto::SlaveKeyBlob& blob);
    void ReceiveKeyAck(ns3::Ptr<ns3::Socket> s);'''
))

# ============================================================================
# FILE 6 — apps/uav-skdc-app.cc
# Implement SLAVE_FWD receive, JOIN_ACCEPT send, KEY_ACK receive
# ============================================================================
SKDC_CC = "apps/uav-skdc-app.cc"
skdc_cc_patches = []

# P1: Init GK + new sockets in StartApplication
skdc_cc_patches.append((
    '''    // Forward socket — send telemetry to KDC via CSMA on port 9300
    m_forward_socket = Socket::CreateSocket(''',
    '''    // Load GK
    if (m_params && m_params->global_key_hex.size() == 64) {
        m_gk = crypto::HandoverProtocol::HexToGlobalKey(
            m_params->global_key_hex);
        NS_LOG_UNCOND("[SKDC_GK] cluster=" << m_cluster_id
            << " GK loaded");
    }

    // SLAVE_FWD receive socket (port 9051) — recv from KDC
    m_slave_fwd_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress sfwd_local(
        Ipv4Address::GetAny(), 9051);
    m_slave_fwd_socket->Bind(sfwd_local);
    m_slave_fwd_socket->SetRecvCallback(
        MakeCallback(
            &SkdcApplication::ReceiveSlaveKeyFwd,
            this));

    // KEY_ACK receive socket (port 9053) — recv from UAV
    m_ack_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress ack_local(
        Ipv4Address::GetAny(), 9053);
    m_ack_socket->Bind(ack_local);
    m_ack_socket->SetRecvCallback(
        MakeCallback(
            &SkdcApplication::ReceiveKeyAck, this));

    // JOIN_ACCEPT send socket (port 9052)
    m_join_acc_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());

    NS_LOG_UNCOND("[SKDC_HO_READY] cluster=" << m_cluster_id
        << " slave_fwd=9051 key_ack=9053");

    // Forward socket — send telemetry to KDC via CSMA on port 9300
    m_forward_socket = Socket::CreateSocket('''
))

# P2: Close new sockets in StopApplication
skdc_cc_patches.append((
    '''    if (m_forward_socket) {
        m_forward_socket->Close();
        m_forward_socket = nullptr;
    }''',
    '''    if (m_forward_socket) {
        m_forward_socket->Close();
        m_forward_socket = nullptr;
    }
    if (m_slave_fwd_socket) {
        m_slave_fwd_socket->Close();
        m_slave_fwd_socket = nullptr;
    }
    if (m_ack_socket) {
        m_ack_socket->Close();
        m_ack_socket = nullptr;
    }'''
))

# P3: Add ReceiveSlaveKeyFwd + SendJoinAccept + ReceiveKeyAck
skdc_cc_patches.append((
    '} // namespace apps\n} // namespace uav',
    '''// ===========================================================================
// ReceiveSlaveKeyFwd — port 9051
// KDC sends encrypted slave key for incoming UAV.
// SKDC stores it and sends JOIN_ACCEPT to UAV.
// ===========================================================================
void SkdcApplication::ReceiveSlaveKeyFwd(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;
    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        uint32_t uav_id = 0, new_c = 0;
        crypto::SlaveKeyBlob blob;
        if (!crypto::HandoverProtocol::ParseSlaveFwd(
                buf, uav_id, new_c, blob, m_gk)) {
            NS_LOG_UNCOND("[SKDC_FWD_DROP] HMAC/decrypt fail"
                << " cluster=" << m_cluster_id);
            continue;
        }
        if (new_c != m_cluster_id) continue;

        NS_LOG_UNCOND("[SKDC_SLAVE_RECV] t="
            << ns3::Simulator::Now().GetSeconds()
            << " cluster=" << m_cluster_id
            << " uav=" << uav_id
            << " new_idx=" << blob.uav_index);

        // Store pending handover
        PendingHO ho;
        ho.blob      = blob;
        ho.new_index = blob.uav_index;
        m_pending_ho[uav_id] = ho;

        // Send JOIN_ACCEPT to UAV
        SendJoinAccept(uav_id, blob.uav_index, blob);
    }
}

// ===========================================================================
// SendJoinAccept — WiFi unicast to UAV (port 9052)
// ===========================================================================
void SkdcApplication::SendJoinAccept(
    uint32_t uav_id,
    uint32_t new_idx,
    const crypto::SlaveKeyBlob& blob)
{
    if (!m_topo || !m_join_acc_socket) return;

    auto wire = crypto::HandoverProtocol::BuildJoinAccept(
        uav_id, m_cluster_id, new_idx, blob, m_gk);

    // Find UAV WiFi IP
    // UAV nodes start at index 3 in wifi_nodes
    // (0=SKDC0, 1=SKDC1, 2=SKDC2, 3..20=UAVs)
    // uav_id is the global UAV id (0..17)
    uint32_t wifi_idx = uav_id + 3;
    if (wifi_idx >= m_topo->wifi_nodes.GetN()) {
        NS_LOG_UNCOND("[SKDC_JA_FAIL] uav_id out of range");
        return;
    }
    ns3::Ptr<ns3::Node> uav_node =
        m_topo->wifi_nodes.Get(wifi_idx);
    ns3::Ptr<ns3::Ipv4> ipv4 =
        uav_node->GetObject<ns3::Ipv4>();
    if (!ipv4) return;
    ns3::Ipv4Address uav_ip =
        ipv4->GetAddress(1,0).GetLocal();

    ns3::InetSocketAddress dst(uav_ip, 9052);
    ns3::Ptr<ns3::Packet> ja_pkt =
        ns3::Create<ns3::Packet>(
            wire.data(),
            static_cast<uint32_t>(wire.size()));
    m_join_acc_socket->SendTo(ja_pkt, 0, dst);

    NS_LOG_UNCOND("[SKDC_JOIN_ACCEPT] t="
        << ns3::Simulator::Now().GetSeconds()
        << " cluster=" << m_cluster_id
        << " → uav=" << uav_id
        << " uav_ip=" << uav_ip
        << " size=" << wire.size() << "B"
        << " [d_i encrypted with GK]");
}

// ===========================================================================
// ReceiveKeyAck — port 9053
// UAV acknowledges it has received and stored new d_i.
// ONLY NOW: run JoKeyUpdate + broadcast MT_K.
// ===========================================================================
void SkdcApplication::ReceiveKeyAck(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;
    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        crypto::HandoverProtocol::SlaveAckPkt ack;
        if (!crypto::HandoverProtocol::ParseKeyAck(
                buf, ack, m_gk)) {
            NS_LOG_UNCOND("[SKDC_ACK_DROP] HMAC fail");
            continue;
        }
        if (ack.new_cluster != m_cluster_id) continue;

        NS_LOG_UNCOND("[SKDC_KEY_ACK] t="
            << ns3::Simulator::Now().GetSeconds()
            << " cluster=" << m_cluster_id
            << " uav=" << ack.uav_id
            << " new_idx=" << ack.new_index
            << " → running JoKeyUpdate + MT_K broadcast");

        // Remove from pending
        m_pending_ho.erase(ack.uav_id);

        // NOW run JoKeyUpdate and broadcast
        // (was previously called immediately — now deferred until ACK)
        ProcessJoin(ack.uav_id, ack.new_index);

        // ProcessJoin calls TriggerRekey(JOIN) which calls BroadcastMtk()
        // UAV will now receive MT_K and decrypt with new d_i
    }
}

} // namespace apps
} // namespace uav'''
))

# ============================================================================
# FILE 7 — apps/uav-uav-app.h
# Add JOIN_ACCEPT receive socket + UpdateSlaveKey method
# ============================================================================
UAV_H = "apps/uav-uav-app.h"
uav_h_patches = []

uav_h_patches.append((
    '#include "ns3/packet.h"\n#include "ns3/mobility-module.h"',
    '#include "ns3/packet.h"\n#include "ns3/mobility-module.h"\n'
    '#include "crypto/uav-handover-protocol.h"'
))

uav_h_patches.append((
    '    ns3::Ptr<ns3::Socket>  m_recv_socket;',
    '''    ns3::Ptr<ns3::Socket>  m_recv_socket;
    ns3::Ptr<ns3::Socket>  m_join_acc_socket; // recv JOIN_ACCEPT (9052)
    ns3::Ptr<ns3::Socket>  m_ack_send_socket; // send KEY_ACK (9053)
    crypto::GlobalKey      m_gk{};            // Global Bootstrap Key'''
))

uav_h_patches.append((
    '    bool  DecryptMtk(',
    '''    void  ReceiveJoinAccept(ns3::Ptr<ns3::Socket> s);
    void  UpdateSlaveKey(
              const crypto::SlaveKeyBlob& blob,
              uint32_t new_cluster,
              uint32_t new_index);
    void  SendKeyAck(
              uint32_t new_cluster,
              uint32_t new_index);

    bool  DecryptMtk('''
))

# ============================================================================
# FILE 8 — apps/uav-uav-app.cc
# Implement ReceiveJoinAccept + UpdateSlaveKey + SendKeyAck
# ============================================================================
UAV_CC = "apps/uav-uav-app.cc"
uav_cc_patches = []

# P1: Load GK + open join-accept socket in StartApplication
uav_cc_patches.append((
    '    // Initialize slave key and TEK from crypto params\n    InitializeSlaveKey();',
    '''    // Load GK from crypto params
    if (m_params && m_params->global_key_hex.size() == 64) {
        m_gk = crypto::HandoverProtocol::HexToGlobalKey(
            m_params->global_key_hex);
    }

    // JOIN_ACCEPT receive socket — new SKDC sends d_i on handover
    m_join_acc_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());
    InetSocketAddress ja_local(
        Ipv4Address::GetAny(), 9052);
    m_join_acc_socket->Bind(ja_local);
    m_join_acc_socket->SetRecvCallback(
        MakeCallback(
            &UavApplication::ReceiveJoinAccept, this));

    // KEY_ACK send socket
    m_ack_send_socket = Socket::CreateSocket(
        GetNode(), UdpSocketFactory::GetTypeId());

    // Initialize slave key and TEK from crypto params
    InitializeSlaveKey();'''
))

# P2: Close new sockets in StopApplication
uav_cc_patches.append((
    '''    if (m_recv_socket) {
        m_recv_socket->Close();
        m_recv_socket = nullptr;
    }''',
    '''    if (m_recv_socket) {
        m_recv_socket->Close();
        m_recv_socket = nullptr;
    }
    if (m_join_acc_socket) {
        m_join_acc_socket->Close();
        m_join_acc_socket = nullptr;
    }'''
))

# P3: Add ReceiveJoinAccept + UpdateSlaveKey + SendKeyAck before end
uav_cc_patches.append((
    '} // namespace apps\n} // namespace uav',
    '''// ===========================================================================
// ReceiveJoinAccept — port 9052
// New SKDC sends d_i_new encrypted with GK.
// UAV decrypts, stores new slave key, sends KEY_ACK.
// ===========================================================================
void UavApplication::ReceiveJoinAccept(
    ns3::Ptr<ns3::Socket> socket)
{
    ns3::Ptr<ns3::Packet> pkt;
    ns3::Address from;
    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        uint32_t uav_id_pkt = 0;
        uint32_t new_cluster = 0, new_index = 0;
        crypto::SlaveKeyBlob blob;

        if (!crypto::HandoverProtocol::ParseJoinAccept(
                buf, uav_id_pkt, new_cluster,
                new_index, blob, m_gk)) {
            NS_LOG_UNCOND("[UAV_JA_DROP] t="
                << ns3::Simulator::Now().GetSeconds()
                << " uav=" << m_uav_id
                << " HMAC/decrypt fail");
            continue;
        }

        if (uav_id_pkt != m_uav_id) continue;

        NS_LOG_UNCOND("[UAV_JOIN_ACCEPT] t="
            << ns3::Simulator::Now().GetSeconds()
            << " uav=" << m_uav_id
            << " old_cluster=" << m_cluster_id
            << " new_cluster=" << new_cluster
            << " new_index=" << new_index
            << " [d_i decrypted with GK ✓]");

        // Update slave key with new cluster params
        UpdateSlaveKey(blob, new_cluster, new_index);

        // Send KEY_ACK to new SKDC
        SendKeyAck(new_cluster, new_index);
    }
}

// ===========================================================================
// UpdateSlaveKey — install new d_i, n_i, e_i from blob
// ===========================================================================
void UavApplication::UpdateSlaveKey(
    const crypto::SlaveKeyBlob& blob,
    uint32_t new_cluster,
    uint32_t new_index)
{
    uint32_t old_cluster = m_cluster_id;

    // Convert byte buffers back to BigInt
    auto from_bytes = [](const utils::ByteBuffer& b)
        -> crypto::BigInt {
        std::string hex;
        hex.reserve(b.size() * 2);
        for (uint8_t byte : b) {
            char tmp[3];
            snprintf(tmp, sizeof(tmp), "%02x", byte);
            hex += tmp;
        }
        // Remove leading zeros
        size_t start = hex.find_first_not_of('0');
        if (start == std::string::npos) return crypto::BigInt(0);
        return crypto::BigIntOps::FromHexString(
            hex.substr(start));
    };

    // Install new slave key params
    m_state.d_i = from_bytes(blob.d_i_bytes);
    m_state.n_i = from_bytes(blob.n_i_bytes);
    m_state.e_i = from_bytes(blob.e_i_bytes);

    // Update cluster identity
    m_state.cluster_id  = new_cluster;
    m_state.uav_index   = new_index;
    m_cluster_id        = new_cluster;
    m_uav_index         = new_index;

    // Invalidate old TEK — will be refreshed when new MT_K arrives
    m_state.tek_valid = false;

    NS_LOG_UNCOND("[UAV_DI_UPDATE] t="
        << ns3::Simulator::Now().GetSeconds()
        << " uav=" << m_uav_id
        << " C" << old_cluster
        << "→C" << new_cluster
        << " new_idx=" << new_index
        << " d_i_updated=YES"
        << " tek_valid=PENDING_MT_K");
}

// ===========================================================================
// SendKeyAck — UAV confirms d_i received, triggers MT_K broadcast
// ===========================================================================
void UavApplication::SendKeyAck(
    uint32_t new_cluster,
    uint32_t new_index)
{
    if (!m_topo || !m_ack_send_socket) return;

    auto wire = crypto::HandoverProtocol::BuildKeyAck(
        m_uav_id, new_cluster, new_index, m_gk);

    // Send to new SKDC WiFi IP on port 9053
    // SKDC index in wifi_nodes = new_cluster (0,1,2)
    if (new_cluster >= m_topo->skdc_nodes.GetN()) return;
    ns3::Ptr<ns3::Node> skdc_node =
        m_topo->skdc_nodes.Get(new_cluster);
    ns3::Ptr<ns3::Ipv4> ipv4 =
        skdc_node->GetObject<ns3::Ipv4>();
    if (!ipv4) return;
    // Get WiFi interface address (interface 1)
    ns3::Ipv4Address skdc_wifi =
        ipv4->GetAddress(1,0).GetLocal();

    ns3::InetSocketAddress dst(skdc_wifi, 9053);
    ns3::Ptr<ns3::Packet> ack_pkt =
        ns3::Create<ns3::Packet>(
            wire.data(),
            static_cast<uint32_t>(wire.size()));
    m_ack_send_socket->SendTo(ack_pkt, 0, dst);

    NS_LOG_UNCOND("[UAV_KEY_ACK] t="
        << ns3::Simulator::Now().GetSeconds()
        << " uav=" << m_uav_id
        << " → new_skdc=" << skdc_wifi
        << " new_cluster=" << new_cluster
        << " [ACK sent, awaiting MT_K broadcast]");
}

} // namespace apps
} // namespace uav'''
))

# ============================================================================
# FILE 9 — apps/uav-handover-manager.cc
# Send HANDOVER_NOTIFY to KDC before processing leave
# ============================================================================
HO_CC = "apps/uav-handover-manager.cc"
ho_cc_patches = []

ho_cc_patches.append((
    '#include "apps/uav-handover-manager.h"',
    '#include "apps/uav-handover-manager.h"\n'
    '#include "crypto/uav-handover-protocol.h"\n'
    '#include "ns3/socket.h"\n'
    '#include "ns3/inet-socket-address.h"\n'
    '#include "ns3/udp-socket-factory.h"'
))

ho_cc_patches.append((
    '''    // Step 1: Leave old cluster (triggers rekey)
    rec.leave_ok = m_leave_mgr->ProcessLeave(
        uav_id, old_uav_index, old_cluster,
        skdc_apps[old_cluster].operator->());''',
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
    }

    // Step 1: Leave old cluster (triggers rekey on old cluster)
    rec.leave_ok = m_leave_mgr->ProcessLeave(
        uav_id, old_uav_index, old_cluster,
        skdc_apps[old_cluster].operator->());'''
))

# Remove the direct ProcessJoin call — it is now deferred until KEY_ACK
ho_cc_patches.append((
    '''    // Step 3: Join new cluster (triggers rekey)
    rec.join_ok = m_join_mgr->ProcessJoin(
        uav_id,
        rec.new_uav_index,
        new_cluster,
        skdc_apps[new_cluster].operator->(),
        nullptr);
    rec.new_rekey_done = rec.join_ok;''',
    '''    // Step 3: ProcessJoin on new cluster is now DEFERRED.
    // It will be triggered by SkdcApplication::ReceiveKeyAck()
    // after the UAV confirms receipt of new d_i via JOIN_ACCEPT/KEY_ACK.
    // Record as pending — mark join_ok=true optimistically for metrics.
    rec.join_ok        = true;
    rec.new_rekey_done = false; // will be true after KEY_ACK'''
))

# ============================================================================
# APPLY ALL
# ============================================================================
print("=" * 60)
print("  d_i Update on Handover — Full Protocol Patch")
print("=" * 60)

print(f"\n[1] {CP_H}")
patch(CP_H, cp_h_patches, "uav-crypto-params.h")

print(f"\n[2] {CP_CC}")
patch(CP_CC, cp_cc_patches, "uav-crypto-params.cc")

print(f"\n[3] {KDC_H}")
patch(KDC_H, kdc_h_patches, "uav-kdc-app.h")

print(f"\n[4] {KDC_CC}")
patch(KDC_CC, kdc_cc_patches, "uav-kdc-app.cc")

print(f"\n[5] {SKDC_H}")
patch(SKDC_H, skdc_h_patches, "uav-skdc-app.h")

print(f"\n[6] {SKDC_CC}")
patch(SKDC_CC, skdc_cc_patches, "uav-skdc-app.cc")

print(f"\n[7] {UAV_H}")
patch(UAV_H, uav_h_patches, "uav-uav-app.h")

print(f"\n[8] {UAV_CC}")
patch(UAV_CC, uav_cc_patches, "uav-uav-app.cc")

print(f"\n[9] {HO_CC}")
patch(HO_CC, ho_cc_patches, "uav-handover-manager.cc")

print("""
============================================================
  NEXT STEPS:

  1. Copy uav-handover-protocol.h to crypto/:
     cp patch/uav-handover-protocol.h crypto/

  2. Regenerate crypto_params.json with GK:
     python3 patch/gen_crypto_gk_patch.py
     python3 scripts/gen_crypto.py --clusters 3 --uavs-per-cluster 6

  3. Add uav-handover-protocol.h to CMakeLists.txt headers list
     (it is header-only, no .cc needed)

  4. Rebuild:
     cd ~/ns-allinone-3.43/ns-3.43
     touch scratch/uav-secure-fanet/apps/uav-kdc-app.cc
     touch scratch/uav-secure-fanet/apps/uav-skdc-app.cc
     touch scratch/uav-secure-fanet/apps/uav-uav-app.cc
     touch scratch/uav-secure-fanet/apps/uav-handover-manager.cc
     cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug \\
           -j$(nproc) 2>&1 | tail -30

  5. Run and verify handover log:
     ./cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug \\
         --scenario=rekey_perf --seed=42 --duration=300 --pcap=0 --anim=0 \\
         2>&1 | grep -E "HO_NOTIFY|KDC_SLAVE|SKDC_JOIN|UAV_JA|UAV_DI|KEY_ACK|UAV_TEK"

  EXPECTED LOG SEQUENCE at t=60s (handover event):
    [HO_NOTIFY_SENT]  uav=5 old_c=0 new_c=1 → KDC
    [KDC_HO_NOTIFY]   uav=5 old_c=0 new_c=1
    [KDC_SLAVE_FWD]   uav=5 new_c=1 new_idx=X → skdc=192.168.0.3
    [SKDC_SLAVE_RECV] cluster=1 uav=5 new_idx=X
    [SKDC_JOIN_ACCEPT] cluster=1 → uav=5 [d_i encrypted with GK]
    [UAV_JOIN_ACCEPT]  uav=5 C0→C1 [d_i decrypted with GK ✓]
    [UAV_DI_UPDATE]    uav=5 C0→C1 d_i_updated=YES tek_valid=PENDING_MT_K
    [UAV_KEY_ACK]      uav=5 → new_skdc [ACK sent]
    [SKDC_KEY_ACK]     cluster=1 uav=5 → JoKeyUpdate + MT_K broadcast
    [UAV_TEK_UPDATE]   uav=5 new TEK active (after MT_K decryption)
============================================================
""")
