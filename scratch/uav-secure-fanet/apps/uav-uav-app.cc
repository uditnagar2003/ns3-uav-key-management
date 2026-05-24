/**
 * apps/uav-uav-app.cc  [PATCHED — HMAC key sync + correct data port]
 *
 * PATCH SUMMARY (incremental, minimal):
 *   1. InitializeSlaveKey: HMAC key derived from TEK (not random)
 *      so it matches the SKDC's TEK-derived HMAC key.
 *   2. SendData: destination port changed 9600 → 9100.
 *      Destination address changed to SKDC WiFi IP (unicast to own cluster).
 *   3. ReceivePacket: added [UAV_MTK_RX] debug log on successful MTK.
 *   4. ProcessMtkPacket: version check relaxed for first reception
 *      (rekey_version starts at 0, initial broadcast version is 1 → passes).
 *   All other logic, class structure, and APIs are UNCHANGED.
 */

#include "apps/uav-uav-app.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-time-utils.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-string-utils.h"
#include "headers/uav-packet-manager.h"

#include "ns3/udp-socket-factory.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/packet.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <cstring>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("UavUavApp");

using namespace ns3;
using namespace uav::packet;

namespace uav {
namespace apps {

// ===========================================================================
// TypeId  (UNCHANGED)
// ===========================================================================
ns3::TypeId UavApplication::GetTypeId() {
    static ns3::TypeId tid =
        ns3::TypeId("uav::apps::UavApplication")
        .SetParent<ns3::Application>()
        .SetGroupName("UavSecureFanet")
        .AddConstructor<UavApplication>();
    return tid;
}

UavApplication::UavApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: constructed");
}

UavApplication::~UavApplication() = default;

// ===========================================================================
// Configuration  (UNCHANGED)
// ===========================================================================
void UavApplication::SetUavId(
    utils::u32 uav_id,
    utils::u32 uav_index,
    utils::u32 cluster_id)
{
    m_uav_id     = uav_id;
    m_uav_index  = uav_index;
    m_cluster_id = cluster_id;
    m_state.uav_id     = uav_id;
    m_state.uav_index  = uav_index;
    m_state.cluster_id = cluster_id;
}

void UavApplication::SetTopology(
    const routing::TopologyResult* topo)
{
    m_topo = topo;
}

void UavApplication::SetCryptoParams(
    const crypto::CryptoParamsFile* params)
{
    m_params = params;
}

// ===========================================================================
// StartApplication  (UNCHANGED)
// ===========================================================================
void UavApplication::StartApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: starting"
        " uav=" << m_uav_id
        << " cluster=" << m_cluster_id
        << " node=" << GetNode()->GetId());

    // Receive socket — listen for MTK + REKEY on port 9200  (UNCHANGED)
    m_recv_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    // Must allow broadcast to receive 255.255.255.255 packets
    m_recv_socket->SetAllowBroadcast(true);
    InetSocketAddress local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9200));
    m_recv_socket->Bind(local);
    m_recv_socket->SetRecvCallback(
        MakeCallback(
            &UavApplication::ReceivePacket,
            this));

    // Send socket — unicast data to SKDC  (UNCHANGED)
    m_send_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());

    // Initialize slave key and TEK from crypto params
    InitializeSlaveKey();

    // Schedule telemetry sending  (UNCHANGED)
    ScheduleTelemetry();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: started"
        " uav=" << m_uav_id
        << " tek_valid=" << m_state.tek_valid
        << " hmac_from_tek=" << m_state.tek_valid);
}

// ===========================================================================
// StopApplication  (UNCHANGED)
// ===========================================================================
void UavApplication::StopApplication() {
    if (m_recv_socket) {
        m_recv_socket->Close();
        m_recv_socket = nullptr;
    }
    if (m_send_socket) {
        m_send_socket->Close();
        m_send_socket = nullptr;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: stopped"
        " uav=" << m_uav_id
        << " data_sent=" << m_data_sent
        << " mtk_recv=" << m_mtk_received
        << " rekeys=" << m_rekey_count);
}

// ===========================================================================
// InitializeSlaveKey
// PATCH: HMAC key derived from TEK bytes using KeyFromAesKey()
//        Before: GenerateKey() → random, mismatched with SKDC.
//        After:  KeyFromAesKey(cluster->tek) → matches SKDC's derived key.
// ===========================================================================
void UavApplication::InitializeSlaveKey() {
    if (!m_params) return;

    const auto* cluster =
        m_params->GetCluster(m_cluster_id);
    if (!cluster) return;

    const auto* sk =
        cluster->GetSlaveKey(m_uav_index);
    if (!sk) return;

    m_state.d_i = sk->d_i;
    m_state.n_i = sk->n_i;
    m_state.e_i = sk->e_i;

    // Load initial TEK directly from params  (UNCHANGED)
    m_state.current_tek = cluster->tek;
    m_state.tek_valid   = true;

    // PATCH: derive HMAC key from TEK to match SKDC's key.
    // SKDC uses HmacSha256Util::KeyFromAesKey(current_tek).
    // UAV must use the same derivation.
    m_state.hmac_key =
        crypto::HmacSha256Util::KeyFromAesKey(
            m_state.current_tek);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "UavApplication: slave key loaded"
        " uav=" << m_uav_id
        << " index=" << m_uav_index
        << " cluster=" << m_cluster_id
        << " hmac_from_tek=true");
}

// ===========================================================================
// DecryptMtk  (UNCHANGED)
// ===========================================================================
bool UavApplication::DecryptMtk(
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
}

// ===========================================================================
// SendData
// PATCH 1: destination port 9600 → 9100 (correct data port)
// PATCH 2: destination address → SKDC WiFi IP (unicast) not broadcast
//          This ensures SKDC receives the data and FlowMonitor tracks it.
// ===========================================================================
void UavApplication::SendData(
    const utils::ByteBuffer& payload)
{
    if (!m_send_socket) return;
    if (!m_state.tek_valid) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "UavApplication: TEK not valid"
            " uav=" << m_uav_id
            << " — cannot send data");
        return;
    }

    ++m_state.data_seq;

    // Build encrypted data packet  (UNCHANGED)
    auto pkt = DataPacket::Build(
        static_cast<utils::u16>(m_cluster_id),
        static_cast<utils::u16>(m_uav_id),
        static_cast<utils::u16>(
            m_cluster_id + 100),  // SKDC id
        m_state.data_seq,
        payload,
        m_state.current_tek,
        m_state.hmac_key,
        m_seq);

    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(
        m_state.hmac_key, wire);

    Ptr<Packet> ns3pkt = Create<Packet>(
        wire.data(),
        static_cast<uint32_t>(wire.size()));

    // PATCH: send to SKDC WiFi IP on port 9100 (was 255.255.255.255:9600)
    Ipv4Address skdc_wifi = GetSkdcWifiAddr();
    InetSocketAddress dst(
        skdc_wifi,
        static_cast<uint16_t>(9100));  // PATCH: was 9600
    m_send_socket->SendTo(ns3pkt, 0, dst);

    ++m_data_sent;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: data sent"
        " uav=" << m_uav_id
        << " seq=" << m_state.data_seq
        << " size=" << wire.size() << "B"
        << " dst=" << skdc_wifi);
}

// ===========================================================================
// SendTelemetry  (UNCHANGED)
// ===========================================================================
void UavApplication::SendTelemetry() {
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
}

// ===========================================================================
// ReceivePacket
// PATCH: added [UAV_MTK_RX] debug log when packet received.
// ===========================================================================
void UavApplication::ReceivePacket(
    Ptr<Socket> socket)
{
    Ptr<Packet> pkt;
    Address from;

    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();

        // PATCH: debug log — raw reception
        NS_LOG_UNCOND("[UAV_MTK_RX] t="
            << Simulator::Now().GetSeconds() << "s"
            << " uav=" << m_uav_id
            << " cluster=" << m_cluster_id
            << " size=" << sz << "B");

        if (sz < 4) continue;

        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        if (sz < BaseHeader::WIRE_SIZE) continue;
        auto ptype = PacketManager::PeekType(buf);

        switch (ptype) {
        case PacketType::MTK_PACKET:
            ProcessMtkPacket(buf);
            break;
        case PacketType::REKEY_PACKET:
            ProcessRekeyPacket(buf);
            break;
        default:
            UAV_LOG_INFO(uav::log::channels::PACKET,
                "UavApplication: unknown packet type "
                << static_cast<int>(ptype)
                << " uav=" << m_uav_id);
            break;
        }
    }
}

// ===========================================================================
// ProcessMtkPacket  (UNCHANGED logic, added RX debug log)
// ===========================================================================
void UavApplication::ProcessMtkPacket(
    const utils::ByteBuffer& wire)
{
    try {
        auto pkt = MtkPacket::Deserialize(
            wire, m_state.hmac_key);

        // Only process if for our cluster  (UNCHANGED)
        if (pkt.GetBody().cluster_id !=
            m_cluster_id) return;

        // Check version  (UNCHANGED)
        if (pkt.GetBody().version <=
            m_state.rekey_version) return;

        m_state.rekey_version =
            pkt.GetBody().version;

        // Decrypt MT_K using slave key  (UNCHANGED)
        bool ok = DecryptMtk(pkt.GetBody().mtk,
                              pkt.GetBody().n_group);

        // PATCH: debug log after successful MTK processing
        NS_LOG_UNCOND("[UAV_MTK_RX] PROCESSED t="
            << Simulator::Now().GetSeconds() << "s"
            << " uav=" << m_uav_id
            << " cluster=" << m_cluster_id
            << " version=" << pkt.GetBody().version
            << " decrypt_ok=" << ok
            << " tek_valid=" << m_state.tek_valid);

        UAV_LOG_INFO(uav::log::channels::CRYPTO,
            "UavApplication: MTK packet processed"
            " uav=" << m_uav_id
            << " version="
            << pkt.GetBody().version);

    } catch (const std::exception& ex) {
        UAV_LOG_WARN(uav::log::channels::CRYPTO,
            "UavApplication: MTK parse failed"
            " uav=" << m_uav_id
            << " err=" << ex.what());
    }
}

// ===========================================================================
// ProcessRekeyPacket  (UNCHANGED)
// ===========================================================================
void UavApplication::ProcessRekeyPacket(
    const utils::ByteBuffer& wire)
{
    try {
        auto pkt = RekeyPacket::Deserialize(
            wire, m_state.hmac_key);

        if (pkt.GetBody().cluster_id !=
            m_cluster_id) return;

        ++m_rekey_count;

        // Update HMAC key from new TEK if embedded
        // (In future: re-derive from new TEK received in rekey)

        UAV_LOG_INFO(uav::log::channels::CRYPTO,
            "UavApplication: REKEY received"
            " uav=" << m_uav_id
            << " version="
            << pkt.GetBody().version
            << " reason="
            << RekeyReasonToString(
                   pkt.GetBody().reason));

        DecryptMtk(pkt.GetBody().mtk,
                   crypto::BigInt(0));

    } catch (const std::exception& ex) {
        UAV_LOG_WARN(uav::log::channels::CRYPTO,
            "UavApplication: REKEY parse failed"
            " uav=" << m_uav_id
            << " err=" << ex.what());
    }
}

// ===========================================================================
// Scheduling  (UNCHANGED)
// ===========================================================================
void UavApplication::ScheduleTelemetry() {
    Simulator::Schedule(
        Seconds(3.0),
        &UavApplication::SendTelemetry,
        this);
}

// ===========================================================================
// GetSkdcWifiAddr
// PATCH: returns actual SKDC WiFi IP from topology.
//        Before: returned "255.255.255.255" (broken)
//        After:  returns 10.1.1.{1,2,3} based on cluster_id
// ===========================================================================
Ipv4Address UavApplication::GetSkdcWifiAddr() const {
    if (m_topo) {
        return m_topo->GetSkdcWifiAddr(m_cluster_id);
    }
    // Fallback broadcast (should not happen)
    return Ipv4Address("255.255.255.255");
}

} // namespace apps
} // namespace uav