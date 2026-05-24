/**
 * apps/uav-uav-app.cc
 * Module 37 - UAV Application
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
// TypeId
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
// Configuration
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
// StartApplication
// ===========================================================================
void UavApplication::StartApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: starting"
        " uav=" << m_uav_id
        << " cluster=" << m_cluster_id
        << " node=" << GetNode()->GetId());

    // Receive socket — listen for MTK + REKEY
    m_recv_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    InetSocketAddress local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9200));
    m_recv_socket->Bind(local);
    m_recv_socket->SetRecvCallback(
        MakeCallback(
            &UavApplication::ReceivePacket,
            this));

    // Send socket — unicast data to SKDC
    m_send_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());

    // Initialize slave key from crypto params
    InitializeSlaveKey();

    // Generate HMAC key
    m_state.hmac_key =
        crypto::HmacSha256Util::GenerateKey();

    // Schedule telemetry sending
    ScheduleTelemetry();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: started"
        " uav=" << m_uav_id
        << " tek_valid=" << m_state.tek_valid);
}

// ===========================================================================
// StopApplication
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

    // Load initial TEK directly from params
    m_state.current_tek = cluster->tek;
    m_state.tek_valid   = true;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "UavApplication: slave key loaded"
        " uav=" << m_uav_id
        << " index=" << m_uav_index
        << " n_i=" << crypto::BigIntOps::ToDecString(
            m_state.n_i).substr(0,20) << "...");
}

// ===========================================================================
// DecryptMtk
// Core CRT slave decryption:
//   recovered = pow(MT_K, d_i, n_i)
//   if recovered == tek_int % n_i → TEK verified
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
// SendData — encrypt with TEK and send to SKDC
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

    // Build encrypted data packet
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

    // Send to SKDC WiFi address
    // SKDCs are on CSMA only — send to broadcast
    Ptr<Packet> ns3pkt = Create<Packet>(
        wire.data(),
        static_cast<uint32_t>(wire.size()));

    InetSocketAddress dst(
        Ipv4Address("255.255.255.255"),
        static_cast<uint16_t>(9600));
    m_send_socket->SendTo(ns3pkt, 0, dst);

    ++m_data_sent;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "UavApplication: data sent"
        " uav=" << m_uav_id
        << " seq=" << m_state.data_seq
        << " size=" << wire.size() << "B");
}

// ===========================================================================
// SendTelemetry — periodic encrypted telemetry
// ===========================================================================
void UavApplication::SendTelemetry() {
    if (!m_state.tek_valid) {
        ScheduleTelemetry();
        return;
    }

    // Build telemetry payload
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
// ===========================================================================
void UavApplication::ReceivePacket(
    Ptr<Socket> socket)
{
    Ptr<Packet> pkt;
    Address from;

    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        if (sz < 4) continue;

        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        // Peek packet type (byte 3)
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
            break;
        }
    }
}

// ===========================================================================
// ProcessMtkPacket
// ===========================================================================
void UavApplication::ProcessMtkPacket(
    const utils::ByteBuffer& wire)
{
    try {
        auto pkt = MtkPacket::Deserialize(
            wire, m_state.hmac_key);

        // Only process if for our cluster
        if (pkt.GetBody().cluster_id !=
            m_cluster_id) return;

        // Check version
        if (pkt.GetBody().version <=
            m_state.rekey_version) return;

        m_state.rekey_version =
            pkt.GetBody().version;

        // Decrypt MT_K using slave key
        DecryptMtk(pkt.GetBody().mtk,
                   pkt.GetBody().n_group);

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
// ProcessRekeyPacket
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

        UAV_LOG_INFO(uav::log::channels::CRYPTO,
            "UavApplication: REKEY received"
            " uav=" << m_uav_id
            << " version="
            << pkt.GetBody().version
            << " reason="
            << RekeyReasonToString(
                   pkt.GetBody().reason));

        // Re-decrypt with new MT_K
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
// Scheduling
// ===========================================================================
void UavApplication::ScheduleTelemetry() {
    // Send telemetry every 3 seconds
    Simulator::Schedule(
        Seconds(3.0),
        &UavApplication::SendTelemetry,
        this);
}

// ===========================================================================
// GetSkdcWifiAddr
// ===========================================================================
Ipv4Address UavApplication::GetSkdcWifiAddr()
    const
{
    // SKDC is not on WiFi — UAVs broadcast
    return Ipv4Address("255.255.255.255");
}

} // namespace apps
} // namespace uav
