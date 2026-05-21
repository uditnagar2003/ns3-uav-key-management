/**
 * apps/uav-skdc-app.cc
 * Module 36 - SKDC Application
 */

#include "apps/uav-skdc-app.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-time-utils.h"
#include "utils/uav-byte-utils.h"

#include "ns3/udp-socket-factory.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/packet.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <cstring>

NS_LOG_COMPONENT_DEFINE("UavSkdcApp");

using namespace ns3;
using namespace uav::packet;

namespace uav {
namespace apps {

// ===========================================================================
// TypeId
// ===========================================================================
ns3::TypeId SkdcApplication::GetTypeId() {
    static ns3::TypeId tid =
        ns3::TypeId("uav::apps::SkdcApplication")
        .SetParent<ns3::Application>()
        .SetGroupName("UavSecureFanet")
        .AddConstructor<SkdcApplication>();
    return tid;
}

// ===========================================================================
// Constructor / Destructor
// ===========================================================================
SkdcApplication::SkdcApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: constructed");
}

SkdcApplication::~SkdcApplication() = default;

// ===========================================================================
// Configuration
// ===========================================================================
void SkdcApplication::SetClusterId(
    utils::u32 cluster_id)
{
    m_cluster_id = cluster_id;
    m_state.cluster_id = cluster_id;
}

void SkdcApplication::SetTopology(
    const routing::TopologyResult* topo)
{
    m_topo = topo;
}

void SkdcApplication::SetCryptoParams(
    const crypto::CryptoParamsFile* params)
{
    m_params = params;
}

// ===========================================================================
// StartApplication
// ===========================================================================
void SkdcApplication::StartApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: starting cluster="
        << m_cluster_id
        << " node=" << GetNode()->GetId());

    // CSMA socket — receive TEK from KDC
    m_csma_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    InetSocketAddress csma_local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9001));
    m_csma_socket->Bind(csma_local);
    m_csma_socket->SetRecvCallback(
        MakeCallback(
            &SkdcApplication::ReceiveFromKdc,
            this));

    // WiFi socket — broadcast MT_K to UAVs
    m_wifi_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    m_wifi_socket->SetAllowBroadcast(true);
    InetSocketAddress wifi_local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9200));
    m_wifi_socket->Bind(wifi_local);

    // Initialize crypto state
    InitializeState();

    // Schedule initial MT_K broadcast
    ScheduleInitialBroadcast();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: started cluster="
        << m_cluster_id
        << " members=" << m_state.members.size());
}

// ===========================================================================
// StopApplication
// ===========================================================================
void SkdcApplication::StopApplication() {
    if (m_csma_socket) {
        m_csma_socket->Close();
        m_csma_socket = nullptr;
    }
    if (m_wifi_socket) {
        m_wifi_socket->Close();
        m_wifi_socket = nullptr;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: stopped cluster="
        << m_cluster_id
        << " mtk_broadcasts=" << m_mtk_count
        << " rekeys=" << m_rekey_count);
}

// ===========================================================================
// InitializeState
// ===========================================================================
void SkdcApplication::InitializeState() {
    m_state.cluster_id    = m_cluster_id;
    m_state.rekey_version = 1;
    m_state.tek_received  = false;

    // Generate HMAC key
    m_state.hmac_key =
        crypto::HmacSha256Util::GenerateKey();

    if (m_params &&
        m_cluster_id < m_params->clusters.size())
    {
        const auto& cp =
            m_params->clusters[m_cluster_id];

        m_state.current_tek = cp.tek;
        m_state.mt_k        = cp.MT_K;
        m_state.n_group     = cp.N_group;
        m_state.e_mk        = cp.e_MK;
        m_state.tek_received = true;

        // Initialize members (UAVs 0-5 in cluster)
        utils::u32 base = m_cluster_id * 6;
        for (utils::u32 u = 0; u < 6; ++u)
            m_state.members.insert(base + u);
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: state initialized"
        << " cluster=" << m_cluster_id
        << " tek_ok=" << m_state.tek_received
        << " members=" << m_state.members.size());
}

// ===========================================================================
// BroadcastMtk
// ===========================================================================
void SkdcApplication::BroadcastMtk() {
    if (!m_wifi_socket) return;
    if (!m_state.tek_received) return;
    if (m_state.mt_k <= 0) return;

    // Build MT_K packet
    auto pkt = MtkPacket::Build(
        m_cluster_id,
        static_cast<utils::u16>(
            GetNode()->GetId()),
        m_state.rekey_version,
        m_state.mt_k,
        m_state.n_group,
        m_state.hmac_key,
        m_seq);

    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(
        m_state.hmac_key, wire);

    // Broadcast to 10.1.1.255
    Ptr<Packet> ns3pkt = Create<Packet>(
        wire.data(),
        static_cast<uint32_t>(wire.size()));

    InetSocketAddress bcast(
        Ipv4Address("255.255.255.255"),
        static_cast<uint16_t>(9200));
    m_wifi_socket->SendTo(ns3pkt, 0, bcast);

    ++m_mtk_count;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: MT_K broadcast"
        << " cluster=" << m_cluster_id
        << " version=" << m_state.rekey_version
        << " size=" << wire.size() << "B");
}

// ===========================================================================
// ProcessJoin
// ===========================================================================
void SkdcApplication::ProcessJoin(
    utils::u32 uav_id,
    utils::u32 uav_index)
{
    m_state.members.insert(uav_id);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: UAV " << uav_id
        << " joined cluster=" << m_cluster_id
        << " members=" << m_state.members.size());

    TriggerRekey(RekeyReason::JOIN);
}

// ===========================================================================
// ProcessLeave
// ===========================================================================
void SkdcApplication::ProcessLeave(
    utils::u32 uav_id)
{
    m_state.members.erase(uav_id);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: UAV " << uav_id
        << " left cluster=" << m_cluster_id
        << " members=" << m_state.members.size());

    TriggerRekey(RekeyReason::LEAVE);
}

// ===========================================================================
// UpdateTek
// ===========================================================================
void SkdcApplication::UpdateTek(
    const crypto::AesGcmKey& tek)
{
    m_state.current_tek  = tek;
    m_state.tek_received = true;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: TEK updated"
        << " cluster=" << m_cluster_id);

    BroadcastMtk();
}

// ===========================================================================
// TriggerRekey
// ===========================================================================
void SkdcApplication::TriggerRekey(
    RekeyReason reason)
{
    ++m_state.rekey_version;
    ++m_rekey_count;

    // Rotate TEK: SHA256(TEK_old || timestamp)
    utils::ByteBuffer seed(
        m_state.current_tek.begin(),
        m_state.current_tek.end());
    utils::u64 ts =
        utils::TimeUtils::NowEpochMicros();
    utils::ByteUtils::AppendU64BE(seed, ts);

    auto new_key =
        crypto::HmacSha256Util::Compute(
            m_state.hmac_key, seed);
    std::memcpy(m_state.current_tek.data(),
        new_key.data(),
        std::min(new_key.size(),
            m_state.current_tek.size()));

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: rekey"
        << " cluster=" << m_cluster_id
        << " reason=" << RekeyReasonToString(reason)
        << " version=" << m_state.rekey_version);

    BroadcastMtk();
}

// ===========================================================================
// ReceiveFromKdc
// ===========================================================================
void SkdcApplication::ReceiveFromKdc(
    Ptr<Socket> socket)
{
    Ptr<Packet> pkt;
    Address from;

    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        if (sz < 16) continue;

        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

        // Parse: [cluster(4)][version(4)][tek(8)]
        utils::u32 cluster =
            utils::ByteUtils::ReadU32BE(buf.data());
        if (cluster != m_cluster_id) continue;

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "SkdcApplication: received from KDC"
            << " cluster=" << cluster);

        BroadcastMtk();
    }
}

// ===========================================================================
// Scheduling
// ===========================================================================
void SkdcApplication::ScheduleInitialBroadcast() {
    Simulator::Schedule(
        Seconds(2.0),
        &SkdcApplication::BroadcastMtk,
        this);
}

void SkdcApplication::SchedulePeriodicBroadcast() {
    Simulator::Schedule(
        Seconds(10.0),
        &SkdcApplication::PeriodicBroadcast,
        this);
}

void SkdcApplication::PeriodicBroadcast() {
    BroadcastMtk();
    SchedulePeriodicBroadcast();
}

// ===========================================================================
// WiFi address
// ===========================================================================
Ipv4Address SkdcApplication::GetWifiAddress()
    const
{
    // SKDC nodes are ground nodes (no WiFi)
    // They use CSMA only
    return Ipv4Address("0.0.0.0");
}

} // namespace apps
} // namespace uav
