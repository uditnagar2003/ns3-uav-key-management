/**
 * apps/uav-kdc-app.cc
 * Module 35 - KDC Application
 */

#include "apps/uav-kdc-app.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-time-utils.h"
#include "crypto/uav-hmac.h"
#include "crypto/uav-aes.h"

#include "ns3/udp-socket-factory.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/packet.h"

NS_LOG_COMPONENT_DEFINE("UavKdcApp");

using namespace ns3;
using namespace uav::packet;

namespace uav {
namespace apps {

// ===========================================================================
// TypeId
// ===========================================================================
ns3::TypeId KdcApplication::GetTypeId() {
    static ns3::TypeId tid =
        ns3::TypeId("uav::apps::KdcApplication")
        .SetParent<ns3::Application>()
        .SetGroupName("UavSecureFanet")
        .AddConstructor<KdcApplication>();
    return tid;
}

// ===========================================================================
// Constructor / Destructor
// ===========================================================================
KdcApplication::KdcApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: constructed");
}

KdcApplication::~KdcApplication() = default;

// ===========================================================================
// Configuration
// ===========================================================================
void KdcApplication::SetTopology(
    const routing::TopologyResult* topo)
{
    m_topo = topo;
}

void KdcApplication::SetCryptoParams(
    const crypto::CryptoParamsFile* params)
{
    m_params = params;
}

// ===========================================================================
// StartApplication
// ===========================================================================
void KdcApplication::StartApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: starting on node "
        << GetNode()->GetId());

    // Create UDP socket
    m_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());

    InetSocketAddress local(
        Ipv4Address::GetAny(),
        static_cast<uint16_t>(9000));
    m_socket->Bind(local);

    // Initialize crypto state
    InitializeClusters();

    // Packet manager initialized on demand

    // Schedule initial TEK distribution
    Simulator::Schedule(
        Seconds(1.0),
        &KdcApplication::SendTekToAllSkdcs,
        this);

    // Schedule periodic sync
    SchedulePeriodicSync();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: started"
        " clusters=" << m_clusters.size());
}

// ===========================================================================
// StopApplication
// ===========================================================================
void KdcApplication::StopApplication() {
    if (m_socket) {
        m_socket->Close();
        m_socket = nullptr;
    }
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: stopped"
        " tx=" << m_tx_count
        << " rekeys=" << m_rekey_count);
}

// ===========================================================================
// InitializeClusters
// ===========================================================================
void KdcApplication::InitializeClusters() {
    for (utils::u32 c = 0; c < 3; ++c) {
        m_clusters[c].cluster_id    = c;
        m_clusters[c].skdc_node     = c + 1;
        m_clusters[c].rekey_version = 1;
        m_clusters[c].member_count  = 6;

        if (m_params &&
            c < m_params->clusters.size())
        {
            m_clusters[c].current_tek =
                m_params->clusters[c].tek;
            m_clusters[c].current_mt_k =
                m_params->clusters[c].MT_K;
            m_clusters[c].initialized = true;
        }

        if (m_topo) {
            m_clusters[c].skdc_addr =
                m_topo->csma_interfaces
                      .GetAddress(c + 1);
        }

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "KdcApplication: cluster " << c
            << " initialized"
            << " skdc=" << m_clusters[c].skdc_addr
            << " version="
            << m_clusters[c].rekey_version);
    }
}

// ===========================================================================
// SendTekToSkdc
// ===========================================================================
void KdcApplication::SendTekToSkdc(
    utils::u32 cluster)
{
    if (!m_socket || !m_topo) return;
    if (cluster >= 3) return;

    auto& cs = m_clusters[cluster];
    SendControlPacket(
        cs.skdc_addr, cluster, cs.current_tek);

    ++m_tx_count;
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: TEK sent to SKDC"
        << cluster
        << " addr=" << cs.skdc_addr
        << " version=" << cs.rekey_version);
}

void KdcApplication::SendTekToAllSkdcs() {
    for (utils::u32 c = 0; c < 3; ++c)
        SendTekToSkdc(c);
}

// ===========================================================================
// TriggerRekey
// ===========================================================================
void KdcApplication::TriggerRekey(
    utils::u32 cluster,
    packet::RekeyReason reason)
{
    if (cluster >= 3) return;

    auto& cs = m_clusters[cluster];
    ++cs.rekey_version;
    ++m_rekey_count;

    // Generate new TEK
    cs.current_tek = crypto::AesGcm::GenerateKey();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: rekey cluster="
        << cluster
        << " reason=" << packet::RekeyReasonToString(reason)
        << " version=" << cs.rekey_version);

    // Distribute new TEK to SKDC
    SendTekToSkdc(cluster);
}

// ===========================================================================
// Getters
// ===========================================================================
const crypto::AesGcmKey& KdcApplication::GetTek(
    utils::u32 cluster) const
{
    static crypto::AesGcmKey empty{};
    if (cluster >= 3) return empty;
    return m_clusters[cluster].current_tek;
}

const KdcClusterState& KdcApplication::GetClusterState(
    utils::u32 cluster) const
{
    static KdcClusterState empty{};
    if (cluster >= 3) return empty;
    return m_clusters[cluster];
}

// ===========================================================================
// Periodic sync
// ===========================================================================
void KdcApplication::SchedulePeriodicSync() {
    // Sync every 30 seconds
    Simulator::Schedule(
        Seconds(30.0),
        &KdcApplication::PeriodicSync,
        this);
}

void KdcApplication::PeriodicSync() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "KdcApplication: periodic sync t="
        << Simulator::Now().GetSeconds());

    SendTekToAllSkdcs();
    SchedulePeriodicSync();
}

// ===========================================================================
// SendControlPacket — UDP to SKDC
// ===========================================================================
void KdcApplication::SendControlPacket(
    Ipv4Address dst,
    utils::u32 cluster,
    const crypto::AesGcmKey& tek)
{
    if (!m_socket) return;

    // Create minimal control payload
    // [cluster(4)][version(4)][tek_first8(8)]
    utils::ByteBuffer payload(16, 0x00);
    utils::ByteUtils::WriteU32BE(
        payload.data(), cluster);
    utils::ByteUtils::WriteU32BE(
        payload.data() + 4,
        m_clusters[cluster].rekey_version);
    std::memcpy(payload.data() + 8,
        tek.data(), 8);

    Ptr<Packet> pkt = Create<Packet>(
        payload.data(),
        static_cast<uint32_t>(payload.size()));

    InetSocketAddress remote(dst,
        static_cast<uint16_t>(9001));
    m_socket->SendTo(pkt, 0, remote);
}

} // namespace apps
} // namespace uav
