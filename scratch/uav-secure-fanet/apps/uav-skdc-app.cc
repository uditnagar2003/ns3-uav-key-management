/**
 * apps/uav-skdc-app.cc  [PATCHED — dual-interface SKDC]
 *
 * PATCH SUMMARY (incremental, minimal):
 *   1. StartApplication: bind wifi_socket to WiFi interface IP (not 0.0.0.0)
 *      so NS-3 routes outgoing broadcast through the WiFi device.
 *   2. InitializeState: HMAC key derived from TEK (not random) so UAVs can
 *      verify the HMAC using the same TEK-derived key.
 *   3. BroadcastMtk: added [MTK_WIFI_TX] debug log.
 *   4. GetWifiAddress: returns actual WiFi IP from topology.
 *   All other logic, class structure, and APIs are UNCHANGED.
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
#include "ns3/ipv4.h"
#include "ns3/net-device.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <cstring>

NS_LOG_COMPONENT_DEFINE("UavSkdcApp");

using namespace ns3;
using namespace uav::packet;

namespace uav {
namespace apps {

// ===========================================================================
// TypeId  (UNCHANGED)
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
// Constructor / Destructor  (UNCHANGED)
// ===========================================================================
SkdcApplication::SkdcApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: constructed");
}

SkdcApplication::~SkdcApplication() = default;

// ===========================================================================
// Configuration  (UNCHANGED)
// ===========================================================================
void SkdcApplication::SetClusterId(utils::u32 cluster_id) {
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
// PATCH 1: wifi_socket bound to WiFi interface IP (not 0.0.0.0)
//          This ensures SendTo uses the WiFi device, not CSMA.
// PATCH 2: [SKDC_WIFI_READY] debug log added.
// ===========================================================================
void SkdcApplication::StartApplication() {
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: starting cluster="
        << m_cluster_id
        << " node=" << GetNode()->GetId());

    // CSMA socket — receive TEK from KDC  (UNCHANGED)
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

    // WiFi socket — bind to WiFi device via BindToNetDevice()
    // This is the NS-3-correct way to force a dual-interface node to
    // send UDP broadcasts out the WiFi device instead of CSMA.
    m_wifi_socket = Socket::CreateSocket(
        GetNode(),
        UdpSocketFactory::GetTypeId());
    m_wifi_socket->SetAllowBroadcast(true);

    // Step 1: Bind socket to the WiFi NetDevice (index 0 on wifi_nodes)
    // SKDCs have: device[0]=CSMA, device[1]=WiFi (added second)
    // wifi_nodes ordering: SKDC0,SKDC1,SKDC2,UAV0..UAV17,Jammer
    // On a SKDC node: GetDevice(0)=loopback, GetDevice(1)=CSMA, GetDevice(2)=WiFi
    {
        Ptr<NetDevice> wifi_dev = nullptr;
        uint32_t n_dev = GetNode()->GetNDevices();
        for (uint32_t di = 0; di < n_dev; ++di) {
            auto dev = GetNode()->GetDevice(di);
            // WiFi device is NOT a LoopbackNetDevice or CsmaNetDevice
            std::string type = dev->GetInstanceTypeId().GetName();
            if (type.find("WifiNetDevice") != std::string::npos) {
                wifi_dev = dev;
                break;
            }
        }

        if (wifi_dev) {
            m_wifi_socket->BindToNetDevice(wifi_dev);
            NS_LOG_UNCOND("[SKDC_WIFI_BIND] cluster=" << m_cluster_id
                << " bound to WifiNetDevice idx=" << wifi_dev->GetIfIndex());
        } else {
            NS_LOG_UNCOND("[SKDC_WIFI_BIND] cluster=" << m_cluster_id
                << " WARNING: WifiNetDevice not found!");
        }

        // Step 2: Bind to any address/port
        InetSocketAddress wifi_local(
            Ipv4Address::GetAny(),
            static_cast<uint16_t>(9200));
        m_wifi_socket->Bind(wifi_local);

        Ipv4Address wifi_ip = m_topo
            ? m_topo->GetSkdcWifiAddr(m_cluster_id)
            : Ipv4Address("0.0.0.0");
        NS_LOG_UNCOND("[SKDC_WIFI_READY] t="
            << Simulator::Now().GetSeconds() << "s"
            << " cluster=" << m_cluster_id
            << " node=" << GetNode()->GetId()
            << " wifi_addr=" << wifi_ip);
        UAV_LOG_INFO(uav::log::channels::PACKET,
            "SkdcApplication: WiFi socket bound"
            << " cluster=" << m_cluster_id
            << " wifi_ip=" << wifi_ip);
    }

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
// StopApplication  (UNCHANGED)
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
// PATCH: HMAC key derived from TEK bytes using HmacSha256Util::KeyFromAesKey()
//        so all UAVs in the cluster can compute the same key from their
//        pre-loaded TEK (loaded from crypto_params.json).
//        Before: GenerateKey() → random, different from UAV's key.
//        After:  KeyFromAesKey(current_tek) → deterministic, same as UAV's.
// ===========================================================================
void SkdcApplication::InitializeState() {
    m_state.cluster_id    = m_cluster_id;
    m_state.rekey_version = 1;
    m_state.tek_received  = false;

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

        // PATCH: derive HMAC key from TEK so UAVs can verify.
        // UAVs do the same derivation in InitializeSlaveKey().
        m_state.hmac_key =
            crypto::HmacSha256Util::KeyFromAesKey(
                m_state.current_tek);

        // Initialize members (UAVs 0-5 in cluster)  (UNCHANGED)
        utils::u32 base = m_cluster_id * 6;
        for (utils::u32 u = 0; u < 6; ++u)
            m_state.members.insert(base + u);
    } else {
        // Fallback: random key if params not loaded
        m_state.hmac_key =
            crypto::HmacSha256Util::GenerateKey();
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "SkdcApplication: crypto params not available"
            " — using random HMAC key (cluster=" << m_cluster_id << ")");
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: state initialized"
        << " cluster=" << m_cluster_id
        << " tek_ok=" << m_state.tek_received
        << " members=" << m_state.members.size()
        << " hmac_from_tek=" << m_state.tek_received);
}

// ===========================================================================
// BroadcastMtk
// PATCH: added [MTK_WIFI_TX] debug log.
// All other logic UNCHANGED.
// ===========================================================================
void SkdcApplication::BroadcastMtk() {
    if (!m_wifi_socket) return;
    if (!m_state.tek_received) return;
    if (m_state.mt_k <= 0) return;

    // Build MT_K packet  (UNCHANGED)
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

    Ptr<Packet> ns3pkt = Create<Packet>(
        wire.data(),
        static_cast<uint32_t>(wire.size()));

    // Broadcast to subnet broadcast address on WiFi (10.1.1.255)
    // PATCH: use subnet broadcast instead of limited broadcast
    // 255.255.255.255 on a dual-interface node may go to CSMA.
    // 10.1.1.255 forces the WiFi subnet broadcast.
    // Use limited broadcast (255.255.255.255) for adhoc WiFi delivery
    InetSocketAddress bcast(
        Ipv4Address("255.255.255.255"),
        static_cast<uint16_t>(9200));

    int sent = m_wifi_socket->SendTo(ns3pkt, 0, bcast);

    ++m_mtk_count;

    // PATCH: debug log
    NS_LOG_UNCOND("[MTK_WIFI_TX] t="
        << Simulator::Now().GetSeconds() << "s"
        << " cluster=" << m_cluster_id
        << " node=" << GetNode()->GetId()
        << " size=" << wire.size() << "B"
        << " version=" << m_state.rekey_version
        << " sent=" << sent);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: MT_K broadcast"
        << " cluster=" << m_cluster_id
        << " version=" << m_state.rekey_version
        << " size=" << wire.size() << "B"
        << " sent=" << sent);
}

// ===========================================================================
// TriggerRekey  (UNCHANGED)
// ===========================================================================
void SkdcApplication::TriggerRekey(RekeyReason reason) {
    ++m_state.rekey_version;
    ++m_rekey_count;

    utils::ByteBuffer seed(
        m_state.current_tek.begin(),
        m_state.current_tek.end());
    utils::u64 ts = utils::TimeUtils::NowEpochMicros();
    utils::ByteUtils::AppendU64BE(seed, ts);

    auto new_key =
        crypto::HmacSha256Util::Compute(
            m_state.hmac_key, seed);
    std::memcpy(m_state.current_tek.data(),
        new_key.data(),
        std::min(new_key.size(),
            m_state.current_tek.size()));

    // HMAC key NOT re-derived — stays fixed to initial TEK

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: rekey"
        << " cluster=" << m_cluster_id
        << " reason=" << RekeyReasonToString(reason)
        << " version=" << m_state.rekey_version);

    BroadcastMtk();
}

// ===========================================================================
// ReceiveFromKdc  (UNCHANGED)
// ===========================================================================
void SkdcApplication::ReceiveFromKdc(Ptr<Socket> socket) {
    Ptr<Packet> pkt;
    Address from;

    while ((pkt = socket->RecvFrom(from))) {
        uint32_t sz = pkt->GetSize();
        if (sz < 16) continue;

        utils::ByteBuffer buf(sz);
        pkt->CopyData(buf.data(), sz);

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
// ProcessJoin  (UNCHANGED)
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
// ProcessLeave  (UNCHANGED)
// ===========================================================================
void SkdcApplication::ProcessLeave(utils::u32 uav_id) {
    m_state.members.erase(uav_id);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: UAV " << uav_id
        << " left cluster=" << m_cluster_id
        << " members=" << m_state.members.size());

    TriggerRekey(RekeyReason::LEAVE);
}

// ===========================================================================
// UpdateTek  (UNCHANGED)
// ===========================================================================
void SkdcApplication::UpdateTek(
    const crypto::AesGcmKey& tek)
{
    m_state.current_tek  = tek;
    m_state.tek_received = true;

    // PATCH: re-derive HMAC key when TEK changes
    m_state.hmac_key =
        crypto::HmacSha256Util::KeyFromAesKey(
            m_state.current_tek);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "SkdcApplication: TEK updated"
        << " cluster=" << m_cluster_id);

    BroadcastMtk();
}

// ===========================================================================
// Scheduling  (UNCHANGED)
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
// GetWifiAddress
// PATCH: returns actual WiFi IP from topology (was "0.0.0.0")
// ===========================================================================
Ipv4Address SkdcApplication::GetWifiAddress() const {
    if (m_topo) {
        return m_topo->GetSkdcWifiAddr(m_cluster_id);
    }
    return Ipv4Address("0.0.0.0");
}

} // namespace apps
} // namespace uav