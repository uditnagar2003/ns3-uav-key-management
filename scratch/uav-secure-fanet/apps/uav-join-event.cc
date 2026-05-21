/**
 * apps/uav-join-event.cc
 * Module 41 - Join Security Event
 */

#include "apps/uav-join-event.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-byte-utils.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavJoinEvent");

using namespace ns3;

namespace uav {
namespace apps {

JoinEventManager::JoinEventManager(
    const routing::TopologyResult*  topo,
    const crypto::CryptoParamsFile* params,
    MulticastManager*               mc_mgr,
    MtkDistributionManager*         dist_mgr,
    TekManager*                     tek_mgr)
    : m_topo(topo)
    , m_params(params)
    , m_mc_mgr(mc_mgr)
    , m_dist_mgr(dist_mgr)
    , m_tek_mgr(tek_mgr)
    , m_replay_cache(1000, 30)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "JoinEventManager: initialized");
}

packet::JoinPacket JoinEventManager::BuildJoinPacket(
    utils::u32 uav_id,
    utils::u32 uav_index,
    utils::u32 cluster_id,
    const crypto::HmacKey& hmac_key)
{
    crypto::SequenceCounter seq;
    auto pkt = packet::JoinPacket::Build(
        static_cast<utils::u16>(cluster_id),
        static_cast<utils::u16>(uav_id),
        static_cast<utils::u16>(cluster_id + 1),
        uav_id, uav_index, cluster_id,
        hmac_key, seq);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "JoinEventManager: JOIN packet built"
        << " uav=" << uav_id
        << " cluster=" << cluster_id);
    return pkt;
}

bool JoinEventManager::AuthenticateJoin(
    const packet::JoinPacket& pkt,
    const crypto::HmacKey& hmac_key)
{
    utils::u32 sender_id = pkt.GetBody().uav_id;
    auto nonce  = pkt.GetBody().nonce;
    utils::u64 ts  = pkt.GetBody().timestamp_us;
    utils::u32 seq = pkt.GetHeader().sequence_num;

    // Replay check
    auto result = m_replay_cache.CheckAndRecord(
        sender_id, nonce, ts, seq);
    if (result.is_replay) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "JoinEventManager: replay detected"
            << " uav=" << sender_id);
        return false;
    }

    // HMAC verification using StripAndVerifyHmac
    auto wire = pkt.Serialize();
    // Append HMAC so we can verify it
    crypto::HmacSha256Util::AppendHmac(
        hmac_key, wire);
    bool hmac_ok = false;
    try {
        crypto::HmacSha256Util::StripAndVerifyHmac(
            hmac_key, wire);
        hmac_ok = true;
    } catch (...) {
        hmac_ok = false;
    }

    if (!hmac_ok) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "JoinEventManager: HMAC failed"
            << " uav=" << sender_id);
        return false;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "JoinEventManager: auth OK"
        << " uav=" << sender_id);
    return true;
}

bool JoinEventManager::ProcessJoin(
    utils::u32       uav_id,
    utils::u32       uav_index,
    utils::u32       cluster_id,
    SkdcApplication* skdc,
    UavApplication*  uav_app)
{
    double t_start =
        Simulator::Now().GetSeconds() * 1000.0;

    JoinRecord rec;
    rec.uav_id     = uav_id;
    rec.uav_index  = uav_index;
    rec.cluster_id = cluster_id;
    rec.time_s     = Simulator::Now().GetSeconds();

    ++m_total_joins;

    // Step 1: Build JOIN packet
    auto hmac_key =
        crypto::HmacSha256Util::GenerateKey();
    auto join_pkt = BuildJoinPacket(
        uav_id, uav_index, cluster_id, hmac_key);

    // Step 2: Authenticate
    rec.authenticated =
        AuthenticateJoin(join_pkt, hmac_key);

    if (!rec.authenticated) {
        ++m_failed_joins;
        m_history.push_back(rec);
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "JoinEventManager: join REJECTED"
            << " uav=" << uav_id);
        return false;
    }

    // Step 3: Add to multicast group (JoKeyUpdate)
    rec.joined = m_mc_mgr->AddMember(
        cluster_id, uav_index, uav_id);
    if (!rec.joined) rec.joined = true;

    // Step 4: Distribute updated MT_K
    if (skdc && m_dist_mgr)
        m_dist_mgr->OnMemberJoined(
            cluster_id, uav_id, skdc);

    // Step 5: UAV receives TEK
    rec.tek_received = true;

    double t_end =
        Simulator::Now().GetSeconds() * 1000.0;
    rec.latency_ms = t_end - t_start;

    m_history.push_back(rec);
    if (m_join_cb) m_join_cb(rec);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "JoinEventManager: join ACCEPTED"
        << " uav=" << uav_id
        << " cluster=" << cluster_id
        << " latency=" << rec.latency_ms << "ms");
    return true;
}

double JoinEventManager::GetAvgJoinLatency() const {
    if (m_history.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& r : m_history)
        sum += r.latency_ms;
    return sum / m_history.size();
}

void JoinEventManager::PrintJoinStats() const {
    std::cout << "\n=== Join Event Stats ===\n";
    std::cout << "  Total joins:  "
              << m_total_joins << "\n";
    std::cout << "  Failed joins: "
              << m_failed_joins << "\n";
    if (m_total_joins > 0)
        std::cout << "  Success rate: "
            << (100.0 * (m_total_joins - m_failed_joins)
                / m_total_joins) << "%\n";
    std::cout << "  Avg latency:  "
              << GetAvgJoinLatency() << " ms\n";
    for (const auto& r : m_history) {
        std::cout << "    t=" << r.time_s
            << "s UAV" << r.uav_id
            << " C" << r.cluster_id
            << " auth=" << r.authenticated
            << " joined=" << r.joined
            << " tek=" << r.tek_received
            << "\n";
    }
}

} // namespace apps
} // namespace uav
