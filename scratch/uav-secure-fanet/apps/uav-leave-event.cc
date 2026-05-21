/**
 * apps/uav-leave-event.cc
 * Module 42 - Leave Security Event
 */

#include "apps/uav-leave-event.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavLeaveEvent");

using namespace ns3;

namespace uav {
namespace apps {

LeaveEventManager::LeaveEventManager(
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
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "LeaveEventManager: initialized");
}

bool LeaveEventManager::ProcessLeave(
    utils::u32       uav_id,
    utils::u32       uav_index,
    utils::u32       cluster_id,
    SkdcApplication* skdc)
{
    ++m_total_leaves;
    return DoLeave(uav_id, uav_index,
                   cluster_id, skdc, false);
}

bool LeaveEventManager::ForceRevoke(
    utils::u32       uav_id,
    utils::u32       uav_index,
    utils::u32       cluster_id,
    SkdcApplication* skdc)
{
    ++m_total_leaves;
    ++m_force_revokes;
    return DoLeave(uav_id, uav_index,
                   cluster_id, skdc, true);
}

bool LeaveEventManager::DoLeave(
    utils::u32       uav_id,
    utils::u32       uav_index,
    utils::u32       cluster_id,
    SkdcApplication* skdc,
    bool             forced)
{
    double t_start =
        Simulator::Now().GetSeconds() * 1000.0;

    LeaveRecord rec;
    rec.uav_id     = uav_id;
    rec.uav_index  = uav_index;
    rec.cluster_id = cluster_id;
    rec.time_s     = Simulator::Now().GetSeconds();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "LeaveEventManager: "
        << (forced ? "FORCE REVOKE" : "leave")
        << " uav=" << uav_id
        << " cluster=" << cluster_id);

    // Step 1: Remove from multicast group (LeKeyUpdate)
    bool removed = m_mc_mgr->RemoveMember(
        cluster_id, uav_index, uav_id);

    rec.revoked = removed || forced;

    if (!rec.revoked) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "LeaveEventManager: UAV " << uav_id
            << " not in cluster " << cluster_id);
        m_history.push_back(rec);
        return false;
    }

    // Step 2: Rotate TEK (forward secrecy)
    // TEK_new = HMAC(key, TEK_old || ts || nonce)
    m_tek_mgr->RotateOnLeave(cluster_id);
    rec.new_version = m_tek_mgr->GetVersion(cluster_id);

    // Step 3: Broadcast new MT_K to remaining UAVs
    if (skdc && m_dist_mgr) {
        m_dist_mgr->OnMemberLeft(
            cluster_id, uav_id, skdc);
    }

    rec.rekey_done = true;

    double t_end =
        Simulator::Now().GetSeconds() * 1000.0;
    rec.latency_ms = t_end - t_start;

    m_history.push_back(rec);
    if (m_leave_cb) m_leave_cb(rec);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "LeaveEventManager: leave complete"
        << " uav=" << uav_id
        << " cluster=" << cluster_id
        << " new_version=" << rec.new_version
        << " latency=" << rec.latency_ms << "ms");

    return true;
}

double LeaveEventManager::GetAvgLeaveLatency()
    const
{
    if (m_history.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& r : m_history)
        sum += r.latency_ms;
    return sum / m_history.size();
}

void LeaveEventManager::PrintLeaveStats() const {
    std::cout << "\n=== Leave Event Stats ===\n";
    std::cout << "  Total leaves:   "
              << m_total_leaves << "\n";
    std::cout << "  Force revokes:  "
              << m_force_revokes << "\n";
    std::cout << "  Avg latency:    "
              << GetAvgLeaveLatency() << " ms\n";

    for (const auto& r : m_history) {
        std::cout << "    t=" << r.time_s
            << "s UAV" << r.uav_id
            << " C" << r.cluster_id
            << " revoked=" << r.revoked
            << " rekey=" << r.rekey_done
            << " v=" << r.new_version
            << "\n";
    }
}

} // namespace apps
} // namespace uav
