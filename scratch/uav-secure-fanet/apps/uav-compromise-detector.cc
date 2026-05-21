/**
 * apps/uav-compromise-detector.cc
 * Module 45 - Compromise Detection
 */

#include "apps/uav-compromise-detector.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <algorithm>

NS_LOG_COMPONENT_DEFINE("UavCompromiseDetector");

using namespace ns3;

namespace uav {
namespace apps {

CompromiseDetector::CompromiseDetector(
    const routing::TopologyResult*  topo,
    MulticastManager*               mc_mgr,
    MtkDistributionManager*         dist_mgr,
    TekManager*                     tek_mgr,
    LeaveEventManager*              leave_mgr)
    : m_topo(topo)
    , m_mc_mgr(mc_mgr)
    , m_dist_mgr(dist_mgr)
    , m_tek_mgr(tek_mgr)
    , m_leave_mgr(leave_mgr)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "CompromiseDetector: initialized");
}

void CompromiseDetector::ReportHmacFailure(
    utils::u32 uav_id,
    utils::u32 cluster_id,
    utils::u32 uav_index,
    Ptr<SkdcApplication> skdc)
{
    HandleCompromise(uav_id, cluster_id,
        uav_index,
        CompromiseReason::HMAC_FAILURE, skdc);
}

void CompromiseDetector::ReportReplayAttack(
    utils::u32 uav_id,
    utils::u32 cluster_id,
    utils::u32 uav_index,
    Ptr<SkdcApplication> skdc)
{
    HandleCompromise(uav_id, cluster_id,
        uav_index,
        CompromiseReason::REPLAY_ATTACK, skdc);
}

void CompromiseDetector::ReportInvalidTek(
    utils::u32 uav_id,
    utils::u32 cluster_id,
    utils::u32 uav_index,
    Ptr<SkdcApplication> skdc)
{
    HandleCompromise(uav_id, cluster_id,
        uav_index,
        CompromiseReason::INVALID_TEK, skdc);
}

void CompromiseDetector::ReportExternal(
    utils::u32 uav_id,
    utils::u32 cluster_id,
    utils::u32 uav_index,
    Ptr<SkdcApplication> skdc)
{
    HandleCompromise(uav_id, cluster_id,
        uav_index,
        CompromiseReason::EXTERNAL_REPORT, skdc);
}

void CompromiseDetector::HandleCompromise(
    utils::u32       uav_id,
    utils::u32       cluster_id,
    utils::u32       uav_index,
    CompromiseReason reason,
    Ptr<SkdcApplication> skdc)
{
    // Skip if already revoked
    if (IsRevoked(uav_id)) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "CompromiseDetector: UAV" << uav_id
            << " already revoked");
        return;
    }

    ++m_total_detections;

    CompromiseEvent ev;
    ev.uav_id     = uav_id;
    ev.cluster_id = cluster_id;
    ev.uav_index  = uav_index;
    ev.reason     = reason;
    ev.time_s     = Simulator::Now().GetSeconds();

    UAV_LOG_WARN(uav::log::channels::PACKET,
        "CompromiseDetector: DETECTED UAV"
        << uav_id
        << " cluster=" << cluster_id
        << " reason=" << CompromiseReasonStr(reason));

    // Mark compromised
    if (!IsCompromised(uav_id))
        m_compromised.push_back(uav_id);

    // Force revoke via LeaveEventManager
    if (m_leave_mgr && skdc) {
        ev.revoked = m_leave_mgr->ForceRevoke(
            uav_id, uav_index, cluster_id,
            skdc.operator->());

        if (ev.revoked) {
            m_revoked.push_back(uav_id);
            ++m_total_revocations;
        }
    }

    m_history.push_back(ev);
    if (m_callback) m_callback(ev);
}

bool CompromiseDetector::IsCompromised(
    utils::u32 uav_id) const
{
    return std::find(
        m_compromised.begin(),
        m_compromised.end(),
        uav_id) != m_compromised.end();
}

bool CompromiseDetector::IsRevoked(
    utils::u32 uav_id) const
{
    return std::find(
        m_revoked.begin(),
        m_revoked.end(),
        uav_id) != m_revoked.end();
}

std::vector<utils::u32>
CompromiseDetector::GetCompromisedUavs() const
{
    return m_compromised;
}

void CompromiseDetector::PrintStatus() const {
    std::cout << "\n=== Compromise Detector ===\n";
    std::cout << "  Detections:  "
              << m_total_detections << "\n";
    std::cout << "  Revocations: "
              << m_total_revocations << "\n";
    for (const auto& ev : m_history) {
        std::cout << "    t=" << ev.time_s
            << "s UAV" << ev.uav_id
            << " C" << ev.cluster_id
            << " " << CompromiseReasonStr(ev.reason)
            << " revoked=" << ev.revoked
            << "\n";
    }
}

} // namespace apps
} // namespace uav
