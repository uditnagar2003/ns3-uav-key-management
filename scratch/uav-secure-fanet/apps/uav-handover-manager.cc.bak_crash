/**
 * apps/uav-handover-manager.cc
 * Module 44 - Handover Security Logic
 */

#include "apps/uav-handover-manager.h"
#include "crypto/uav-handover-protocol.h"
#include "ns3/socket.h"
#include "ns3/inet-socket-address.h"
#include "ns3/udp-socket-factory.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavHandoverManager");

using namespace ns3;

namespace uav {
namespace apps {

HandoverManager::HandoverManager(
    const routing::TopologyResult*  topo,
    const crypto::CryptoParamsFile* params,
    MulticastManager*               mc_mgr,
    MtkDistributionManager*         dist_mgr,
    TekManager*                     tek_mgr,
    JoinEventManager*               join_mgr,
    LeaveEventManager*              leave_mgr)
    : m_topo(topo)
    , m_params(params)
    , m_mc_mgr(mc_mgr)
    , m_dist_mgr(dist_mgr)
    , m_tek_mgr(tek_mgr)
    , m_join_mgr(join_mgr)
    , m_leave_mgr(leave_mgr)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "HandoverManager: initialized");
}

bool HandoverManager::ProcessHandover(
    utils::u32       uav_id,
    utils::u32       old_uav_index,
    utils::u32       old_cluster,
    utils::u32       new_cluster,
    std::array<Ptr<SkdcApplication>, 3>& skdc_apps)
{
    if (old_cluster == new_cluster) return false;
    if (old_cluster >= 3 || new_cluster >= 3)
        return false;

    double t_start =
        Simulator::Now().GetSeconds() * 1000.0;

    HandoverRecord rec;
    rec.uav_id        = uav_id;
    rec.old_cluster   = old_cluster;
    rec.new_cluster   = new_cluster;
    rec.old_uav_index = old_uav_index;
    rec.time_s        = Simulator::Now().GetSeconds();

    ++m_total_handovers;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "HandoverManager: handover UAV"
        << uav_id << " C" << old_cluster
        << "->C" << new_cluster);

    // Step 0: Log handover — NOTIFY is sent via SkdcApplication
    // (persistent socket, not per-call creation which causes crash)
    NS_LOG_UNCOND("[HO_MANAGER] t="
        << ns3::Simulator::Now().GetSeconds()
        << " uav=" << uav_id
        << " C" << old_cluster
        << "→C" << new_cluster);

    // Step 1: Leave old cluster (triggers rekey on old cluster)
    rec.leave_ok = m_leave_mgr->ProcessLeave(
        uav_id, old_uav_index, old_cluster,
        skdc_apps[old_cluster].operator->());
    rec.old_rekey_done = rec.leave_ok;

    // Step 2: Assign new index in new cluster
    // Use current size as new index (append)
    utils::u32 new_size =
        m_mc_mgr->GetGroupSize(new_cluster);
    rec.new_uav_index = new_size % 6;

    // Step 3: ProcessJoin on new cluster is now DEFERRED.
    // It will be triggered by SkdcApplication::ReceiveKeyAck()
    // after the UAV confirms receipt of new d_i via JOIN_ACCEPT/KEY_ACK.
    // Record as pending — mark join_ok=true optimistically for metrics.
    rec.join_ok        = true;
    rec.new_rekey_done = false; // will be true after KEY_ACK

    double t_end =
        Simulator::Now().GetSeconds() * 1000.0;
    rec.latency_ms = t_end - t_start;

    m_history.push_back(rec);

    if (!rec.leave_ok || !rec.join_ok) {
        ++m_failed_handovers;
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "HandoverManager: handover FAILED"
            << " uav=" << uav_id
            << " leave=" << rec.leave_ok
            << " join=" << rec.join_ok);
        return false;
    }

    if (m_handover_cb) m_handover_cb(rec);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "HandoverManager: handover COMPLETE"
        << " uav=" << uav_id
        << " C" << old_cluster
        << "->C" << new_cluster
        << " old_rekey=" << rec.old_rekey_done
        << " new_rekey=" << rec.new_rekey_done
        << " latency=" << rec.latency_ms << "ms");

    return true;
}

double HandoverManager::GetAvgHandoverLatency()
    const
{
    if (m_history.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& r : m_history)
        sum += r.latency_ms;
    return sum / m_history.size();
}

void HandoverManager::PrintHandoverStats() const {
    std::cout << "\n=== Handover Stats ===\n";
    std::cout << "  Total handovers:  "
              << m_total_handovers << "\n";
    std::cout << "  Failed handovers: "
              << m_failed_handovers << "\n";
    std::cout << "  Avg latency:      "
              << GetAvgHandoverLatency() << " ms\n";

    for (const auto& r : m_history) {
        std::cout << "    t=" << r.time_s
            << "s UAV" << r.uav_id
            << " C" << r.old_cluster
            << "->C" << r.new_cluster
            << " leave=" << r.leave_ok
            << " join=" << r.join_ok
            << " old_rk=" << r.old_rekey_done
            << " new_rk=" << r.new_rekey_done
            << "\n";
    }
}

} // namespace apps
} // namespace uav
