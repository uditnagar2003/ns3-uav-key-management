/**
 * apps/uav-mtk-distribution.cc
 * Module 40 - MT_K Distribution Manager
 */

#include "apps/uav-mtk-distribution.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-time-utils.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavMtkDistribution");

using namespace ns3;

namespace uav {
namespace apps {

// ===========================================================================
// Constructor
// ===========================================================================
MtkDistributionManager::MtkDistributionManager(
    const routing::TopologyResult*  topo,
    const crypto::CryptoParamsFile* params,
    TekManager*                     tek_mgr,
    MulticastManager*               mc_mgr)
    : m_topo(topo)
    , m_params(params)
    , m_tek_mgr(tek_mgr)
    , m_mc_mgr(mc_mgr)
{
    for (utils::u32 c = 0; c < 3; ++c) {
        m_records[c].cluster_id   = c;
        m_records[c].last_version = 0;
        m_records[c].pending      = false;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: initialized");
}

// ===========================================================================
// BroadcastMtk - trigger SKDC broadcast for cluster
// ===========================================================================
void MtkDistributionManager::BroadcastMtk(
    utils::u32 cluster_id,
    SkdcApplication* skdc)
{
    if (!skdc || cluster_id >= 3) return;

    utils::u32 version =
        m_tek_mgr->GetVersion(cluster_id);

    // Update SKDC TEK state
    skdc->UpdateTek(
        m_tek_mgr->GetTek(cluster_id));

    auto& rec = m_records[cluster_id];
    rec.last_version   = version;
    rec.last_broadcast =
        utils::TimeUtils::NowEpochMicros();
    ++rec.total_broadcasts;
    rec.total_bytes += 892;  // MT_K packet size
    rec.pending = false;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: broadcast"
        << " cluster=" << cluster_id
        << " version=" << version
        << " total=" << rec.total_broadcasts);

    if (m_broadcast_cb) {
        m_broadcast_cb(cluster_id, version,
                       rec.total_bytes);
    }
}

// ===========================================================================
// BroadcastAll
// ===========================================================================
void MtkDistributionManager::BroadcastAll(
    std::array<Ptr<SkdcApplication>, 3>& skdc_apps)
{
    for (utils::u32 c = 0; c < 3; ++c) {
        if (skdc_apps[c])
            BroadcastMtk(c,
                skdc_apps[c].operator->());
    }
}

// ===========================================================================
// ScheduleRefresh - periodic MT_K refresh
// ===========================================================================
void MtkDistributionManager::ScheduleRefresh(
    std::array<Ptr<SkdcApplication>, 3>& skdc_apps)
{
    // Schedule via NS-3 simulator
    // Called periodically every REFRESH_INTERVAL_S
    for (utils::u32 c = 0; c < 3; ++c) {
        m_records[c].pending = true;
    }

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: refresh scheduled"
        << " interval=" << REFRESH_INTERVAL_S << "s");
}

// ===========================================================================
// On-event triggers
// ===========================================================================
void MtkDistributionManager::OnTekRotated(
    utils::u32 cluster_id,
    const crypto::AesGcmKey& new_tek,
    utils::u32 version,
    SkdcApplication* skdc)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: TEK rotated"
        << " cluster=" << cluster_id
        << " version=" << version
        << " → broadcasting MT_K");

    // Update TekManager with new TEK
    m_tek_mgr->UpdateTek(
        cluster_id, new_tek, version);

    // Broadcast new MT_K
    BroadcastMtk(cluster_id, skdc);
}

void MtkDistributionManager::OnMemberJoined(
    utils::u32 cluster_id,
    utils::u32 uav_id,
    SkdcApplication* skdc)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: join event"
        << " cluster=" << cluster_id
        << " uav=" << uav_id);

    // On join: MT_K updated but TEK unchanged
    BroadcastMtk(cluster_id, skdc);
}

void MtkDistributionManager::OnMemberLeft(
    utils::u32 cluster_id,
    utils::u32 uav_id,
    SkdcApplication* skdc)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MtkDistributionManager: leave event"
        << " cluster=" << cluster_id
        << " uav=" << uav_id);

    // On leave: rotate TEK first then broadcast
    m_tek_mgr->RotateOnLeave(cluster_id);
    BroadcastMtk(cluster_id, skdc);
}

// ===========================================================================
// Stats
// ===========================================================================
const DistributionRecord&
MtkDistributionManager::GetRecord(
    utils::u32 cluster_id) const
{
    static DistributionRecord empty;
    if (cluster_id >= 3) return empty;
    return m_records[cluster_id];
}

utils::u64
MtkDistributionManager::GetTotalBroadcasts() const
{
    utils::u64 total = 0;
    for (const auto& r : m_records)
        total += r.total_broadcasts;
    return total;
}

utils::u64
MtkDistributionManager::GetTotalBytes() const
{
    utils::u64 total = 0;
    for (const auto& r : m_records)
        total += r.total_bytes;
    return total;
}

void MtkDistributionManager::PrintDistributionStats()
    const
{
    std::cout << "\n=== MT_K Distribution Stats ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        const auto& r = m_records[c];
        std::cout << "  Cluster " << c
            << ": broadcasts=" << r.total_broadcasts
            << " bytes=" << r.total_bytes
            << " version=" << r.last_version
            << " pending=" << r.pending
            << "\n";
    }
    std::cout << "  Total broadcasts: "
              << GetTotalBroadcasts() << "\n";
    std::cout << "  Total bytes:      "
              << GetTotalBytes() << "\n";
}

} // namespace apps
} // namespace uav
