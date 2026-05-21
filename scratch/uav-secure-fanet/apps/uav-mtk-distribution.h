/**
 * apps/uav-mtk-distribution.h
 * Module 40 - MT_K Distribution Manager
 *
 * Manages MT_K distribution from SKDC to UAVs.
 *
 * DISTRIBUTION FLOW (per project spec):
 *   1. KDC generates TEK
 *   2. KDC encrypts TEK into MT_K using SKDC domain
 *   3. SKDC decrypts MT_K using SKDC parameters
 *   4. SKDC re-encrypts TEK using local multicast domain
 *   5. SKDC broadcasts MT_K to UAV cluster
 *   6. UAV decrypts MT_K using slave key → extracts TEK
 *
 * MT_K PACKET STRUCTURE:
 *   [cluster_id][version][MT_K_bigint][N_group][HMAC]
 *
 * BROADCAST SCHEDULE:
 *   - On startup
 *   - On TEK rotation
 *   - On join/leave event
 *   - Periodic refresh every 30s
 */

#ifndef UAV_MTK_DISTRIBUTION_H
#define UAV_MTK_DISTRIBUTION_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-multicast-manager.h"
#include "crypto/uav-crypto-params.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-error.h"

#include <array>
#include <vector>
#include <functional>
#include <chrono>

namespace uav {
namespace apps {

// ===========================================================================
// DistributionRecord - tracks MT_K broadcast state per cluster
// ===========================================================================
struct DistributionRecord {
    utils::u32   cluster_id      = 0;
    utils::u32   last_version    = 0;
    utils::u64   last_broadcast  = 0;  // epoch micros
    utils::u64   total_broadcasts= 0;
    utils::u64   total_bytes     = 0;
    bool         pending         = false;
};

// ===========================================================================
// MtkDistributionManager - Module 40
// ===========================================================================
class MtkDistributionManager {
public:
    static constexpr utils::u32 REFRESH_INTERVAL_S = 30;
    static constexpr utils::u32 MAX_RETRIES        = 3;

    using BroadcastCallback =
        std::function<void(utils::u32 cluster,
                           utils::u32 version,
                           utils::u64 bytes)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    MtkDistributionManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params,
        TekManager*                     tek_mgr,
        MulticastManager*               mc_mgr);

    // -----------------------------------------------------------------------
    // Distribution control
    // -----------------------------------------------------------------------

    /// Trigger immediate MT_K broadcast for cluster
    void BroadcastMtk(utils::u32 cluster_id,
                      SkdcApplication* skdc);

    /// Broadcast to all clusters
    void BroadcastAll(
        std::array<Ptr<SkdcApplication>, 3>& skdc_apps);

    /// Schedule periodic refresh
    void ScheduleRefresh(
        std::array<Ptr<SkdcApplication>, 3>& skdc_apps);

    // -----------------------------------------------------------------------
    // On-event triggers
    // -----------------------------------------------------------------------
    void OnTekRotated(utils::u32 cluster_id,
                      const crypto::AesGcmKey& new_tek,
                      utils::u32 version,
                      SkdcApplication* skdc);

    void OnMemberJoined(utils::u32 cluster_id,
                        utils::u32 uav_id,
                        SkdcApplication* skdc);

    void OnMemberLeft(utils::u32 cluster_id,
                      utils::u32 uav_id,
                      SkdcApplication* skdc);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    const DistributionRecord& GetRecord(
        utils::u32 cluster_id) const;

    utils::u64 GetTotalBroadcasts() const;
    utils::u64 GetTotalBytes() const;

    void SetBroadcastCallback(BroadcastCallback cb) {
        m_broadcast_cb = cb;
    }

    void PrintDistributionStats() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;
    TekManager*                     m_tek_mgr;
    MulticastManager*               m_mc_mgr;

    std::array<DistributionRecord, 3> m_records;
    BroadcastCallback                 m_broadcast_cb;
};

} // namespace apps
} // namespace uav

#endif // UAV_MTK_DISTRIBUTION_H
