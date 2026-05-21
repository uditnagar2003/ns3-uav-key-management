/**
 * apps/uav-leave-event.h
 * Module 42 - Leave Security Event
 *
 * LEAVE FLOW (per project spec):
 *   1. UAV leaves cluster (voluntary or forced)
 *   2. SKDC immediately revokes UAV
 *   3. SKDC broadcasts rekey instruction
 *   4. Remaining UAVs update TEK:
 *      TEK_new = SHA256(TEK_old || timestamp || nonce)
 *   5. SKDC updates TEK and MT_K
 *   6. KDC maintains cluster TEK awareness
 *
 * Algorithm 5 (LeKeyUpdate) is invoked here.
 */

#ifndef UAV_LEAVE_EVENT_H
#define UAV_LEAVE_EVENT_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-tek-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-time-utils.h"

#include <functional>
#include <vector>

namespace uav {
namespace apps {

// ===========================================================================
// LeaveRecord - result of a leave event
// ===========================================================================
struct LeaveRecord {
    utils::u32  uav_id        = 0;
    utils::u32  uav_index     = 0;
    utils::u32  cluster_id    = 0;
    double      time_s        = 0.0;
    bool        revoked       = false;
    bool        rekey_done    = false;
    double      latency_ms    = 0.0;
    utils::u32  new_version   = 0;
};

// ===========================================================================
// LeaveEventManager - Module 42
// ===========================================================================
class LeaveEventManager {
public:
    using LeaveCallback =
        std::function<void(const LeaveRecord&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    LeaveEventManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params,
        MulticastManager*               mc_mgr,
        MtkDistributionManager*         dist_mgr,
        TekManager*                     tek_mgr);

    // -----------------------------------------------------------------------
    // Leave processing
    // -----------------------------------------------------------------------

    /// Process a UAV leave event
    bool ProcessLeave(
        utils::u32       uav_id,
        utils::u32       uav_index,
        utils::u32       cluster_id,
        SkdcApplication* skdc);

    /// Force-revoke a compromised UAV
    bool ForceRevoke(
        utils::u32       uav_id,
        utils::u32       uav_index,
        utils::u32       cluster_id,
        SkdcApplication* skdc);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalLeaves()  const {
        return m_total_leaves;
    }
    utils::u64 GetForceRevokes() const {
        return m_force_revokes;
    }
    double GetAvgLeaveLatency()  const;

    const std::vector<LeaveRecord>& GetHistory() const {
        return m_history;
    }

    void SetLeaveCallback(LeaveCallback cb) {
        m_leave_cb = cb;
    }

    void PrintLeaveStats() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;
    MulticastManager*               m_mc_mgr;
    MtkDistributionManager*         m_dist_mgr;
    TekManager*                     m_tek_mgr;

    std::vector<LeaveRecord>  m_history;
    LeaveCallback             m_leave_cb;
    utils::u64                m_total_leaves  = 0;
    utils::u64                m_force_revokes = 0;

    bool DoLeave(utils::u32 uav_id,
                 utils::u32 uav_index,
                 utils::u32 cluster_id,
                 SkdcApplication* skdc,
                 bool forced);
};

} // namespace apps
} // namespace uav

#endif // UAV_LEAVE_EVENT_H
