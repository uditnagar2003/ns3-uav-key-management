/**
 * apps/uav-handover-manager.h
 * Module 44 - Handover Security Logic
 *
 * HANDOVER FLOW (per project spec):
 *   1. UAV moves to different cluster area
 *   2. Old SKDC sends UAV identity to KDC
 *   3. KDC relays to new SKDC
 *   4. New SKDC generates new decryption key
 *   5. New SKDC assigns new multicast state
 *   6. New SKDC distributes new MT_K
 *   7. BOTH old and new clusters rekey
 *
 * Handover = Leave old cluster + Join new cluster
 * Both clusters rekey after handover.
 */

#ifndef UAV_HANDOVER_MANAGER_H
#define UAV_HANDOVER_MANAGER_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-join-event.h"
#include "apps/uav-leave-event.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"

#include <vector>
#include <functional>

namespace uav {
namespace apps {

// ===========================================================================
// HandoverRecord
// ===========================================================================
struct HandoverRecord {
    utils::u32  uav_id         = 0;
    utils::u32  old_cluster    = 0;
    utils::u32  new_cluster    = 0;
    utils::u32  old_uav_index  = 0;
    utils::u32  new_uav_index  = 0;
    double      time_s         = 0.0;
    bool        leave_ok       = false;
    bool        join_ok        = false;
    bool        old_rekey_done = false;
    bool        new_rekey_done = false;
    double      latency_ms     = 0.0;
};

// ===========================================================================
// HandoverManager - Module 44
// ===========================================================================
class HandoverManager {
public:
    using HandoverCallback =
        std::function<void(const HandoverRecord&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    HandoverManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params,
        MulticastManager*               mc_mgr,
        MtkDistributionManager*         dist_mgr,
        TekManager*                     tek_mgr,
        JoinEventManager*               join_mgr,
        LeaveEventManager*              leave_mgr);

    // -----------------------------------------------------------------------
    // Handover processing
    // -----------------------------------------------------------------------

    /// Process UAV handover from old_cluster to new_cluster
    bool ProcessHandover(
        utils::u32       uav_id,
        utils::u32       old_uav_index,
        utils::u32       old_cluster,
        utils::u32       new_cluster,
        std::array<Ptr<SkdcApplication>, 3>& skdc_apps);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalHandovers() const {
        return m_total_handovers;
    }
    utils::u64 GetFailedHandovers() const {
        return m_failed_handovers;
    }
    double GetAvgHandoverLatency() const;

    const std::vector<HandoverRecord>& GetHistory()
        const { return m_history; }

    void SetHandoverCallback(HandoverCallback cb) {
        m_handover_cb = cb;
    }

    void PrintHandoverStats() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;
    MulticastManager*               m_mc_mgr;
    MtkDistributionManager*         m_dist_mgr;
    TekManager*                     m_tek_mgr;
    JoinEventManager*               m_join_mgr;
    LeaveEventManager*              m_leave_mgr;

    std::vector<HandoverRecord>     m_history;
    HandoverCallback                m_handover_cb;
    utils::u64                      m_total_handovers  = 0;
    utils::u64                      m_failed_handovers = 0;
};

} // namespace apps
} // namespace uav

#endif // UAV_HANDOVER_MANAGER_H
