/**
 * apps/uav-compromise-detector.h
 * Module 45 - Compromise Detection
 *
 * COMPROMISE MODEL (per project spec):
 *   - Node compromise probability: 5%
 *   - Compromised UAV detected via:
 *     * HMAC verification failure
 *     * Replay attack attempt
 *     * Invalid TEK usage
 *     * Anomalous packet rate
 *   - Detection triggers:
 *     * Immediate revocation (ForceRevoke)
 *     * Cluster rekey
 *     * KDC notification
 *     * NetAnim color change to black
 */

#ifndef UAV_COMPROMISE_DETECTOR_H
#define UAV_COMPROMISE_DETECTOR_H

#include "apps/uav-leave-event.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-tek-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"

#include <vector>
#include <unordered_map>
#include <functional>

namespace uav {
namespace apps {

// ===========================================================================
// CompromiseReason - why a UAV was flagged
// ===========================================================================
enum class CompromiseReason {
    HMAC_FAILURE    = 0,
    REPLAY_ATTACK   = 1,
    INVALID_TEK     = 2,
    ANOMALOUS_RATE  = 3,
    EXTERNAL_REPORT = 4
};

static inline const char* CompromiseReasonStr(
    CompromiseReason r)
{
    switch (r) {
    case CompromiseReason::HMAC_FAILURE:
        return "HMAC_FAILURE";
    case CompromiseReason::REPLAY_ATTACK:
        return "REPLAY_ATTACK";
    case CompromiseReason::INVALID_TEK:
        return "INVALID_TEK";
    case CompromiseReason::ANOMALOUS_RATE:
        return "ANOMALOUS_RATE";
    case CompromiseReason::EXTERNAL_REPORT:
        return "EXTERNAL_REPORT";
    default: return "UNKNOWN";
    }
}

// ===========================================================================
// CompromiseEvent
// ===========================================================================
struct CompromiseEvent {
    utils::u32       uav_id      = 0;
    utils::u32       cluster_id  = 0;
    utils::u32       uav_index   = 0;
    CompromiseReason reason;
    double           time_s      = 0.0;
    bool             revoked     = false;
};

// ===========================================================================
// CompromiseDetector - Module 45
// ===========================================================================
class CompromiseDetector {
public:
    using CompromiseCallback =
        std::function<void(const CompromiseEvent&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    CompromiseDetector(
        const routing::TopologyResult*  topo,
        MulticastManager*               mc_mgr,
        MtkDistributionManager*         dist_mgr,
        TekManager*                     tek_mgr,
        LeaveEventManager*              leave_mgr);

    // -----------------------------------------------------------------------
    // Detection triggers
    // -----------------------------------------------------------------------

    /// Report HMAC failure for UAV
    void ReportHmacFailure(
        utils::u32 uav_id,
        utils::u32 cluster_id,
        utils::u32 uav_index,
        Ptr<SkdcApplication> skdc);

    /// Report replay attack attempt
    void ReportReplayAttack(
        utils::u32 uav_id,
        utils::u32 cluster_id,
        utils::u32 uav_index,
        Ptr<SkdcApplication> skdc);

    /// Report invalid TEK usage
    void ReportInvalidTek(
        utils::u32 uav_id,
        utils::u32 cluster_id,
        utils::u32 uav_index,
        Ptr<SkdcApplication> skdc);

    /// External compromise report (e.g. from KDC)
    void ReportExternal(
        utils::u32 uav_id,
        utils::u32 cluster_id,
        utils::u32 uav_index,
        Ptr<SkdcApplication> skdc);

    // -----------------------------------------------------------------------
    // State queries
    // -----------------------------------------------------------------------
    bool IsCompromised(utils::u32 uav_id) const;
    bool IsRevoked(utils::u32 uav_id) const;

    std::vector<utils::u32> GetCompromisedUavs()
        const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalDetections() const {
        return m_total_detections;
    }
    utils::u64 GetTotalRevocations() const {
        return m_total_revocations;
    }

    const std::vector<CompromiseEvent>&
        GetHistory() const { return m_history; }

    void SetCallback(CompromiseCallback cb) {
        m_callback = cb;
    }

    void PrintStatus() const;

private:
    const routing::TopologyResult*  m_topo;
    MulticastManager*               m_mc_mgr;
    MtkDistributionManager*         m_dist_mgr;
    TekManager*                     m_tek_mgr;
    LeaveEventManager*              m_leave_mgr;

    std::vector<CompromiseEvent>    m_history;
    std::vector<utils::u32>         m_compromised;
    std::vector<utils::u32>         m_revoked;
    CompromiseCallback              m_callback;
    utils::u64                      m_total_detections  = 0;
    utils::u64                      m_total_revocations = 0;

    void HandleCompromise(
        utils::u32       uav_id,
        utils::u32       cluster_id,
        utils::u32       uav_index,
        CompromiseReason reason,
        Ptr<SkdcApplication> skdc);
};

} // namespace apps
} // namespace uav

#endif // UAV_COMPROMISE_DETECTOR_H
