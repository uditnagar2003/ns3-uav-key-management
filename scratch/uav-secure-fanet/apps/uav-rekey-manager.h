/**
 * apps/uav-rekey-manager.h
 * Module 46 - Rekey Event Logic
 *
 * REKEY MODEL (per project spec):
 *   When UAV leaves:
 *     TEK_new = SHA256(TEK_old || timestamp || nonce)
 *   SKDC updates TEK and MT_K.
 *   KDC maintains cluster TEK awareness.
 *
 * REKEY TRIGGERS:
 *   1. UAV leave event
 *   2. UAV compromise/revocation
 *   3. Periodic rekey (scheduled)
 *   4. KDC-initiated global rekey
 *   5. Handover (both clusters)
 *
 * REKEY PACKET contains:
 *   - MT_K (new)
 *   - sequence number
 *   - nonce
 *   - timestamp
 *   - cluster ID
 */

#ifndef UAV_REKEY_MANAGER_H
#define UAV_REKEY_MANAGER_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-multicast-manager.h"
#include "routing/uav-topology.h"
#include "crypto/uav-crypto-params.h"
#include "utils/uav-types.h"
#include "utils/uav-time-utils.h"

#include <vector>
#include <functional>
#include <array>

namespace uav {
namespace apps {

// ===========================================================================
// RekeyReason - why a rekey was triggered
// ===========================================================================
enum class RekeyReason {
    LEAVE       = 0,
    COMPROMISE  = 1,
    PERIODIC    = 2,
    KDC_INIT    = 3,
    HANDOVER    = 4
};

static inline const char* RekeyReasonStr(
    RekeyReason r)
{
    switch (r) {
    case RekeyReason::LEAVE:      return "LEAVE";
    case RekeyReason::COMPROMISE: return "COMPROMISE";
    case RekeyReason::PERIODIC:   return "PERIODIC";
    case RekeyReason::KDC_INIT:   return "KDC_INIT";
    case RekeyReason::HANDOVER:   return "HANDOVER";
    default: return "UNKNOWN";
    }
}

// ===========================================================================
// RekeyEvent - record of a rekey operation
// ===========================================================================
struct RekeyEvent {
    utils::u32  cluster_id    = 0;
    utils::u32  old_version   = 0;
    utils::u32  new_version   = 0;
    RekeyReason reason;
    double      time_s        = 0.0;
    double      latency_ms    = 0.0;
    bool        success       = false;
};

// ===========================================================================
// RekeyManager - Module 46
// ===========================================================================
class RekeyManager {
public:
    static constexpr double PERIODIC_INTERVAL_S = 60.0;

    using RekeyCallback =
        std::function<void(const RekeyEvent&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    RekeyManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params,
        TekManager*                     tek_mgr,
        MtkDistributionManager*         dist_mgr,
        MulticastManager*               mc_mgr);

    // -----------------------------------------------------------------------
    // Rekey triggers
    // -----------------------------------------------------------------------

    /// Trigger rekey for cluster (any reason)
    bool TriggerRekey(
        utils::u32       cluster_id,
        RekeyReason      reason,
        SkdcApplication* skdc);

    /// KDC-initiated global rekey (all clusters)
    void GlobalRekey(
        std::array<Ptr<SkdcApplication>, 3>& skdc_apps,
        RekeyReason reason = RekeyReason::KDC_INIT);

    /// Schedule periodic rekey for cluster
    void SchedulePeriodic(
        utils::u32 cluster_id,
        Ptr<SkdcApplication> skdc,
        double interval_s = PERIODIC_INTERVAL_S);

    // -----------------------------------------------------------------------
    // TEK derivation (per spec)
    // TEK_new = SHA256(TEK_old || timestamp || nonce)
    // -----------------------------------------------------------------------
    crypto::AesGcmKey DeriveTek(
        const crypto::AesGcmKey& old_tek,
        utils::u64               timestamp_us,
        const utils::Nonce128&    nonce) const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalRekeys() const {
        return m_total_rekeys;
    }
    utils::u64 GetRekeyCount(
        utils::u32 cluster_id) const;
    double GetAvgRekeyLatency() const;

    const std::vector<RekeyEvent>& GetHistory()
        const { return m_history; }

    void SetRekeyCallback(RekeyCallback cb) {
        m_rekey_cb = cb;
    }

    void PrintRekeyStats() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;
    TekManager*                     m_tek_mgr;
    MtkDistributionManager*         m_dist_mgr;
    MulticastManager*               m_mc_mgr;

    std::vector<RekeyEvent>         m_history;
    RekeyCallback                   m_rekey_cb;
    utils::u64                      m_total_rekeys = 0;
    std::array<utils::u64, 3>       m_cluster_rekeys = {0,0,0};

    void PeriodicRekeyCallback(
        utils::u32 cluster_id,
        Ptr<SkdcApplication> skdc);
};

} // namespace apps
} // namespace uav

#endif // UAV_REKEY_MANAGER_H
