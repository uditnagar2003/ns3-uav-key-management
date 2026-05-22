/**
 * apps/uav-jammer-attack-handler.h
 * Module 47 — Jammer Attack Handling
 *
 * Integrates JammerManager (Module 43) with:
 *   - CompromiseDetector (Module 45): revokes jammer-compromised UAVs
 *   - RekeyManager (Module 46): emergency rekey when cluster >50% jammed
 *
 * RESPONSE POLICY (per project spec):
 *   1. SINR < threshold  → UAV marked JAMMED
 *   2. Compromised UAV   → ForceRevoke via CompromiseDetector
 *   3. jammed/cluster_size > threshold → emergency rekey
 *   4. All events logged to jammer.log
 */

#ifndef UAV_JAMMER_ATTACK_HANDLER_H
#define UAV_JAMMER_ATTACK_HANDLER_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-rekey-manager.h"
#include "apps/uav-compromise-detector.h"
#include "apps/uav-jammer-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <array>
#include <vector>
#include <functional>

namespace uav {
namespace apps {

// ===========================================================================
// AttackEvent — one recorded jammer attack response
// ===========================================================================
struct AttackEvent {
    double      time_s          = 0.0;
    utils::u32  cluster_id      = 0;
    utils::u32  jammed_count    = 0;
    utils::u32  cluster_size    = 0;
    utils::u32  revoked_count   = 0;
    bool        rekey_triggered = false;
    double      min_sinr_db     = 0.0;
};

// ===========================================================================
// JammerAttackHandler — Module 47
// ===========================================================================
class JammerAttackHandler {
public:
    using AttackCallback =
        std::function<void(const AttackEvent&)>;

    JammerAttackHandler(
        const routing::TopologyResult*             topo,
        JammerManager*                             jammer_mgr,
        RekeyManager*                              rekey_mgr,
        CompromiseDetector*                        comp_det,
        MulticastManager*                          mc_mgr,
        std::array<ns3::Ptr<SkdcApplication>, 3>*  skdc_apps);

    /**
     * HandleJammerEvent — process one JammerEvent from JammerManager::Scan()
     *
     * Per cluster:
     *   1. Count jammed UAVs via JammerManager::IsJammed()
     *   2. Revoke any also flagged by JammerManager::IsCompromised()
     *   3. If jammed ratio >= m_rekey_threshold → emergency rekey
     */
    void HandleJammerEvent(const JammerEvent& ev);

    /**
     * SchedulePeriodicHandling — calls JammerManager::Scan() then
     * HandleJammerEvent() every interval_s seconds.
     */
    void SchedulePeriodicHandling(double interval_s);

    /// Fraction of cluster jammed to trigger rekey (default 0.5)
    void SetRekeyThreshold(double t) { m_rekey_threshold = t; }

    // Stats
    utils::u64 GetTotalAttackEvents()    const { return m_total_events;     }
    utils::u64 GetTotalRekeyTriggered()  const { return m_rekeys_triggered; }
    utils::u64 GetTotalRevocations()     const { return m_total_revocations;}

    const std::vector<AttackEvent>& GetHistory() const {
        return m_history;
    }
    void SetCallback(AttackCallback cb) { m_callback = cb; }
    void PrintStats() const;

private:
    const routing::TopologyResult*            m_topo;
    JammerManager*                            m_jammer_mgr;
    RekeyManager*                             m_rekey_mgr;
    CompromiseDetector*                       m_comp_det;
    MulticastManager*                         m_mc_mgr;
    std::array<ns3::Ptr<SkdcApplication>, 3>* m_skdc_apps;

    std::vector<AttackEvent>                  m_history;
    AttackCallback                            m_callback;

    double      m_rekey_threshold   = 0.5;
    double      m_periodic_interval = 0.0;
    utils::u64  m_total_events      = 0;
    utils::u64  m_rekeys_triggered  = 0;
    utils::u64  m_total_revocations = 0;

    void PeriodicCallback();

    // UAV 0-5 → cluster 0, 6-11 → cluster 1, 12-17 → cluster 2
    utils::u32 UavToCluster(utils::u32 uav_id) const { return uav_id / 6; }
    utils::u32 UavToIndex  (utils::u32 uav_id) const { return uav_id % 6; }
};

} // namespace apps
} // namespace uav

#endif // UAV_JAMMER_ATTACK_HANDLER_H
