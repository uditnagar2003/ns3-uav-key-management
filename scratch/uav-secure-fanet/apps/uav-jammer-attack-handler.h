/**
 * apps/uav-jammer-attack-handler.h
 * Module 47 — Jammer Attack Handling
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

struct AttackEvent {
    double      time_s          = 0.0;
    utils::u32  cluster_id      = 0;
    utils::u32  jammed_count    = 0;
    utils::u32  cluster_size    = 0;
    utils::u32  revoked_count   = 0;
    bool        rekey_triggered = false;
    double      min_sinr_db     = 0.0;
};

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

    void HandleJammerEvent(const JammerEvent& ev);
    void SchedulePeriodicHandling(double interval_s);
    void SetRekeyThreshold(double t) { m_rekey_threshold = t; }

    utils::u64 GetTotalAttackEvents()   const { return m_total_events;     }
    utils::u64 GetTotalRekeyTriggered() const { return m_rekeys_triggered; }
    utils::u64 GetTotalRevocations()    const { return m_total_revocations;}

    const std::vector<AttackEvent>& GetHistory() const { return m_history; }
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
    utils::u32 UavToCluster(utils::u32 uav_id) const { return uav_id / 6; }
    utils::u32 UavToIndex  (utils::u32 uav_id) const { return uav_id % 6; }
};

} // namespace apps
} // namespace uav

#endif // UAV_JAMMER_ATTACK_HANDLER_H
