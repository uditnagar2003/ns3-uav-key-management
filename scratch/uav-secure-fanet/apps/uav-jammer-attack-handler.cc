/**
 * apps/uav-jammer-attack-handler.cc
 * Module 47 — Jammer Attack Handling
 */

#include "apps/uav-jammer-attack-handler.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavJammerAttackHandler");

using namespace ns3;

namespace uav {
namespace apps {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
JammerAttackHandler::JammerAttackHandler(
    const routing::TopologyResult*             topo,
    JammerManager*                             jammer_mgr,
    RekeyManager*                              rekey_mgr,
    CompromiseDetector*                        comp_det,
    MulticastManager*                          mc_mgr,
    std::array<ns3::Ptr<SkdcApplication>, 3>*  skdc_apps)
    : m_topo(topo)
    , m_jammer_mgr(jammer_mgr)
    , m_rekey_mgr(rekey_mgr)
    , m_comp_det(comp_det)
    , m_mc_mgr(mc_mgr)
    , m_skdc_apps(skdc_apps)
{
    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerAttackHandler: initialized"
        " rekey_threshold=" << m_rekey_threshold);
}

// ---------------------------------------------------------------------------
// HandleJammerEvent
// ---------------------------------------------------------------------------
void JammerAttackHandler::HandleJammerEvent(
    const JammerEvent& ev)
{
    double now = Simulator::Now().GetSeconds();

    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerAttackHandler: t=" << now
        << " affected=" << ev.affected_uavs
        << " min_sinr=" << ev.min_sinr_db
        << "dB threshold_hit=" << ev.threshold_hit);

    // Per-cluster accounting
    std::array<utils::u32, 3> jammed_per_cluster  = {0, 0, 0};
    std::array<utils::u32, 3> revoked_per_cluster = {0, 0, 0};

    // Step 1: check every UAV against JammerManager
    for (utils::u32 uav_id = 0; uav_id < 18; ++uav_id) {
        if (!m_jammer_mgr->IsJammed(uav_id)) continue;

        utils::u32 cluster = UavToCluster(uav_id);
        utils::u32 idx     = UavToIndex(uav_id);
        ++jammed_per_cluster[cluster];

        // Step 2: if also compromised → revoke
        if (m_comp_det && m_skdc_apps &&
            !m_comp_det->IsRevoked(uav_id) &&
            m_jammer_mgr->IsCompromised(uav_id))
        {
            UAV_LOG_WARN(uav::log::channels::JAMMER,
                "JammerAttackHandler: UAV" << uav_id
                << " jammed+compromised → revoking");

            m_comp_det->ReportExternal(
                uav_id, cluster, idx,
                (*m_skdc_apps)[cluster]);

            ++revoked_per_cluster[cluster];
            ++m_total_revocations;
        }
    }

    // Step 3: per-cluster rekey decision
    for (utils::u32 c = 0; c < 3; ++c) {
        utils::u32 cluster_size = m_mc_mgr->GetGroupSize(c);
        if (cluster_size == 0) continue;

        double ratio =
            static_cast<double>(jammed_per_cluster[c]) /
            static_cast<double>(cluster_size);

        AttackEvent aev;
        aev.time_s        = now;
        aev.cluster_id    = c;
        aev.jammed_count  = jammed_per_cluster[c];
        aev.cluster_size  = cluster_size;
        aev.revoked_count = revoked_per_cluster[c];
        aev.min_sinr_db   = ev.min_sinr_db;

        if (jammed_per_cluster[c] > 0) {
            UAV_LOG_INFO(uav::log::channels::JAMMER,
                "JammerAttackHandler: C" << c
                << " jammed=" << jammed_per_cluster[c]
                << "/" << cluster_size
                << " ratio=" << std::fixed
                << std::setprecision(2) << ratio);
        }

        // Emergency rekey if ratio >= threshold
        if (ratio >= m_rekey_threshold &&
            m_rekey_mgr && m_skdc_apps)
        {
            UAV_LOG_WARN(uav::log::channels::JAMMER,
                "JammerAttackHandler: C" << c
                << " ratio=" << ratio
                << " >= " << m_rekey_threshold
                << " → emergency rekey");

            bool ok = m_rekey_mgr->ProcessRekey(
                c,
                RekeyTrigger::MANUAL,
                0xFFFFFFFF,
                (*m_skdc_apps)[c].operator->());

            aev.rekey_triggered = ok;
            if (ok) ++m_rekeys_triggered;
        }

        // Record if anything happened this cluster
        if (aev.jammed_count > 0 || aev.rekey_triggered) {
            ++m_total_events;
            m_history.push_back(aev);
            if (m_callback) m_callback(aev);
        }
    }
}

// ---------------------------------------------------------------------------
// SchedulePeriodicHandling
// ---------------------------------------------------------------------------
void JammerAttackHandler::SchedulePeriodicHandling(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_periodic_interval = interval_s;

    Simulator::Schedule(
        Seconds(interval_s),
        &JammerAttackHandler::PeriodicCallback, this);

    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerAttackHandler: periodic every "
        << interval_s << "s");
}

void JammerAttackHandler::PeriodicCallback()
{
    if (m_jammer_mgr) {
        JammerEvent ev = m_jammer_mgr->Scan();
        HandleJammerEvent(ev);
    }
    Simulator::Schedule(
        Seconds(m_periodic_interval),
        &JammerAttackHandler::PeriodicCallback, this);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
void JammerAttackHandler::PrintStats() const
{
    std::cout << "\n=== JammerAttackHandler Stats ===\n";
    std::cout << "  Attack events:    " << m_total_events     << "\n";
    std::cout << "  Rekeys triggered: " << m_rekeys_triggered << "\n";
    std::cout << "  Revocations:      " << m_total_revocations<< "\n";
    for (const auto& ev : m_history) {
        std::cout << "    t=" << ev.time_s
            << "s C" << ev.cluster_id
            << " jammed=" << ev.jammed_count
            << "/" << ev.cluster_size
            << " revoked=" << ev.revoked_count
            << " rekey=" << ev.rekey_triggered
            << " sinr=" << ev.min_sinr_db << "dB\n";
    }
}

} // namespace apps
} // namespace uav
