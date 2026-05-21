/**
 * apps/uav-jammer-manager.h
 * Module 43 - Jammer Detection and SINR Degradation
 *
 * DENIED ENVIRONMENT MODEL (per project spec):
 *   - SINR degradation from mobile jammer
 *   - SINR failure threshold: 8 dB
 *   - Mobile jammer: 10 m/s, 30 dBm Tx
 *   - Node compromise probability: 5%
 *   - Packet drops under jamming
 *   - Routing instability
 *   - Temporary disconnections
 */

#ifndef UAV_JAMMER_MANAGER_H
#define UAV_JAMMER_MANAGER_H

#include "mobility/uav-jammer-mobility.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"

#include <vector>
#include <unordered_map>
#include <functional>

namespace uav {
namespace apps {

// ===========================================================================
// JammerEvent - single jammer impact record
// ===========================================================================
struct JammerEvent {
    double      time_s         = 0.0;
    utils::u32  affected_uavs  = 0;
    double      jammer_x       = 0.0;
    double      jammer_y       = 0.0;
    double      min_sinr_db    = 0.0;
    bool        threshold_hit  = false;
};

// ===========================================================================
// JammerManager - Module 43
// ===========================================================================
class JammerManager {
public:
    static constexpr double SINR_THRESHOLD_DB  = 8.0;
    static constexpr double NOISE_FLOOR_DBM    = -95.0;
    static constexpr double SIGNAL_TX_DBM      = 20.0;
    static constexpr double COMPROMISE_PROB    = 0.05;

    using JammerAlertCallback =
        std::function<void(const JammerEvent&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    JammerManager(
        const routing::TopologyResult*        topo,
        mobility::JammerMobilityManager*      jammer_mob);

    // -----------------------------------------------------------------------
    // SINR computation
    // -----------------------------------------------------------------------

    /// Compute SINR for UAV (dB)
    double ComputeSinr(utils::u32 uav_index) const;

    /// Check if UAV is below SINR threshold
    bool IsJammed(utils::u32 uav_index) const;

    /// Get all currently jammed UAVs
    std::vector<utils::u32> GetJammedUavs() const;

    /// Get jammer impact level (0.0-1.0)
    double GetJammerImpact(utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Packet drop probability under jamming
    // -----------------------------------------------------------------------

    /// Get packet drop probability for UAV (0.0-1.0)
    double GetDropProbability(utils::u32 uav_index) const;

    /// Simulate packet drop under jamming
    bool ShouldDrop(utils::u32 uav_index,
                    utils::u32 seed = 0) const;

    // -----------------------------------------------------------------------
    // Node compromise
    // -----------------------------------------------------------------------

    /// Check if a UAV is compromised (5% probability)
    bool IsCompromised(utils::u32 uav_index) const;

    /// Get all currently compromised UAVs
    std::vector<utils::u32> GetCompromisedUavs() const;

    // -----------------------------------------------------------------------
    // Periodic scan
    // -----------------------------------------------------------------------

    /// Scan all UAVs for jammer impact
    JammerEvent Scan() const;

    /// Start periodic scanning
    void StartPeriodicScan(double interval_s = 1.0);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalJammerEvents()  const {
        return m_jammer_events;
    }
    utils::u64 GetTotalPacketDrops()   const {
        return m_packet_drops;
    }

    void SetAlertCallback(JammerAlertCallback cb) {
        m_alert_cb = cb;
    }

    void PrintJammerStatus() const;

private:
    const routing::TopologyResult*       m_topo;
    mobility::JammerMobilityManager*     m_jammer_mob;
    JammerAlertCallback                  m_alert_cb;

    mutable std::vector<utils::u32>      m_compromised;
    mutable utils::u64                   m_jammer_events = 0;
    mutable utils::u64                   m_packet_drops  = 0;

    double FriisPathLoss(double dist_m) const;
    void   PeriodicScanCallback();
};

} // namespace apps
} // namespace uav

#endif // UAV_JAMMER_MANAGER_H
