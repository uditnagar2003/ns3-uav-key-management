/**
 * mobility/uav-jammer-mobility.h
 * Module 34 - Jammer mobility manager
 *
 * JAMMER SPEC (per project):
 *   Model  : RandomWaypointMobilityModel
 *   Speed  : 10 m/s
 *   Power  : 30 dBm Tx
 *   SINR   : degrades below 8 dB threshold
 *
 * The jammer moves using RandomWaypoint mobility
 * across the entire simulation area.
 * Its position is tracked and used by WifiConfigManager
 * to compute SINR degradation on UAV links.
 */

#ifndef UAV_JAMMER_MOBILITY_H
#define UAV_JAMMER_MOBILITY_H

#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <vector>
#include <string>
#include <functional>

namespace uav {
namespace mobility {

// ===========================================================================
// JammerPosition - snapshot of jammer state
// ===========================================================================
struct JammerPosition {
    double x       = 0.0;
    double y       = 0.0;
    double z       = 0.0;
    double time_s  = 0.0;
    double speed   = 10.0;   // m/s
};

// ===========================================================================
// JammerMobilityManager - Module 34
// ===========================================================================
class JammerMobilityManager {
public:
    static constexpr double JAMMER_SPEED_MPS  = 10.0;
    static constexpr double JAMMER_TX_DBM     = 30.0;
    static constexpr double SINR_THRESHOLD_DB =  8.0;
    static constexpr double JAMMER_ALT_M      = 50.0;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit JammerMobilityManager(
        const routing::TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Install RandomWaypoint mobility on jammer node
    // -----------------------------------------------------------------------
    void InstallRandomWaypoint(
        double min_speed = JAMMER_SPEED_MPS,
        double max_speed = JAMMER_SPEED_MPS,
        utils::u32 seed  = 42);

    // -----------------------------------------------------------------------
    // Position queries
    // -----------------------------------------------------------------------
    JammerPosition GetPosition() const;

    double GetDistanceToUav(
        utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // SINR impact
    // -----------------------------------------------------------------------

    /// Get list of UAVs affected by jammer
    /// (SINR degraded below threshold)
    std::vector<utils::u32> GetAffectedUavs(
        double jamming_range_m = 300.0) const;

    /// Check if specific UAV is jammed
    bool IsUavJammed(utils::u32 uav_index,
                     double jamming_range_m = 300.0) const;

    /// Estimate jammer interference at UAV (dBm)
    double GetJammerInterference(
        utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------------
    using JammerCallback =
        std::function<void(JammerPosition)>;

    void SetPositionCallback(JammerCallback cb) {
        m_cb = cb;
    }

    // -----------------------------------------------------------------------
    // Print
    // -----------------------------------------------------------------------
    void PrintStatus() const;

private:
    const routing::TopologyResult& m_topo;
    JammerCallback                 m_cb;

    ns3::Vector GetJammerVec() const;
    ns3::Vector GetUavVec(utils::u32 idx) const;

    double FriisLossDb(double dist_m) const;
};

} // namespace mobility
} // namespace uav

#endif // UAV_JAMMER_MOBILITY_H
