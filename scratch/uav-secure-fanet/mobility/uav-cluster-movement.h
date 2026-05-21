/**
 * mobility/uav-cluster-movement.h
 * Module 32 - Cluster movement logic
 * Module 33 - Boundary reflection logic
 */

#ifndef UAV_CLUSTER_MOVEMENT_H
#define UAV_CLUSTER_MOVEMENT_H

#include "uav-mobility-manager.h"
#include "uav-types.h"
#include "ns3/vector.h"

#include <array>
#include <vector>

namespace uav {
namespace mobility {

// ===========================================================================
// ClusterMovementManager - Modules 32 + 33
// ===========================================================================
class ClusterMovementManager {
public:
    // Simulation boundaries
    static constexpr double BOUND_X_MIN =   0.0;
    static constexpr double BOUND_X_MAX = 1500.0;
    static constexpr double BOUND_Y_MIN =   0.0;
    static constexpr double BOUND_Y_MAX = 1500.0;
    static constexpr double BOUND_Z_MIN =  50.0;
    static constexpr double BOUND_Z_MAX = 150.0;

    explicit ClusterMovementManager(
        const routing::TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Module 32: Cluster movement logic
    // -----------------------------------------------------------------------

    /// Check if UAV has left its assigned cluster area
    bool HasLeftClusterArea(utils::u32 uav_index,
                             double threshold_m = 400.0) const;

    /// Get UAVs that have crossed cluster boundaries
    std::vector<utils::u32> GetHandoverCandidates() const;

    /// Get nearest cluster for position
    utils::u32 GetNearestCluster(
        double x, double y) const;

    /// Get intra-cluster cohesion score (0-1)
    double GetClusterCohesion(
        utils::u32 cluster) const;

    /// Print cluster movement summary
    void PrintMovementSummary() const;

    // -----------------------------------------------------------------------
    // Module 33: Boundary reflection
    // -----------------------------------------------------------------------

    /// Apply reflective boundary to a position+velocity
    /// Returns corrected position
    ns3::Vector ApplyReflection(
        const ns3::Vector& pos,
        ns3::Vector& vel) const;

    /// Check if position is within bounds
    bool IsInBounds(const ns3::Vector& pos) const;

    /// Clamp position to bounds (without reflection)
    ns3::Vector ClampToBounds(
        const ns3::Vector& pos) const;

    /// Check boundary violations across all UAVs
    utils::u32 CountBoundaryViolations() const;

    /// Print boundary status
    void PrintBoundaryStatus() const;

private:
    const routing::TopologyResult& m_topo;

    static constexpr double CLUSTER_CENTERS[3][2] = {
        {250.0,  750.0},
        {750.0,  250.0},
        {1250.0, 750.0}
    };

    ns3::Vector GetUavPos(utils::u32 idx) const;
};

} // namespace mobility
} // namespace uav

#endif // UAV_CLUSTER_MOVEMENT_H
