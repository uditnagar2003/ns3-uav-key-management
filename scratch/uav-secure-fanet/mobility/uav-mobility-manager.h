/**
 * mobility/uav-mobility-manager.h
 *
 * UAV Mobility Manager
 *
 * Manages GaussMarkov 3D mobility for all 18 UAVs.
 *
 * MOBILITY SPEC (per project):
 *   Model    : GaussMarkovMobilityModel
 *   Speed    : 10-25 m/s
 *   Altitude : 50-150 m
 *   Area     : 1500m × 1500m × 200m
 *   Boundaries: reflective
 *   Movement : formation-based cluster movement
 *              + random perturbations
 *
 * CLUSTER CENTERS (initial):
 *   Cluster 0: (250,  750) → SKDC0 coverage area
 *   Cluster 1: (750,  250) → SKDC1 coverage area
 *   Cluster 2: (1250, 750) → SKDC2 coverage area
 *
 * Formation: UAVs arranged in hexagonal pattern
 *            around cluster center, 100m radius
 */

#ifndef UAV_MOBILITY_MANAGER_H
#define UAV_MOBILITY_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/gauss-markov-mobility-model.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <array>
#include <vector>
#include <string>
#include <functional>

namespace uav {
namespace mobility {

// ===========================================================================
// UAV position record
// ===========================================================================
struct UavPosition {
    utils::u32  uav_index = 0;
    utils::u32  cluster   = 0;
    double      x         = 0.0;
    double      y         = 0.0;
    double      z         = 0.0;
    double      speed     = 0.0;   // m/s
    double      time_s    = 0.0;
};

// ===========================================================================
// MobilityConfig — per-simulation mobility parameters
// ===========================================================================
struct MobilityConfig {
    // Speed bounds
    double  min_speed_mps    = 10.0;
    double  max_speed_mps    = 25.0;

    // Altitude bounds
    double  min_altitude_m   = 50.0;
    double  max_altitude_m   = 150.0;

    // Area bounds
    double  area_x_m         = 1500.0;
    double  area_y_m         = 1500.0;
    double  area_z_m         = 200.0;

    // Formation radius around cluster center
    double  formation_radius_m = 100.0;

    // GaussMarkov parameters
    double  alpha            = 0.85;  // memory factor
    double  mean_velocity    = 15.0;  // m/s
    double  mean_direction   = 0.0;   // radians
    double  mean_pitch       = 0.0;   // radians
    double  variance         = 3.0;

    // Update interval
    double  update_interval_s = 0.5;

    // Random seed
    utils::u32 seed          = 42;
};

// ===========================================================================
// MobilityManager
// ===========================================================================
class MobilityManager {
public:
    // Cluster center positions
    static constexpr double CLUSTER_CENTERS[3][2] = {
        {250.0,  750.0},
        {750.0,  250.0},
        {1250.0, 750.0}
    };

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    MobilityManager(const routing::TopologyResult& topo,
                    const MobilityConfig& cfg =
                        MobilityConfig{});

    // -----------------------------------------------------------------------
    // Install GaussMarkov mobility on all UAVs
    // -----------------------------------------------------------------------
    void InstallGaussMarkov();

    // -----------------------------------------------------------------------
    // Position queries
    // -----------------------------------------------------------------------

    /// Get current position of UAV
    UavPosition GetUavPosition(utils::u32 uav_index) const;

    /// Get all UAV positions at current time
    std::vector<UavPosition> GetAllPositions() const;

    /// Get distance between two UAVs (meters)
    double GetUavDistance(utils::u32 uav_a,
                          utils::u32 uav_b) const;

    /// Get distance from UAV to its cluster center
    double GetDistanceToClusterCenter(
        utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Cluster membership based on position
    // -----------------------------------------------------------------------

    /// Get nearest cluster center for a UAV's current position
    utils::u32 GetNearestCluster(
        utils::u32 uav_index) const;

    /// Check if UAV has moved to a different cluster
    /// (handover trigger condition)
    bool HasClusterChanged(utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Mobility callbacks
    // -----------------------------------------------------------------------

    using PositionCallback =
        std::function<void(utils::u32, UavPosition)>;

    /// Register callback for position updates
    void SetPositionCallback(PositionCallback cb) {
        m_position_cb = cb;
    }

    // -----------------------------------------------------------------------
    // Print
    // -----------------------------------------------------------------------
    void PrintPositions() const;
    void PrintClusterMembership() const;

    const MobilityConfig& GetConfig() const {
        return m_cfg;
    }

private:
    const routing::TopologyResult& m_topo;
    MobilityConfig                 m_cfg;
    PositionCallback               m_position_cb;

    // Original cluster assignment per UAV
    std::array<utils::u32, 18>  m_original_cluster;

    /// Set initial UAV positions in formation
    void SetInitialFormationPositions();

    /// Get cluster for UAV index (0-17)
    static utils::u32 GetClusterForUav(
        utils::u32 uav_index) {
        return uav_index / 6;
    }
};

} // namespace mobility
} // namespace uav

#endif // UAV_MOBILITY_MANAGER_H
