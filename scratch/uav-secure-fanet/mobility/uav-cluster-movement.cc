/**
 * mobility/uav-cluster-movement.cc
 * Module 32 - Cluster movement logic
 * Module 33 - Boundary reflection logic
 */

#include "uav-cluster-movement.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/mobility-model.h"
#include "ns3/simulator.h"

#include <cmath>
#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavClusterMovement");

using namespace ns3;

namespace uav {
namespace mobility {

constexpr double ClusterMovementManager::CLUSTER_CENTERS[3][2];

ClusterMovementManager::ClusterMovementManager(
    const routing::TopologyResult& topo)
    : m_topo(topo)
{
    UAV_LOG_INFO(uav::log::channels::MOBILITY,
        "ClusterMovementManager: initialized "
        "bounds=(" << BOUND_X_MAX << "x"
        << BOUND_Y_MAX << "x"
        << BOUND_Z_MAX << ")m");
}

// ===========================================================================
// Helper: get UAV position
// ===========================================================================
Vector ClusterMovementManager::GetUavPos(
    utils::u32 idx) const
{
    if (idx >= m_topo.uav_nodes.GetN())
        return Vector(0,0,0);
    Ptr<MobilityModel> mob =
        m_topo.uav_nodes.Get(idx)
              ->GetObject<MobilityModel>();
    if (!mob) return Vector(0,0,0);
    return mob->GetPosition();
}

// ===========================================================================
// Module 32: Cluster movement logic
// ===========================================================================
bool ClusterMovementManager::HasLeftClusterArea(
    utils::u32 uav_index,
    double threshold_m) const
{
    utils::u32 cluster = uav_index / 6;
    Vector pos = GetUavPos(uav_index);
    double cx = CLUSTER_CENTERS[cluster][0];
    double cy = CLUSTER_CENTERS[cluster][1];
    double dx = pos.x - cx;
    double dy = pos.y - cy;
    return std::sqrt(dx*dx + dy*dy) > threshold_m;
}

std::vector<utils::u32>
ClusterMovementManager::GetHandoverCandidates() const
{
    std::vector<utils::u32> candidates;
    for (utils::u32 i = 0; i < 18; ++i) {
        if (HasLeftClusterArea(i)) {
            // Check if nearer to another cluster
            Vector pos = GetUavPos(i);
            utils::u32 nearest =
                GetNearestCluster(pos.x, pos.y);
            if (nearest != i / 6) {
                candidates.push_back(i);
            }
        }
    }
    return candidates;
}

utils::u32 ClusterMovementManager::GetNearestCluster(
    double x, double y) const
{
    utils::u32 nearest = 0;
    double min_dist = 1e9;
    for (utils::u32 c = 0; c < 3; ++c) {
        double dx = x - CLUSTER_CENTERS[c][0];
        double dy = y - CLUSTER_CENTERS[c][1];
        double dist = std::sqrt(dx*dx + dy*dy);
        if (dist < min_dist) {
            min_dist = dist;
            nearest  = c;
        }
    }
    return nearest;
}

double ClusterMovementManager::GetClusterCohesion(
    utils::u32 cluster) const
{
    if (cluster >= 3) return 0.0;
    utils::u32 base = cluster * 6;
    double cx = CLUSTER_CENTERS[cluster][0];
    double cy = CLUSTER_CENTERS[cluster][1];

    double total_dist = 0.0;
    for (utils::u32 u = 0; u < 6; ++u) {
        Vector pos = GetUavPos(base + u);
        double dx = pos.x - cx;
        double dy = pos.y - cy;
        total_dist += std::sqrt(dx*dx + dy*dy);
    }
    double avg_dist = total_dist / 6.0;
    // Cohesion score: 1.0 = perfect (all at center)
    // 0.0 = all at boundary (400m)
    return std::max(0.0,
        1.0 - avg_dist / 400.0);
}

void ClusterMovementManager::PrintMovementSummary()
    const
{
    std::cout << "\n=== Cluster Movement Summary ===\n";
    std::cout << "  Time: "
        << Simulator::Now().GetSeconds() << "s\n";

    for (utils::u32 c = 0; c < 3; ++c) {
        double cohesion = GetClusterCohesion(c);
        std::cout << "  Cluster " << c
            << " cohesion: "
            << std::fixed << std::setprecision(3)
            << cohesion * 100.0 << "%\n";
    }

    auto candidates = GetHandoverCandidates();
    std::cout << "  Handover candidates: "
        << candidates.size() << "\n";
    for (auto uav : candidates) {
        std::cout << "    UAV " << uav << "\n";
    }
}

// ===========================================================================
// Module 33: Boundary reflection
// ===========================================================================
Vector ClusterMovementManager::ApplyReflection(
    const Vector& pos,
    Vector& vel) const
{
    Vector new_pos = pos;

    // X boundary
    if (new_pos.x < BOUND_X_MIN) {
        new_pos.x = BOUND_X_MIN +
            (BOUND_X_MIN - new_pos.x);
        vel.x = std::abs(vel.x);
    } else if (new_pos.x > BOUND_X_MAX) {
        new_pos.x = BOUND_X_MAX -
            (new_pos.x - BOUND_X_MAX);
        vel.x = -std::abs(vel.x);
    }

    // Y boundary
    if (new_pos.y < BOUND_Y_MIN) {
        new_pos.y = BOUND_Y_MIN +
            (BOUND_Y_MIN - new_pos.y);
        vel.y = std::abs(vel.y);
    } else if (new_pos.y > BOUND_Y_MAX) {
        new_pos.y = BOUND_Y_MAX -
            (new_pos.y - BOUND_Y_MAX);
        vel.y = -std::abs(vel.y);
    }

    // Z boundary (altitude)
    if (new_pos.z < BOUND_Z_MIN) {
        new_pos.z = BOUND_Z_MIN +
            (BOUND_Z_MIN - new_pos.z);
        vel.z = std::abs(vel.z);
    } else if (new_pos.z > BOUND_Z_MAX) {
        new_pos.z = BOUND_Z_MAX -
            (new_pos.z - BOUND_Z_MAX);
        vel.z = -std::abs(vel.z);
    }

    return new_pos;
}

bool ClusterMovementManager::IsInBounds(
    const Vector& pos) const
{
    return pos.x >= BOUND_X_MIN &&
           pos.x <= BOUND_X_MAX &&
           pos.y >= BOUND_Y_MIN &&
           pos.y <= BOUND_Y_MAX &&
           pos.z >= BOUND_Z_MIN &&
           pos.z <= BOUND_Z_MAX;
}

Vector ClusterMovementManager::ClampToBounds(
    const Vector& pos) const
{
    return Vector(
        std::max(BOUND_X_MIN,
            std::min(pos.x, BOUND_X_MAX)),
        std::max(BOUND_Y_MIN,
            std::min(pos.y, BOUND_Y_MAX)),
        std::max(BOUND_Z_MIN,
            std::min(pos.z, BOUND_Z_MAX)));
}

utils::u32
ClusterMovementManager::CountBoundaryViolations()
    const
{
    utils::u32 count = 0;
    for (utils::u32 i = 0; i < 18; ++i) {
        if (!IsInBounds(GetUavPos(i))) ++count;
    }
    return count;
}

void ClusterMovementManager::PrintBoundaryStatus()
    const
{
    std::cout << "\n=== Boundary Status ===\n";
    std::cout << "  Bounds: X[" << BOUND_X_MIN
        << "," << BOUND_X_MAX << "] Y["
        << BOUND_Y_MIN << "," << BOUND_Y_MAX
        << "] Z[" << BOUND_Z_MIN << ","
        << BOUND_Z_MAX << "]\n";
    std::cout << "  Violations: "
        << CountBoundaryViolations() << "\n";

    for (utils::u32 i = 0; i < 18; ++i) {
        Vector pos = GetUavPos(i);
        if (!IsInBounds(pos)) {
            std::cout << "  UAV " << i
                << " OUT: (" << pos.x << ","
                << pos.y << "," << pos.z
                << ")\n";
        }
    }
}

} // namespace mobility
} // namespace uav
