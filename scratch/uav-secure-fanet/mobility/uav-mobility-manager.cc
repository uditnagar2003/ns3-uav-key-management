/**
 * mobility/uav-mobility-manager.cc
 */

#include "uav-mobility-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/rectangle.h"
#include "ns3/box.h"

#include <cmath>
#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavMobilityManager");

using namespace ns3;

namespace uav {
namespace mobility {

// Static member definition
constexpr double MobilityManager::CLUSTER_CENTERS[3][2];

// ===========================================================================
// Constructor
// ===========================================================================
MobilityManager::MobilityManager(
    const routing::TopologyResult& topo,
    const MobilityConfig& cfg)
    : m_topo(topo)
    , m_cfg(cfg)
{
    // Initialize original cluster assignments
    for (utils::u32 i = 0; i < 18; ++i)
        m_original_cluster[i] = GetClusterForUav(i);

    UAV_LOG_INFO(uav::log::channels::MOBILITY,
        "MobilityManager: initialized "
        << topo.uav_nodes.GetN() << " UAVs"
        << " speed=[" << cfg.min_speed_mps
        << "," << cfg.max_speed_mps << "] m/s"
        << " alt=[" << cfg.min_altitude_m
        << "," << cfg.max_altitude_m << "] m");
}

// ===========================================================================
// Install GaussMarkov mobility
// ===========================================================================
void MobilityManager::InstallGaussMarkov() {
    MobilityHelper mobility;

    // Set initial positions via ListPositionAllocator
    Ptr<ListPositionAllocator> pos =
        CreateObject<ListPositionAllocator>();

    for (utils::u32 c = 0; c < 3; ++c) {
        double cx = CLUSTER_CENTERS[c][0];
        double cy = CLUSTER_CENTERS[c][1];

        for (utils::u32 u = 0;
             u < (utils::u32)m_cfg.formation_radius_m / 16 + 6;
             ++u)
        {
            if (u >= 6) break;
            // Hexagonal formation
            double angle =
                (2.0 * M_PI * u) / 6.0;
            double r = m_cfg.formation_radius_m;
            double x = cx + r * std::cos(angle);
            double y = cy + r * std::sin(angle);

            // Clamp to area
            x = std::max(10.0, std::min(x,
                m_cfg.area_x_m - 10.0));
            y = std::max(10.0, std::min(y,
                m_cfg.area_y_m - 10.0));

            // Altitude: 50-150m, staggered
            double z = m_cfg.min_altitude_m +
                (m_cfg.max_altitude_m -
                 m_cfg.min_altitude_m) *
                static_cast<double>(u) / 5.0;

            pos->Add(Vector(x, y, z));
        }
    }

    mobility.SetPositionAllocator(pos);

    // GaussMarkov mobility model
    mobility.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(
            0.0, m_cfg.area_x_m,
            0.0, m_cfg.area_y_m,
            m_cfg.min_altitude_m,
            m_cfg.max_altitude_m)),
        "TimeStep", TimeValue(
            Seconds(m_cfg.update_interval_s)),
        "Alpha", DoubleValue(m_cfg.alpha),
        "MeanVelocity", StringValue(
            "ns3::ConstantRandomVariable[Constant="
            + std::to_string(m_cfg.mean_velocity)
            + "]"),
        "MeanDirection", StringValue(
            "ns3::ConstantRandomVariable[Constant="
            + std::to_string(m_cfg.mean_direction)
            + "]"),
        "MeanPitch", StringValue(
            "ns3::ConstantRandomVariable[Constant="
            + std::to_string(m_cfg.mean_pitch)
            + "]"),
        "NormalVelocity", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|"
            "Variance=" + std::to_string(m_cfg.variance)
            + "]"),
        "NormalDirection", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|"
            "Variance=0.1]"),
        "NormalPitch", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|"
            "Variance=0.02]"));

    mobility.Install(m_topo.uav_nodes);

    // Trigger GaussMarkov to start moving
    // Set initial non-zero velocity on each UAV
    for (utils::u32 i = 0;
         i < m_topo.uav_nodes.GetN(); ++i)
    {
        Ptr<Node> node = m_topo.uav_nodes.Get(i);
        Ptr<GaussMarkovMobilityModel> gmm =
            node->GetObject<GaussMarkovMobilityModel>();
        if (gmm) {
            // Set initial velocity vector
            double speed = m_cfg.mean_velocity;
            gmm->SetAttribute("MeanVelocity",
                StringValue(
                    "ns3::ConstantRandomVariable[Constant="
                    + std::to_string(speed) + "]"));
        }
    }

    UAV_LOG_INFO(uav::log::channels::MOBILITY,
        "MobilityManager: GaussMarkov installed on "
        << m_topo.uav_nodes.GetN() << " UAVs"
        << " alpha=" << m_cfg.alpha
        << " mean_v=" << m_cfg.mean_velocity);
}

// ===========================================================================
// Position queries
// ===========================================================================
UavPosition MobilityManager::GetUavPosition(
    utils::u32 uav_index) const
{
    UavPosition p;
    p.uav_index = uav_index;
    p.cluster   = GetClusterForUav(uav_index);
    p.time_s    = Simulator::Now().GetSeconds();

    if (uav_index >= m_topo.uav_nodes.GetN())
        return p;

    Ptr<Node> node = m_topo.uav_nodes.Get(uav_index);
    Ptr<MobilityModel> mob =
        node->GetObject<MobilityModel>();

    if (mob) {
        Vector pos = mob->GetPosition();
        Vector vel = mob->GetVelocity();
        p.x = pos.x;
        p.y = pos.y;
        p.z = pos.z;
        p.speed = std::sqrt(
            vel.x*vel.x + vel.y*vel.y + vel.z*vel.z);
    }

    return p;
}

std::vector<UavPosition>
MobilityManager::GetAllPositions() const
{
    std::vector<UavPosition> positions;
    positions.reserve(18);
    for (utils::u32 i = 0; i < 18; ++i)
        positions.push_back(GetUavPosition(i));
    return positions;
}

double MobilityManager::GetUavDistance(
    utils::u32 uav_a, utils::u32 uav_b) const
{
    auto pa = GetUavPosition(uav_a);
    auto pb = GetUavPosition(uav_b);
    double dx = pa.x - pb.x;
    double dy = pa.y - pb.y;
    double dz = pa.z - pb.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

double MobilityManager::GetDistanceToClusterCenter(
    utils::u32 uav_index) const
{
    auto p = GetUavPosition(uav_index);
    utils::u32 c = GetClusterForUav(uav_index);
    double cx = CLUSTER_CENTERS[c][0];
    double cy = CLUSTER_CENTERS[c][1];
    double dx = p.x - cx;
    double dy = p.y - cy;
    return std::sqrt(dx*dx + dy*dy);
}

// ===========================================================================
// Cluster membership
// ===========================================================================
utils::u32 MobilityManager::GetNearestCluster(
    utils::u32 uav_index) const
{
    auto p = GetUavPosition(uav_index);
    utils::u32 nearest = 0;
    double min_dist = 1e9;

    for (utils::u32 c = 0; c < 3; ++c) {
        double dx = p.x - CLUSTER_CENTERS[c][0];
        double dy = p.y - CLUSTER_CENTERS[c][1];
        double dist = std::sqrt(dx*dx + dy*dy);
        if (dist < min_dist) {
            min_dist = dist;
            nearest  = c;
        }
    }
    return nearest;
}

bool MobilityManager::HasClusterChanged(
    utils::u32 uav_index) const
{
    utils::u32 original = m_original_cluster[uav_index];
    utils::u32 current  = GetNearestCluster(uav_index);
    return (current != original);
}

// ===========================================================================
// Print
// ===========================================================================
void MobilityManager::PrintPositions() const {
    std::cout << "\n=== UAV Positions at t="
              << Simulator::Now().GetSeconds()
              << "s ===\n";
    for (utils::u32 i = 0; i < 18; ++i) {
        auto p = GetUavPosition(i);
        std::cout << "  UAV " << std::setw(2) << i
            << " C" << p.cluster
            << ": (" << std::fixed
            << std::setprecision(1)
            << p.x << "," << p.y << ","
            << p.z << ")"
            << " v=" << p.speed << "m/s\n";
    }
}

void MobilityManager::PrintClusterMembership() const {
    std::cout << "\n=== Cluster Membership ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        std::cout << "  Cluster " << c << ":";
        for (utils::u32 i = 0; i < 18; ++i) {
            if (GetNearestCluster(i) == c)
                std::cout << " UAV" << i;
        }
        std::cout << "\n";
    }
}

} // namespace mobility
} // namespace uav
