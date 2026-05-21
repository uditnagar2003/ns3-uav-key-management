/**
 * mobility/uav-jammer-mobility.cc
 * Module 34 - Jammer mobility manager
 */

#include "uav-jammer-mobility.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/mobility-model.h"
#include "ns3/simulator.h"
#include "ns3/random-variable-stream.h"

#include <cmath>
#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavJammerMobility");

using namespace ns3;

namespace uav {
namespace mobility {

// ===========================================================================
// Constructor
// ===========================================================================
JammerMobilityManager::JammerMobilityManager(
    const routing::TopologyResult& topo)
    : m_topo(topo)
{
    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerMobilityManager: initialized"
        " speed=" << JAMMER_SPEED_MPS << "m/s"
        " power=" << JAMMER_TX_DBM << "dBm");
}

// ===========================================================================
// Install RandomWaypoint mobility on jammer
// ===========================================================================
void JammerMobilityManager::InstallRandomWaypoint(
    double min_speed,
    double max_speed,
    utils::u32 seed)
{
    if (m_topo.jammer_node.GetN() == 0) {
        UAV_LOG_WARN(uav::log::channels::JAMMER,
            "JammerMobilityManager: no jammer node");
        return;
    }

    MobilityHelper mobility;

    // Random starting position
    Ptr<RandomRectanglePositionAllocator> pos =
        CreateObject<RandomRectanglePositionAllocator>();

    Ptr<UniformRandomVariable> xrv =
        CreateObject<UniformRandomVariable>();
    xrv->SetAttribute("Min", DoubleValue(0.0));
    xrv->SetAttribute("Max", DoubleValue(1500.0));
    xrv->SetStream(static_cast<int64_t>(seed));

    Ptr<UniformRandomVariable> yrv =
        CreateObject<UniformRandomVariable>();
    yrv->SetAttribute("Min", DoubleValue(0.0));
    yrv->SetAttribute("Max", DoubleValue(1500.0));
    yrv->SetStream(static_cast<int64_t>(seed + 1));

    pos->SetX(xrv);
    pos->SetY(yrv);
    mobility.SetPositionAllocator(pos);

    // RandomWaypoint with constant speed
    Ptr<UniformRandomVariable> speed_rv =
        CreateObject<UniformRandomVariable>();
    speed_rv->SetAttribute("Min",
        DoubleValue(min_speed));
    speed_rv->SetAttribute("Max",
        DoubleValue(max_speed));
    speed_rv->SetStream(static_cast<int64_t>(seed+2));

    Ptr<ConstantRandomVariable> pause_rv =
        CreateObject<ConstantRandomVariable>();
    pause_rv->SetAttribute("Constant",
        DoubleValue(0.0));

    mobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed",  PointerValue(speed_rv),
        "Pause",  PointerValue(pause_rv),
        "PositionAllocator",
            PointerValue(pos));

    mobility.Install(m_topo.jammer_node);

    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerMobilityManager: RandomWaypoint installed"
        " speed=[" << min_speed << ","
        << max_speed << "] m/s");
}

// ===========================================================================
// Position helpers
// ===========================================================================
Vector JammerMobilityManager::GetJammerVec() const {
    if (m_topo.jammer_node.GetN() == 0)
        return Vector(0,0,0);
    Ptr<MobilityModel> mob =
        m_topo.jammer_node.Get(0)
              ->GetObject<MobilityModel>();
    if (!mob) return Vector(750, 750, JAMMER_ALT_M);
    return mob->GetPosition();
}

Vector JammerMobilityManager::GetUavVec(
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

JammerPosition JammerMobilityManager::GetPosition()
    const
{
    Vector v = GetJammerVec();
    JammerPosition jp;
    jp.x      = v.x;
    jp.y      = v.y;
    jp.z      = v.z;
    jp.time_s = Simulator::Now().GetSeconds();
    jp.speed  = JAMMER_SPEED_MPS;
    return jp;
}

double JammerMobilityManager::GetDistanceToUav(
    utils::u32 uav_index) const
{
    Vector jv = GetJammerVec();
    Vector uv = GetUavVec(uav_index);
    double dx = jv.x - uv.x;
    double dy = jv.y - uv.y;
    double dz = jv.z - uv.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

// ===========================================================================
// Friis path loss (dB) at 5 GHz
// ===========================================================================
double JammerMobilityManager::FriisLossDb(
    double dist_m) const
{
    if (dist_m < 1.0) dist_m = 1.0;
    constexpr double freq_hz = 5.18e9;
    constexpr double c       = 3e8;
    return 20.0 * std::log10(
        4.0 * M_PI * dist_m * freq_hz / c);
}

// ===========================================================================
// SINR impact
// ===========================================================================
double JammerMobilityManager::GetJammerInterference(
    utils::u32 uav_index) const
{
    double dist = GetDistanceToUav(uav_index);
    double loss = FriisLossDb(dist);
    return JAMMER_TX_DBM - loss;  // received power dBm
}

bool JammerMobilityManager::IsUavJammed(
    utils::u32 uav_index,
    double jamming_range_m) const
{
    return GetDistanceToUav(uav_index) <=
           jamming_range_m;
}

std::vector<utils::u32>
JammerMobilityManager::GetAffectedUavs(
    double jamming_range_m) const
{
    std::vector<utils::u32> affected;
    for (utils::u32 i = 0;
         i < m_topo.uav_nodes.GetN(); ++i)
    {
        if (IsUavJammed(i, jamming_range_m))
            affected.push_back(i);
    }
    return affected;
}

// ===========================================================================
// Print status
// ===========================================================================
void JammerMobilityManager::PrintStatus() const {
    auto jp = GetPosition();
    std::cout << "\n=== Jammer Status ===\n";
    std::cout << "  Position: ("
        << std::fixed << std::setprecision(1)
        << jp.x << "," << jp.y << ","
        << jp.z << ")\n";
    std::cout << "  Speed:    "
        << jp.speed << " m/s\n";
    std::cout << "  Tx power: "
        << JAMMER_TX_DBM << " dBm\n";

    auto affected = GetAffectedUavs(300.0);
    std::cout << "  Affected UAVs (300m): "
        << affected.size() << "\n";

    for (utils::u32 i = 0;
         i < m_topo.uav_nodes.GetN(); ++i)
    {
        double dist = GetDistanceToUav(i);
        double interference =
            GetJammerInterference(i);
        std::cout << "  UAV " << i
            << ": dist=" << std::setprecision(1)
            << dist << "m"
            << " int=" << std::setprecision(1)
            << interference << "dBm\n";
    }
}

} // namespace mobility
} // namespace uav
