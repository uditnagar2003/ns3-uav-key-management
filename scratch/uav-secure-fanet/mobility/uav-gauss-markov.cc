/**
 * mobility/uav-gauss-markov.cc
 * Module 31 - GaussMarkov per-UAV speed configuration
 */

#include "uav-gauss-markov.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/mobility-model.h"

#include <cmath>
#include <iostream>
#include <random>

NS_LOG_COMPONENT_DEFINE("UavGaussMarkov");

using namespace ns3;

namespace uav {
namespace mobility {

static const double CENTERS[3][2] = {
    {250.0,  750.0},
    {750.0,  250.0},
    {1250.0, 750.0}
};

GaussMarkovManager::GaussMarkovManager(
    const routing::TopologyResult& topo,
    const GaussMarkovConfig& cfg)
    : m_topo(topo)
    , m_cfg(cfg)
{
    m_uav_speeds.resize(
        topo.uav_nodes.GetN(), cfg.mean_velocity);

    UAV_LOG_INFO(uav::log::channels::MOBILITY,
        "GaussMarkovManager: initialized "
        << topo.uav_nodes.GetN() << " UAVs"
        << " alpha=" << cfg.alpha
        << " mean_v=" << cfg.mean_velocity);
}

void GaussMarkovManager::RandomizeUavSpeeds(
    double min_mps,
    double max_mps,
    utils::u32 seed)
{
    std::mt19937 rng(seed);
    std::uniform_real_distribution<double>
        dist(min_mps, max_mps);

    for (utils::u32 i = 0;
         i < m_topo.uav_nodes.GetN(); ++i)
    {
        m_uav_speeds[i] = dist(rng);

        Ptr<Node> node = m_topo.uav_nodes.Get(i);
        Ptr<GaussMarkovMobilityModel> gmm =
            node->GetObject<GaussMarkovMobilityModel>();
        if (gmm) {
            gmm->SetAttribute("MeanVelocity",
                StringValue(
                    "ns3::ConstantRandomVariable[Constant="
                    + std::to_string(m_uav_speeds[i])
                    + "]"));
        }
    }

    UAV_LOG_INFO(uav::log::channels::MOBILITY,
        "GaussMarkovManager: speeds randomized ["
        << min_mps << "," << max_mps
        << "] m/s seed=" << seed);
}

double GaussMarkovManager::GetUavSpeed(
    utils::u32 uav_index) const
{
    if (uav_index < m_uav_speeds.size())
        return m_uav_speeds[uav_index];
    return 0.0;
}

bool GaussMarkovManager::IsWithinCohesion(
    utils::u32 uav_index,
    utils::u32 cluster) const
{
    if (uav_index >= m_topo.uav_nodes.GetN())
        return false;
    Ptr<Node> node = m_topo.uav_nodes.Get(uav_index);
    Ptr<MobilityModel> mob =
        node->GetObject<MobilityModel>();
    if (!mob) return true;
    Vector pos = mob->GetPosition();
    double dx = pos.x - CENTERS[cluster][0];
    double dy = pos.y - CENTERS[cluster][1];
    return std::sqrt(dx*dx + dy*dy) <= m_cfg.cohesion_radius;
}

void GaussMarkovManager::PrintSpeedSummary() const {
    std::cout << "\n=== UAV Speed Configuration ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        std::cout << "  Cluster " << c << ":\n";
        for (utils::u32 u = 0; u < 6; ++u) {
            utils::u32 idx = c * 6 + u;
            std::cout << "    UAV " << idx
                << ": " << m_uav_speeds[idx]
                << " m/s\n";
        }
    }
}

} // namespace mobility
} // namespace uav
