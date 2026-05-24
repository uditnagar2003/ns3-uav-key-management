/**
 * apps/uav-jammer-manager.cc
 * Module 43 - Jammer Detection and SINR Degradation
 */

#include "apps/uav-jammer-manager.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <cmath>
#include <iostream>
#include <iomanip>
#include <random>

NS_LOG_COMPONENT_DEFINE("UavJammerManager");

using namespace ns3;

namespace uav {
namespace apps {

JammerManager::JammerManager(
    const routing::TopologyResult*       topo,
    mobility::JammerMobilityManager*     jammer_mob)
    : m_topo(topo)
    , m_jammer_mob(jammer_mob)
{
    // Initialize compromised UAVs (5% probability)
    std::mt19937 rng(42);
    std::uniform_real_distribution<double>
        dist(0.0, 1.0);

    for (utils::u32 i = 0;
         i < topo->uav_nodes.GetN(); ++i)
    {
        if (dist(rng) < COMPROMISE_PROB) {
            m_compromised.push_back(i);
        }
    }

    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerManager: initialized"
        << " compromised=" << m_compromised.size()
        << " threshold=" << SINR_THRESHOLD_DB << "dB");
}

// ===========================================================================
// Friis path loss (dB) at 5 GHz
// ===========================================================================
double JammerManager::FriisPathLoss(
    double dist_m) const
{
    if (dist_m < 1.0) dist_m = 1.0;
    constexpr double freq_hz = 5.18e9;
    constexpr double c = 3e8;
    return 20.0 * std::log10(
        4.0 * M_PI * dist_m * freq_hz / c);
}

// ===========================================================================
// SINR computation
// SINR = Signal - Noise - Interference (all in dB)
// ===========================================================================
double JammerManager::ComputeSinr(
    utils::u32 uav_index) const
{
    return 20.0;  // jammer disabled — always good SINR
    if (!m_jammer_mob) return 100.0;

    double jammer_dist =
        m_jammer_mob->GetDistanceToUav(uav_index);

    // Jammer interference at UAV
    double jammer_rx_dbm =
        m_jammer_mob->GetJammerInterference(
            uav_index);

    // Signal power (approximate)
    // Assume nearby SKDC at ~300m avg distance
    double signal_loss = FriisPathLoss(300.0);
    double signal_rx_dbm = SIGNAL_TX_DBM - signal_loss;

    // Noise + Interference
    double noise_and_int = 10.0 * std::log10(
        std::pow(10.0, NOISE_FLOOR_DBM / 10.0) +
        std::pow(10.0, jammer_rx_dbm / 10.0));

    double sinr = signal_rx_dbm - noise_and_int;

    (void)jammer_dist;
    return sinr;
}

bool JammerManager::IsJammed(
    utils::u32 uav_index) const
{
    return ComputeSinr(uav_index) < SINR_THRESHOLD_DB;
}

std::vector<utils::u32>
JammerManager::GetJammedUavs() const
{
    std::vector<utils::u32> jammed;
    for (utils::u32 i = 0;
         i < m_topo->uav_nodes.GetN(); ++i)
    {
        if (IsJammed(i)) jammed.push_back(i);
    }
    return jammed;
}

double JammerManager::GetJammerImpact(
    utils::u32 uav_index) const
{
    double sinr = ComputeSinr(uav_index);
    if (sinr >= SINR_THRESHOLD_DB) return 0.0;

    // Impact: 0.0 (threshold) to 1.0 (severe)
    double impact = (SINR_THRESHOLD_DB - sinr) / 20.0;
    return std::min(1.0, std::max(0.0, impact));
}

// ===========================================================================
// Packet drop probability
// Higher impact = higher drop probability
// ===========================================================================
double JammerManager::GetDropProbability(
    utils::u32 uav_index) const
{
    double impact = GetJammerImpact(uav_index);
    // At full impact: 80% drop probability
    return impact * 0.8;
}

bool JammerManager::ShouldDrop(
    utils::u32 uav_index,
    utils::u32 seed) const
{
    return false;  // jammer disabled
    double drop_prob =
        GetDropProbability(uav_index);
    if (drop_prob <= 0.0) return false;

    std::mt19937 rng(seed + uav_index +
        static_cast<utils::u32>(
            Simulator::Now().GetNanoSeconds()));
    std::uniform_real_distribution<double>
        dist(0.0, 1.0);

    bool drop = (dist(rng) < drop_prob);
    if (drop) ++m_packet_drops;
    return drop;
}

// ===========================================================================
// Node compromise
// ===========================================================================
bool JammerManager::IsCompromised(
    utils::u32 uav_index) const
{
    for (auto c : m_compromised)
        if (c == uav_index) return true;
    return false;
}

std::vector<utils::u32>
JammerManager::GetCompromisedUavs() const
{
    return m_compromised;
}

// ===========================================================================
// Scan
// ===========================================================================
JammerEvent JammerManager::Scan() const {
    JammerEvent ev;
    ev.time_s = Simulator::Now().GetSeconds();

    auto jp = m_jammer_mob->GetPosition();
    ev.jammer_x = jp.x;
    ev.jammer_y = jp.y;

    auto jammed = GetJammedUavs();
    ev.affected_uavs =
        static_cast<utils::u32>(jammed.size());

    double min_sinr = 1000.0;
    for (utils::u32 i = 0;
         i < m_topo->uav_nodes.GetN(); ++i)
    {
        double sinr = ComputeSinr(i);
        if (sinr < min_sinr) min_sinr = sinr;
    }
    ev.min_sinr_db = min_sinr;
    ev.threshold_hit =
        (min_sinr < SINR_THRESHOLD_DB);

    if (ev.affected_uavs > 0) {
        ++m_jammer_events;
        if (m_alert_cb) m_alert_cb(ev);
    }

    return ev;
}

void JammerManager::StartPeriodicScan(
    double interval_s)
{
    Simulator::Schedule(
        Seconds(interval_s),
        &JammerManager::PeriodicScanCallback,
        this);
}

void JammerManager::PeriodicScanCallback() {
    auto ev = Scan();
    UAV_LOG_INFO(uav::log::channels::JAMMER,
        "JammerManager: scan t="
        << ev.time_s
        << " affected=" << ev.affected_uavs
        << " min_sinr=" << ev.min_sinr_db
        << "dB");
}

// ===========================================================================
// Print status
// ===========================================================================
void JammerManager::PrintJammerStatus() const {
    std::cout << "\n=== Jammer Status ===\n";

    auto jp = m_jammer_mob->GetPosition();
    std::cout << "  Jammer pos: ("
        << std::fixed << std::setprecision(1)
        << jp.x << "," << jp.y << ")\n";
    std::cout << "  SINR threshold: "
        << SINR_THRESHOLD_DB << " dB\n";

    auto jammed = GetJammedUavs();
    std::cout << "  Jammed UAVs: "
        << jammed.size() << "\n";

    std::cout << "  Compromised UAVs: "
        << m_compromised.size() << " (";
    for (auto c : m_compromised)
        std::cout << c << " ";
    std::cout << ")\n";

    std::cout << "  Per-UAV SINR:\n";
    for (utils::u32 i = 0;
         i < m_topo->uav_nodes.GetN(); ++i)
    {
        double sinr = ComputeSinr(i);
        std::cout << "    UAV " << i
            << ": SINR=" << std::setprecision(1)
            << sinr << "dB"
            << (sinr < SINR_THRESHOLD_DB
                ? " [JAMMED]" : "")
            << (IsCompromised(i)
                ? " [COMPROMISED]" : "")
            << "\n";
    }
}

} // namespace apps
} // namespace uav
