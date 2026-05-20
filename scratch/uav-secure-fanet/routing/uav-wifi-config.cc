/**
 * routing/uav-wifi-config.cc
 */

#include "uav-wifi-config.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/wifi-net-device.h"
#include "ns3/yans-wifi-phy.h"
#include "ns3/mobility-model.h"

#include <cmath>
#include <sstream>
#include <iostream>

NS_LOG_COMPONENT_DEFINE("UavWifiConfig");

using namespace ns3;

namespace uav {
namespace routing {

// ===========================================================================
// Constructor
// ===========================================================================
WifiConfigManager::WifiConfigManager(
    const TopologyResult& topo)
    : m_topo(topo)
{
    // Initialize stats for all UAV nodes
    for (utils::u32 i = 0; i < topo.uav_nodes.GetN(); ++i) {
        utils::u32 nid = topo.uav_nodes.Get(i)->GetId();
        WifiNodeStats s;
        s.node_id      = nid;
        s.tx_power_dbm = UAV_TX_POWER_DBM;
        m_stats[nid]   = s;
    }

    // Jammer stats
    if (topo.jammer_node.GetN() > 0) {
        utils::u32 jid = topo.jammer_node.Get(0)->GetId();
        WifiNodeStats js;
        js.node_id      = jid;
        js.tx_power_dbm = JAMMER_TX_POWER_DBM;
        m_stats[jid]    = js;
    }
}

// ===========================================================================
// Tx power control
// ===========================================================================
void WifiConfigManager::SetNodeTxPower(
    Ptr<Node> node,
    double power_dbm)
{
    // Iterate over devices to find WifiNetDevice
    for (utils::u32 i = 0; i < node->GetNDevices(); ++i) {
        Ptr<WifiNetDevice> wifi_dev =
            DynamicCast<WifiNetDevice>(node->GetDevice(i));
        if (wifi_dev) {
            Ptr<WifiPhy> phy = wifi_dev->GetPhy();
            if (phy) {
                phy->SetTxPowerStart(power_dbm);
                phy->SetTxPowerEnd(power_dbm);
                NS_LOG_INFO("WifiConfigManager: Node "
                    << node->GetId()
                    << " Tx power set to "
                    << power_dbm << " dBm");
            }
            break;
        }
    }

    utils::u32 nid = node->GetId();
    if (m_stats.count(nid)) {
        m_stats[nid].tx_power_dbm = power_dbm;
    }
}

void WifiConfigManager::SetJammerTxPower() {
    if (m_topo.jammer_node.GetN() > 0) {
        SetNodeTxPower(m_topo.jammer_node.Get(0),
                       JAMMER_TX_POWER_DBM);
    }
}

void WifiConfigManager::SetAllUavTxPowers() {
    for (utils::u32 i = 0; i < m_topo.uav_nodes.GetN(); ++i) {
        SetNodeTxPower(m_topo.uav_nodes.Get(i),
                       UAV_TX_POWER_DBM);
    }
}

// ===========================================================================
// Distance computation
// ===========================================================================
double WifiConfigManager::GetDistance(
    Ptr<Node> a, Ptr<Node> b) const
{
    Ptr<MobilityModel> mob_a =
        a->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob_b =
        b->GetObject<MobilityModel>();

    if (!mob_a || !mob_b) return 9999.0;

    Vector pa = mob_a->GetPosition();
    Vector pb = mob_b->GetPosition();

    double dx = pa.x - pb.x;
    double dy = pa.y - pb.y;
    double dz = pa.z - pb.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

// ===========================================================================
// Friis path loss (dB)
// PL = 20*log10(4*pi*d*f/c)
// ===========================================================================
double WifiConfigManager::FriisPathLossDb(
    double dist_m, double freq_hz) const
{
    if (dist_m < 1.0) dist_m = 1.0;
    constexpr double c = 3e8;
    double pl = 20.0 * std::log10(
        4.0 * M_PI * dist_m * freq_hz / c);
    return pl;
}

// ===========================================================================
// Path loss between two nodes
// ===========================================================================
double WifiConfigManager::ComputePathLossDb(
    Ptr<Node> tx, Ptr<Node> rx) const
{
    double dist = GetDistance(tx, rx);
    return FriisPathLossDb(dist, GetFreqHz());
}

// ===========================================================================
// SINR estimation
// SINR = Tx_power - PathLoss - NoiseFloor - JammerInterference
// ===========================================================================
double WifiConfigManager::EstimateSinrDb(
    Ptr<Node> tx, Ptr<Node> rx) const
{
    double tx_power  = UAV_TX_POWER_DBM;
    double path_loss = ComputePathLossDb(tx, rx);
    double noise_floor = -95.0;  // dBm thermal noise @ 20MHz

    double rx_power = tx_power - path_loss;

    // Check jammer interference
    double jammer_interference = -200.0;  // negligible by default
    if (m_topo.jammer_node.GetN() > 0) {
        Ptr<Node> jammer = m_topo.jammer_node.Get(0);
        double jammer_dist    = GetDistance(jammer, rx);
        double jammer_loss    = FriisPathLossDb(
            jammer_dist, GetFreqHz());
        double jammer_rx_power =
            JAMMER_TX_POWER_DBM - jammer_loss;

        if (jammer_rx_power > noise_floor) {
            jammer_interference = jammer_rx_power;
        }
    }

    // Total interference = noise + jammer (log-sum)
    double interference;
    if (jammer_interference > -150.0) {
        // Convert to linear, add, convert back
        double n_lin = std::pow(10.0, noise_floor / 10.0);
        double j_lin = std::pow(10.0,
            jammer_interference / 10.0);
        interference = 10.0 * std::log10(n_lin + j_lin);
    } else {
        interference = noise_floor;
    }

    return rx_power - interference;
}

// ===========================================================================
// Link usability
// ===========================================================================
bool WifiConfigManager::IsLinkUsable(
    Ptr<Node> tx, Ptr<Node> rx) const
{
    double sinr = EstimateSinrDb(tx, rx);
    return sinr >= SINR_FAIL_THRESHOLD_DB;
}

// ===========================================================================
// Jammer proximity check
// ===========================================================================
bool WifiConfigManager::IsJammerNearby(
    Ptr<Node> node, double range_m) const
{
    if (m_topo.jammer_node.GetN() == 0) return false;
    Ptr<Node> jammer = m_topo.jammer_node.Get(0);
    return GetDistance(jammer, node) <= range_m;
}

// ===========================================================================
// Stats
// ===========================================================================
WifiNodeStats WifiConfigManager::GetNodeStats(
    utils::u32 node_id) const
{
    auto it = m_stats.find(node_id);
    if (it != m_stats.end()) return it->second;
    return WifiNodeStats{};
}

void WifiConfigManager::UpdateNodeStats(
    utils::u32 node_id,
    const WifiNodeStats& stats)
{
    m_stats[node_id] = stats;
}

void WifiConfigManager::PrintAllStats() const {
    std::cout << "\n=== WiFi Node Statistics ===\n";
    for (const auto& [nid, s] : m_stats) {
        std::cout << "  Node " << nid
            << ": tx=" << s.tx_packets
            << " rx=" << s.rx_packets
            << " drop=" << s.dropped
            << " power=" << s.tx_power_dbm << "dBm"
            << " jammer=" << (s.jammer_nearby ? "YES" : "no")
            << "\n";
    }
}

// ===========================================================================
// Cluster connectivity
// ===========================================================================
std::vector<utils::u32>
WifiConfigManager::GetConnectedUavsInCluster(
    utils::u32 cluster) const
{
    std::vector<utils::u32> connected;
    if (cluster >= 3) return connected;

    Ptr<Node> skdc = m_topo.skdc_nodes.Get(cluster);

    // SKDCs are on CSMA — use cluster center UAV as proxy
    // Check which UAVs have usable links within cluster
    const auto& cn = m_topo.cluster_nodes[cluster];
    for (utils::u32 i = 0; i < cn.GetN(); ++i) {
        Ptr<Node> uav = cn.Get(i);
        // Check link to cluster leader (UAV 0 in cluster)
        if (i == 0) {
            connected.push_back(i);
            continue;
        }
        Ptr<Node> leader = cn.Get(0);
        if (IsLinkUsable(uav, leader)) {
            connected.push_back(i);
        }
    }
    return connected;
}

utils::u32 WifiConfigManager::GetJammedUavCount(
    utils::u32 cluster) const
{
    if (cluster >= 3) return 0;
    utils::u32 count = 0;
    const auto& cn = m_topo.cluster_nodes[cluster];
    for (utils::u32 i = 0; i < cn.GetN(); ++i) {
        if (IsJammerNearby(cn.Get(i))) ++count;
    }
    return count;
}

} // namespace routing
} // namespace uav
