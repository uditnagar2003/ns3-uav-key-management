/**
 * routing/uav-wifi-config.h
 *
 * WiFi Adhoc Configuration Manager
 *
 * Manages runtime WiFi parameters for the UAV swarm:
 *   - Per-node Tx power adjustment (jammer vs UAV)
 *   - SINR threshold enforcement
 *   - Channel configuration queries
 *   - Per-cluster WiFi statistics
 *   - Denied environment degradation
 *
 * WIFI SPEC (per project):
 *   Standard  : 802.11a
 *   Band      : 5 GHz
 *   Channel   : 36 (20 MHz)
 *   Data rate : OfdmRate24Mbps (26 Mbps PHY)
 *   Tx power  : 20 dBm (UAV), 30 dBm (jammer)
 *   SINR fail : 8 dB threshold
 *
 * Propagation:
 *   FriisPropagationLossModel
 *   NakagamiPropagationLossModel (m0=m1=m2=1.0)
 */

#ifndef UAV_WIFI_CONFIG_H
#define UAV_WIFI_CONFIG_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <string>
#include <vector>
#include <unordered_map>

namespace uav {
namespace routing {

// ===========================================================================
// WifiNodeStats — per-node WiFi statistics
// ===========================================================================
struct WifiNodeStats {
    utils::u32  node_id       = 0;
    utils::u64  tx_packets    = 0;
    utils::u64  rx_packets    = 0;
    utils::u64  dropped       = 0;
    double      avg_sinr_db   = 0.0;
    double      tx_power_dbm  = 20.0;
    bool        jammer_nearby = false;
};

// ===========================================================================
// WifiConfigManager
// ===========================================================================
class WifiConfigManager {
public:
    // SINR threshold below which link is considered failed
    static constexpr double SINR_FAIL_THRESHOLD_DB = 8.0;

    // UAV Tx power
    static constexpr double UAV_TX_POWER_DBM    = 20.0;

    // Jammer Tx power
    static constexpr double JAMMER_TX_POWER_DBM = 30.0;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit WifiConfigManager(const TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Tx power control
    // -----------------------------------------------------------------------

    /// Set Tx power for a specific node's WiFi device
    void SetNodeTxPower(ns3::Ptr<ns3::Node> node,
                        double power_dbm);

    /// Set jammer Tx power (30 dBm)
    void SetJammerTxPower();

    /// Set all UAV Tx powers (20 dBm)
    void SetAllUavTxPowers();

    // -----------------------------------------------------------------------
    // SINR / link quality
    // -----------------------------------------------------------------------

    /// Compute estimated path loss between two nodes (dB)
    double ComputePathLossDb(ns3::Ptr<ns3::Node> tx,
                              ns3::Ptr<ns3::Node> rx) const;

    /// Compute estimated SINR at rx from tx (dB)
    /// Accounts for jammer interference if nearby
    double EstimateSinrDb(ns3::Ptr<ns3::Node> tx,
                           ns3::Ptr<ns3::Node> rx) const;

    /// Check if link between tx and rx is usable (SINR > threshold)
    bool IsLinkUsable(ns3::Ptr<ns3::Node> tx,
                      ns3::Ptr<ns3::Node> rx) const;

    /// Check if jammer is within interference range of a node
    bool IsJammerNearby(ns3::Ptr<ns3::Node> node,
                        double range_m = 300.0) const;

    // -----------------------------------------------------------------------
    // Channel info
    // -----------------------------------------------------------------------
    static std::string GetDataRate()    { return "OfdmRate24Mbps"; }
    static std::string GetControlRate() { return "OfdmRate6Mbps";  }
    static utils::u32  GetChannel()     { return 36;               }
    static double      GetFreqHz()      { return 5.18e9;           }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------
    WifiNodeStats GetNodeStats(utils::u32 node_id) const;
    void UpdateNodeStats(utils::u32 node_id,
                         const WifiNodeStats& stats);
    void PrintAllStats() const;

    // -----------------------------------------------------------------------
    // Cluster connectivity check
    // -----------------------------------------------------------------------

    /// Returns list of UAV indices in cluster c that have
    /// usable link to their SKDC
    std::vector<utils::u32> GetConnectedUavsInCluster(
        utils::u32 cluster) const;

    /// Returns count of UAVs in cluster with jammer interference
    utils::u32 GetJammedUavCount(utils::u32 cluster) const;

private:
    const TopologyResult&                       m_topo;
    std::unordered_map<utils::u32, WifiNodeStats> m_stats;

    /// Get distance between two nodes in meters
    double GetDistance(ns3::Ptr<ns3::Node> a,
                       ns3::Ptr<ns3::Node> b) const;

    /// Friis path loss model (dB)
    double FriisPathLossDb(double dist_m,
                            double freq_hz) const;
};

} // namespace routing
} // namespace uav

#endif // UAV_WIFI_CONFIG_H
