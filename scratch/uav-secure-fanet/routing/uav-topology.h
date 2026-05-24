/**
 * routing/uav-topology.h  [PATCHED — dual-interface SKDC]
 *
 * CHANGE SUMMARY (incremental correction only):
 *   1. TopologyResult: added skdc_wifi_devices + skdc_wifi_interfaces
 *   2. TopologyResult: added GetSkdcWifiAddr()
 *   3. wifi_nodes now includes SKDCs (for shared WiFi channel)
 *   4. All existing APIs preserved exactly.
 *
 * NODE ID MAPPING (unchanged):
 *   KDC    = 0
 *   SKDC_i = 1 + i          (i = 0,1,2)
 *   UAV_j  = 4 + j          (j = 0..17)
 *   JAMMER = 22
 *
 * INTERFACE LAYOUT AFTER PATCH:
 *   wifi_interfaces[0..2]   = SKDC0, SKDC1, SKDC2  (10.1.1.1–3)
 *   wifi_interfaces[3..20]  = UAV0..UAV17           (10.1.1.4–21)
 *   wifi_interfaces[21]     = Jammer                (10.1.1.22)
 *   csma_interfaces[0..3]   = KDC, SKDC0,1,2       (192.168.0.x)
 *
 * WIRELESS:
 *   Standard  : 802.11a
 *   Band      : 5 GHz
 *   Channel   : 36 (20 MHz)
 *   Data rate : OfdmRate24Mbps
 *   Tx power  : 20 dBm (UAV/SKDC), 30 dBm (jammer)
 *
 * CSMA:
 *   100 Mbps backbone between KDC and SKDCs
 */

#ifndef UAV_TOPOLOGY_H
#define UAV_TOPOLOGY_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-static-routing-helper.h"

#include "uav-types.h"
#include "uav-constants.h"
#include "uav-error.h"

#include <string>
#include <vector>
#include <array>

namespace uav {
namespace routing {

// ===========================================================================
// TopologyConfig — simulation-wide parameters (unchanged)
// ===========================================================================
struct TopologyConfig {
    // Network
    utils::u32  num_clusters         = 3;
    utils::u32  uavs_per_cluster     = 6;
    utils::u32  total_uavs           = 18;

    // WiFi
    std::string wifi_standard        = "80211a";
    double      tx_power_dbm         = 20.0;
    std::string data_rate            = "OfdmRate24Mbps";
    std::string control_rate         = "OfdmRate6Mbps";
    utils::u32  channel_number       = 36;       // 5 GHz
    utils::u32  queue_max_packets    = 100;

    // CSMA backbone
    std::string csma_data_rate       = "100Mbps";
    std::string csma_delay           = "1ms";

    // Propagation
    double      nakagami_m0          = 1.0;
    double      nakagami_m1          = 1.0;
    double      nakagami_m2          = 1.0;

    // Addressing
    std::string wifi_base_addr       = "10.1.1.0";
    std::string wifi_mask            = "255.255.255.0";
    std::string csma_base_addr       = "192.168.0.0";
    std::string csma_mask            = "255.255.255.0";

    // Simulation area
    double      area_x               = 1500.0;
    double      area_y               = 1500.0;
    double      area_z               = 200.0;
};

// ===========================================================================
// TopologyResult — all node/device/interface references
// PATCH: skdc_wifi_devices + skdc_wifi_interfaces added
//        wifi_nodes now includes SKDCs
//        wifi_interfaces[0..2] = SKDC0/1/2
//        wifi_interfaces[3..20] = UAV0..17
//        wifi_interfaces[21] = Jammer
// ===========================================================================
struct TopologyResult {
    // Node containers (UNCHANGED)
    ns3::NodeContainer  all_nodes;
    ns3::NodeContainer  ground_nodes;   // KDC + SKDCs
    ns3::NodeContainer  kdc_node;
    ns3::NodeContainer  skdc_nodes;     // 3 SKDCs
    ns3::NodeContainer  uav_nodes;      // 18 UAVs
    ns3::NodeContainer  jammer_node;

    // PATCH: wifi_nodes now = SKDCs + UAVs + jammer (22 total)
    // was: UAVs + jammer (19 total)
    ns3::NodeContainer  wifi_nodes;     // SKDCs + UAVs + jammer

    // Per-cluster UAV containers (UNCHANGED)
    std::array<ns3::NodeContainer, 3> cluster_nodes;

    // Device containers
    ns3::NetDeviceContainer  csma_devices;    // 4 devices (KDC+3SKDCs)
    ns3::NetDeviceContainer  wifi_devices;    // 22 devices (3SKDCs+18UAVs+jammer)

    // Interface containers
    ns3::Ipv4InterfaceContainer  csma_interfaces;  // 4 interfaces
    ns3::Ipv4InterfaceContainer  wifi_interfaces;  // 22 interfaces

    // Node ID helpers (UNCHANGED)
    static constexpr utils::u32 KDC_NODE_ID    = 0;
    static constexpr utils::u32 SKDC0_NODE_ID  = 1;
    static constexpr utils::u32 SKDC1_NODE_ID  = 2;
    static constexpr utils::u32 SKDC2_NODE_ID  = 3;
    static constexpr utils::u32 UAV0_NODE_ID   = 4;
    static constexpr utils::u32 JAMMER_NODE_ID = 22;

    // WiFi interface layout offsets
    // PATCH: SKDCs now occupy slots 0..2 in wifi_interfaces
    static constexpr utils::u32 WIFI_SKDC_BASE = 0;  // SKDC0=0, SKDC1=1, SKDC2=2
    static constexpr utils::u32 WIFI_UAV_BASE  = 3;  // UAV0=3, UAV1=4, ... UAV17=20
    static constexpr utils::u32 WIFI_JAMMER    = 21; // Jammer=21

    // Get NS-3 node ID for UAV index (0-17) — UNCHANGED
    static utils::u32 UavNodeId(utils::u32 uav_index) {
        return UAV0_NODE_ID + uav_index;
    }

    // Get NS-3 node ID for SKDC (cluster 0-2) — UNCHANGED
    static utils::u32 SkdcNodeId(utils::u32 cluster) {
        return SKDC0_NODE_ID + cluster;
    }

    // Get NS-3 node for UAV — UNCHANGED
    ns3::Ptr<ns3::Node> GetUavNode(utils::u32 uav_index) const {
        return uav_nodes.Get(uav_index);
    }

    // Get NS-3 node for SKDC — UNCHANGED
    ns3::Ptr<ns3::Node> GetSkdcNode(utils::u32 cluster) const {
        return skdc_nodes.Get(cluster);
    }

    // Get NS-3 node for KDC — UNCHANGED
    ns3::Ptr<ns3::Node> GetKdcNode() const {
        return kdc_node.Get(0);
    }

    // PATCH: UAV WiFi index is now WIFI_UAV_BASE + uav_index
    // was: wifi_interfaces.GetAddress(uav_index)
    ns3::Ipv4Address GetUavWifiAddr(utils::u32 uav_index) const {
        return wifi_interfaces.GetAddress(WIFI_UAV_BASE + uav_index);
    }

    // PATCH: NEW — get WiFi IP for SKDC (cluster 0-2)
    ns3::Ipv4Address GetSkdcWifiAddr(utils::u32 cluster) const {
        return wifi_interfaces.GetAddress(WIFI_SKDC_BASE + cluster);
    }

    // Get CSMA IP for SKDC — UNCHANGED
    ns3::Ipv4Address GetSkdcCsmaAddr(utils::u32 cluster) const;

    // Get CSMA IP for KDC
    ns3::Ipv4Address GetKdcCsmaAddr() const;
};

// ===========================================================================
// TopologyBuilder — builds complete simulation topology
// ===========================================================================
class TopologyBuilder {
public:
    explicit TopologyBuilder(const TopologyConfig& cfg = TopologyConfig{});

    /// Build complete topology.
    /// Returns TopologyResult with all node/device/interface refs.
    TopologyResult Build();

    /// Enable PCAP tracing on all devices
    void EnablePcap(const std::string& prefix,
                    const TopologyResult& topo);

    const TopologyConfig& GetConfig() const { return m_cfg; }

private:
    TopologyConfig m_cfg;

    // Build steps (UNCHANGED signatures)
    void CreateNodes(TopologyResult& topo);
    void ConfigureCsmaBackbone(TopologyResult& topo);
    void ConfigureWifiAdhoc(TopologyResult& topo);  // PATCH: now includes SKDCs
    void InstallInternetStack(TopologyResult& topo); // PATCH: OLSR on SKDCs too
    void AssignAddresses(TopologyResult& topo);
    void ConfigureInitialPositions(TopologyResult& topo);
    void ConfigureOlsr(TopologyResult& topo);
};

} // namespace routing
} // namespace uav

#endif // UAV_TOPOLOGY_H