/**
 * routing/uav-topology.h
 *
 * Network Topology Builder for UAV Secure FANET simulation.
 *
 * TOPOLOGY:
 *   Ground infrastructure (CSMA wired backbone):
 *     Node 0     : KDC
 *     Nodes 1-3  : SKDC[0], SKDC[1], SKDC[2]
 *
 *   UAV swarm (WiFi adhoc):
 *     Nodes 4-9  : Cluster 0 UAVs (UAV 0-5)
 *     Nodes 10-15: Cluster 1 UAVs (UAV 6-11)
 *     Nodes 16-21: Cluster 2 UAVs (UAV 12-17)
 *
 *   Jammer:
 *     Node 22    : Mobile jammer
 *
 *   Total: 23 nodes
 *
 * NODE ID MAPPING:
 *   KDC    = 0
 *   SKDC_i = 1 + i          (i = 0,1,2)
 *   UAV_j  = 4 + j          (j = 0..17)
 *   JAMMER = 22
 *
 * WIRELESS:
 *   802.11a, 5GHz, 26Mbps, AdhocWifiMac
 *   FriisPropagationLoss + NakagamiPropagationLoss
 *   20 dBm Tx power
 *
 * CSMA:
 *   100 Mbps backbone between KDC and SKDCs
 */

#ifndef UAV_TOPOLOGY_H
#define UAV_TOPOLOGY_H

// NS-3 headers
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
// TopologyConfig — simulation-wide parameters
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
// ===========================================================================
struct TopologyResult {
    // Node containers
    ns3::NodeContainer  all_nodes;
    ns3::NodeContainer  ground_nodes;   // KDC + SKDCs
    ns3::NodeContainer  kdc_node;
    ns3::NodeContainer  skdc_nodes;     // 3 SKDCs
    ns3::NodeContainer  uav_nodes;      // 18 UAVs
    ns3::NodeContainer  jammer_node;
    ns3::NodeContainer  wifi_nodes;     // UAVs + jammer

    // Per-cluster UAV containers
    std::array<ns3::NodeContainer, 3> cluster_nodes;

    // Device containers
    ns3::NetDeviceContainer  csma_devices;
    ns3::NetDeviceContainer  wifi_devices;

    // Interface containers
    ns3::Ipv4InterfaceContainer  csma_interfaces;
    ns3::Ipv4InterfaceContainer  wifi_interfaces;

    // Node ID helpers
    static constexpr utils::u32 KDC_NODE_ID    = 0;
    static constexpr utils::u32 SKDC0_NODE_ID  = 1;
    static constexpr utils::u32 SKDC1_NODE_ID  = 2;
    static constexpr utils::u32 SKDC2_NODE_ID  = 3;
    static constexpr utils::u32 UAV0_NODE_ID   = 4;
    static constexpr utils::u32 JAMMER_NODE_ID = 22;

    // Get NS-3 node ID for UAV index (0-17)
    static utils::u32 UavNodeId(utils::u32 uav_index) {
        return UAV0_NODE_ID + uav_index;
    }

    // Get NS-3 node ID for SKDC (cluster 0-2)
    static utils::u32 SkdcNodeId(utils::u32 cluster) {
        return SKDC0_NODE_ID + cluster;
    }

    // Get NS-3 node for UAV
    ns3::Ptr<ns3::Node> GetUavNode(utils::u32 uav_index) const {
        return uav_nodes.Get(uav_index);
    }

    // Get NS-3 node for SKDC
    ns3::Ptr<ns3::Node> GetSkdcNode(utils::u32 cluster) const {
        return skdc_nodes.Get(cluster);
    }

    // Get NS-3 node for KDC
    ns3::Ptr<ns3::Node> GetKdcNode() const {
        return kdc_node.Get(0);
    }

    // Get WiFi IP for UAV
    ns3::Ipv4Address GetUavWifiAddr(utils::u32 uav_index) const;

    // Get CSMA IP for SKDC
    ns3::Ipv4Address GetSkdcCsmaAddr(utils::u32 cluster) const;
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

    // Build steps
    void CreateNodes(TopologyResult& topo);
    void ConfigureCsmaBackbone(TopologyResult& topo);
    void ConfigureWifiAdhoc(TopologyResult& topo);
    void InstallInternetStack(TopologyResult& topo);
    void AssignAddresses(TopologyResult& topo);
    void ConfigureInitialPositions(TopologyResult& topo);
    void ConfigureOlsr(TopologyResult& topo);
};

} // namespace routing
} // namespace uav

#endif // UAV_TOPOLOGY_H
