/**
 * routing/uav-topology.cc
 */

#include "uav-topology.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/yans-wifi-helper.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/ssid.h"
#include "ns3/olsr-helper.h"
#include "ns3/ipv4-list-routing-helper.h"

NS_LOG_COMPONENT_DEFINE("UavTopology");

using namespace uav::utils::constants;

namespace uav {
namespace routing {

// ===========================================================================
// TopologyResult helpers
// ===========================================================================
ns3::Ipv4Address TopologyResult::GetUavWifiAddr(
    utils::u32 uav_index) const
{
    // UAV WiFi interfaces start at index 0 of wifi_interfaces
    return wifi_interfaces.GetAddress(uav_index);
}

ns3::Ipv4Address TopologyResult::GetSkdcCsmaAddr(
    utils::u32 cluster) const
{
    // CSMA: [0]=KDC, [1]=SKDC0, [2]=SKDC1, [3]=SKDC2
    return csma_interfaces.GetAddress(cluster + 1);
}

// ===========================================================================
// TopologyBuilder constructor
// ===========================================================================
TopologyBuilder::TopologyBuilder(const TopologyConfig& cfg)
    : m_cfg(cfg)
{}

// ===========================================================================
// Build — orchestrate all steps
// ===========================================================================
TopologyResult TopologyBuilder::Build() {
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: "
        << m_cfg.total_uavs << " UAVs, "
        << m_cfg.num_clusters << " clusters");

    TopologyResult topo;

    CreateNodes(topo);
    ConfigureCsmaBackbone(topo);
    ConfigureWifiAdhoc(topo);
    InstallInternetStack(topo);
    AssignAddresses(topo);
    ConfigureInitialPositions(topo);

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: complete. "
        << "Total nodes: " << topo.all_nodes.GetN());

    return topo;
}

// ===========================================================================
// Step 1: Create all nodes
// ===========================================================================
void TopologyBuilder::CreateNodes(TopologyResult& topo) {
    // Ground nodes: KDC(1) + SKDCs(3) = 4
    topo.ground_nodes.Create(4);

    // UAV nodes: 18
    topo.uav_nodes.Create(m_cfg.total_uavs);

    // Jammer: 1
    topo.jammer_node.Create(1);

    // KDC = ground_nodes[0]
    topo.kdc_node.Add(topo.ground_nodes.Get(0));

    // SKDCs = ground_nodes[1..3]
    for (utils::u32 i = 0; i < m_cfg.num_clusters; ++i) {
        topo.skdc_nodes.Add(topo.ground_nodes.Get(i + 1));
    }

    // Per-cluster UAV containers
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            utils::u32 idx = c * m_cfg.uavs_per_cluster + u;
            topo.cluster_nodes[c].Add(
                topo.uav_nodes.Get(idx));
        }
    }

    // WiFi nodes = UAVs + jammer
    topo.wifi_nodes.Add(topo.uav_nodes);
    topo.wifi_nodes.Add(topo.jammer_node);

    // All nodes = ground + UAVs + jammer
    topo.all_nodes.Add(topo.ground_nodes);
    topo.all_nodes.Add(topo.uav_nodes);
    topo.all_nodes.Add(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Created "
        << topo.all_nodes.GetN() << " nodes");
}

// ===========================================================================
// Step 2: CSMA backbone (KDC + SKDCs)
// ===========================================================================
void TopologyBuilder::ConfigureCsmaBackbone(
    TopologyResult& topo)
{
    ns3::CsmaHelper csma;
    csma.SetChannelAttribute("DataRate",
        ns3::StringValue(m_cfg.csma_data_rate));
    csma.SetChannelAttribute("Delay",
        ns3::StringValue(m_cfg.csma_delay));

    // Queue on CSMA devices
    csma.SetDeviceAttribute("Mtu",
        ns3::UintegerValue(1500));

    topo.csma_devices = csma.Install(topo.ground_nodes);

    NS_LOG_INFO("TopologyBuilder: CSMA backbone installed "
        << m_cfg.csma_data_rate);
}

// ===========================================================================
// Step 3: WiFi adhoc (UAVs + jammer)
// ===========================================================================
void TopologyBuilder::ConfigureWifiAdhoc(
    TopologyResult& topo)
{
    // PHY layer
    ns3::YansWifiChannelHelper channel =
        ns3::YansWifiChannelHelper::Default();

    // Friis + Nakagami propagation
    channel.AddPropagationLoss(
        "ns3::FriisPropagationLossModel");
    channel.AddPropagationLoss(
        "ns3::NakagamiPropagationLossModel",
        "m0", ns3::DoubleValue(m_cfg.nakagami_m0),
        "m1", ns3::DoubleValue(m_cfg.nakagami_m1),
        "m2", ns3::DoubleValue(m_cfg.nakagami_m2));

    ns3::YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    // 5 GHz band, channel 36
    phy.Set("ChannelSettings",
        ns3::StringValue("{36, 20, BAND_5GHZ, 0}"));

    // Tx power 20 dBm
    phy.Set("TxPowerStart",
        ns3::DoubleValue(m_cfg.tx_power_dbm));
    phy.Set("TxPowerEnd",
        ns3::DoubleValue(m_cfg.tx_power_dbm));

    // MAC: adhoc
    ns3::WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    // WiFi standard: 802.11a
    ns3::WifiHelper wifi;
    wifi.SetStandard(ns3::WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode",
        ns3::StringValue(m_cfg.data_rate),
        "ControlMode",
        ns3::StringValue(m_cfg.control_rate));

    topo.wifi_devices = wifi.Install(phy, mac, topo.wifi_nodes);

    NS_LOG_INFO("TopologyBuilder: WiFi adhoc installed "
        << "802.11a " << m_cfg.data_rate);
}

// ===========================================================================
// Step 4: Internet stack + OLSR routing
// ===========================================================================
void TopologyBuilder::InstallInternetStack(
    TopologyResult& topo)
{
    // OLSR for WiFi nodes (UAVs + jammer)
    ns3::OlsrHelper olsr;
    olsr.Set("HelloInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_HELLO_INTERVAL)));
    olsr.Set("TcInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_TC_INTERVAL)));

    ns3::Ipv4ListRoutingHelper list_routing;
    list_routing.Add(olsr, 10);

    ns3::InternetStackHelper internet_wifi;
    internet_wifi.SetRoutingHelper(list_routing);
    internet_wifi.Install(topo.wifi_nodes);

    // Static routing for ground nodes (CSMA)
    ns3::InternetStackHelper internet_ground;
    internet_ground.Install(topo.ground_nodes);

    NS_LOG_INFO("TopologyBuilder: Internet stack + OLSR installed");
}

// ===========================================================================
// Step 5: Assign IP addresses
// ===========================================================================
void TopologyBuilder::AssignAddresses(TopologyResult& topo) {
    ns3::Ipv4AddressHelper addr;

    // WiFi: 10.1.1.0/24
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.wifi_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.wifi_mask.c_str()));
    topo.wifi_interfaces = addr.Assign(topo.wifi_devices);

    // CSMA: 192.168.0.0/24
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.csma_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.csma_mask.c_str()));
    topo.csma_interfaces = addr.Assign(topo.csma_devices);

    NS_LOG_INFO("TopologyBuilder: Addresses assigned. "
        << "WiFi: " << m_cfg.wifi_base_addr
        << " CSMA: " << m_cfg.csma_base_addr);
}

// ===========================================================================
// Step 6: Initial node positions
// ===========================================================================
void TopologyBuilder::ConfigureInitialPositions(
    TopologyResult& topo)
{
    // Ground nodes: fixed positions along x-axis at z=0
    ns3::MobilityHelper ground_mobility;
    ground_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");

    ns3::Ptr<ns3::ListPositionAllocator> ground_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    // KDC at center
    ground_pos->Add(ns3::Vector(750.0, 750.0, 0.0));
    // SKDC0 at left
    ground_pos->Add(ns3::Vector(250.0, 750.0, 0.0));
    // SKDC1 at center
    ground_pos->Add(ns3::Vector(750.0, 250.0, 0.0));
    // SKDC2 at right
    ground_pos->Add(ns3::Vector(1250.0, 750.0, 0.0));

    ground_mobility.SetPositionAllocator(ground_pos);
    ground_mobility.Install(topo.ground_nodes);

    // UAV initial positions — clustered around their SKDC
    // Cluster 0: around SKDC0 (250, 750)
    // Cluster 1: around SKDC1 (750, 250)
    // Cluster 2: around SKDC2 (1250, 750)
    double cluster_centers[3][2] = {
        {250.0,  750.0},
        {750.0,  250.0},
        {1250.0, 750.0}
    };

    ns3::MobilityHelper uav_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> uav_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    double altitude_base = 100.0;  // 100m base altitude
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        double cx = cluster_centers[c][0];
        double cy = cluster_centers[c][1];
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            // Spread UAVs in formation around cluster center
            double angle  = (2.0 * M_PI * u) /
                             m_cfg.uavs_per_cluster;
            double radius = 100.0;  // 100m formation radius
            double x = cx + radius * std::cos(angle);
            double y = cy + radius * std::sin(angle);
            double z = altitude_base +
                       10.0 * static_cast<double>(u);
            uav_pos->Add(ns3::Vector(x, y, z));
        }
    }

    // Positions only — GaussMarkov installed by MobilityManager
    // Installing ConstantPosition here would prevent GaussMarkov
    // from being aggregated to these nodes later
    uav_mobility.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(0.0,1500.0,0.0,1500.0,50.0,150.0)),
        "TimeStep", TimeValue(Seconds(0.5)),
        "Alpha", DoubleValue(0.3),
        "MeanVelocity", StringValue(
            "ns3::ConstantRandomVariable[Constant=20.0]"),
        "MeanDirection", StringValue(
            "ns3::UniformRandomVariable[Min=0|Max=6.283]"),
        "MeanPitch", StringValue(
            "ns3::ConstantRandomVariable[Constant=0.0]"),
        "NormalVelocity", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=8.0]"),
        "NormalDirection", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.3]"),
        "NormalPitch", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.02]"));
    uav_mobility.SetPositionAllocator(uav_pos);
    uav_mobility.Install(topo.uav_nodes);

    // Jammer initial position at center
    ns3::MobilityHelper jammer_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> jammer_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();
    jammer_pos->Add(ns3::Vector(750.0, 750.0, 50.0));
    jammer_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");
    jammer_mobility.SetPositionAllocator(jammer_pos);
    jammer_mobility.Install(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Initial positions configured");
}

// ===========================================================================
// Enable PCAP tracing
// ===========================================================================
void TopologyBuilder::EnablePcap(
    const std::string& prefix,
    const TopologyResult& topo)
{
    ns3::YansWifiPhyHelper phy;
    phy.EnablePcapAll(prefix + "-wifi");

    ns3::CsmaHelper csma;
    csma.EnablePcapAll(prefix + "-csma");

    NS_LOG_INFO("TopologyBuilder: PCAP enabled: " << prefix);
}

} // namespace routing
} // namespace uav
