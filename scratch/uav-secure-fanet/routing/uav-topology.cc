/**
 * routing/uav-topology.cc  [PATCHED — dual-interface SKDC]
 *
 * PATCH SUMMARY (incremental, minimal):
 *   CreateNodes:        wifi_nodes.Add(topo.skdc_nodes) before UAVs
 *   ConfigureWifiAdhoc: wifi.Install(topo.wifi_nodes) now includes SKDCs
 *   InstallInternetStack: OLSR installed on wifi_nodes (now includes SKDCs)
 *                         InternetStack NOT installed on skdc_nodes again
 *   AssignAddresses:    wifi address block covers 22 nodes (SKDCs+UAVs+jammer)
 *   GetSkdcCsmaAddr:    unchanged (CSMA index cluster+1)
 *   GetSkdcWifiAddr:    NEW — inline in header, implementation not needed
 *   GetUavWifiAddr:     unchanged call — uses WIFI_UAV_BASE offset in header
 *
 * INTERFACE LAYOUT PRODUCED:
 *   wifi_interfaces[0]  = SKDC0  10.1.1.1
 *   wifi_interfaces[1]  = SKDC1  10.1.1.2
 *   wifi_interfaces[2]  = SKDC2  10.1.1.3
 *   wifi_interfaces[3]  = UAV0   10.1.1.4
 *   ...
 *   wifi_interfaces[20] = UAV17  10.1.1.21
 *   wifi_interfaces[21] = Jammer 10.1.1.22
 *   csma_interfaces[0]  = KDC    192.168.0.1
 *   csma_interfaces[1]  = SKDC0  192.168.0.2
 *   csma_interfaces[2]  = SKDC1  192.168.0.3
 *   csma_interfaces[3]  = SKDC2  192.168.0.4
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

ns3::Ipv4Address TopologyResult::GetSkdcCsmaAddr(
    utils::u32 cluster) const
{
    // CSMA: [0]=KDC, [1]=SKDC0, [2]=SKDC1, [3]=SKDC2  (UNCHANGED)
    return csma_interfaces.GetAddress(cluster + 1);
}

ns3::Ipv4Address TopologyResult::GetKdcCsmaAddr() const
{
    return csma_interfaces.GetAddress(0);
}

// ===========================================================================
// TopologyBuilder constructor
// ===========================================================================
TopologyBuilder::TopologyBuilder(const TopologyConfig& cfg)
    : m_cfg(cfg)
{}

// ===========================================================================
// Build — orchestrate all steps (UNCHANGED)
// ===========================================================================
TopologyResult TopologyBuilder::Build() {
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: "
        << m_cfg.total_uavs << " UAVs, "
        << m_cfg.num_clusters << " clusters"
        << " [dual-interface SKDC]");

    TopologyResult topo;

    CreateNodes(topo);
    ConfigureCsmaBackbone(topo);
    ConfigureWifiAdhoc(topo);
    InstallInternetStack(topo);
    AssignAddresses(topo);
    ConfigureInitialPositions(topo);

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: complete. "
        << "Total: " << topo.all_nodes.GetN() << " nodes"
        << " WiFi: " << topo.wifi_nodes.GetN()
        << " (SKDCs+UAVs+jammer)");

    return topo;
}

// ===========================================================================
// Step 1: Create all nodes
// PATCH: wifi_nodes.Add(skdc_nodes) FIRST so SKDCs get
//        lower wifi_interfaces indices (0,1,2) before UAVs (3-20).
// ===========================================================================
void TopologyBuilder::CreateNodes(TopologyResult& topo) {
    // Ground nodes: KDC(1) + SKDCs(3) = 4  (UNCHANGED)
    topo.ground_nodes.Create(4);

    // UAV nodes: 18  (UNCHANGED)
    topo.uav_nodes.Create(m_cfg.total_uavs);

    // Jammer: 1  (UNCHANGED)
    topo.jammer_node.Create(1);

    // KDC = ground_nodes[0]  (UNCHANGED)
    topo.kdc_node.Add(topo.ground_nodes.Get(0));

    // SKDCs = ground_nodes[1..3]  (UNCHANGED)
    for (utils::u32 i = 0; i < m_cfg.num_clusters; ++i) {
        topo.skdc_nodes.Add(topo.ground_nodes.Get(i + 1));
    }

    // Per-cluster UAV containers  (UNCHANGED)
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            utils::u32 idx = c * m_cfg.uavs_per_cluster + u;
            topo.cluster_nodes[c].Add(topo.uav_nodes.Get(idx));
        }
    }

    // PATCH: wifi_nodes = SKDCs + UAVs + jammer  (was: UAVs + jammer)
    // Order matters — SKDCs get wifi_interfaces[0,1,2]
    //                 UAVs  get wifi_interfaces[3..20]
    //                 Jammer gets wifi_interfaces[21]
    topo.wifi_nodes.Add(topo.skdc_nodes);   // PATCH: SKDCs first
    topo.wifi_nodes.Add(topo.uav_nodes);
    topo.wifi_nodes.Add(topo.jammer_node);

    // All nodes = ground + UAVs + jammer  (UNCHANGED)
    topo.all_nodes.Add(topo.ground_nodes);
    topo.all_nodes.Add(topo.uav_nodes);
    topo.all_nodes.Add(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Created "
        << topo.all_nodes.GetN() << " nodes"
        << " wifi_nodes=" << topo.wifi_nodes.GetN()
        << " (3 SKDCs + 18 UAVs + 1 Jammer)");
}

// ===========================================================================
// Step 2: CSMA backbone (KDC + SKDCs)  (UNCHANGED)
// ===========================================================================
void TopologyBuilder::ConfigureCsmaBackbone(
    TopologyResult& topo)
{
    ns3::CsmaHelper csma;
    csma.SetChannelAttribute("DataRate",
        ns3::StringValue(m_cfg.csma_data_rate));
    csma.SetChannelAttribute("Delay",
        ns3::StringValue(m_cfg.csma_delay));
    csma.SetDeviceAttribute("Mtu",
        ns3::UintegerValue(1500));

    topo.csma_devices = csma.Install(topo.ground_nodes);

    NS_LOG_INFO("TopologyBuilder: CSMA backbone installed "
        << m_cfg.csma_data_rate);
}

// ===========================================================================
// Step 3: WiFi adhoc (SKDCs + UAVs + jammer)
// PATCH: wifi.Install(topo.wifi_nodes) now includes SKDCs automatically
//        because topo.wifi_nodes includes skdc_nodes (added in CreateNodes).
// ===========================================================================
void TopologyBuilder::ConfigureWifiAdhoc(
    TopologyResult& topo)
{
    // PHY layer  (UNCHANGED)
    ns3::YansWifiChannelHelper channel =
        ns3::YansWifiChannelHelper::Default();

    channel.AddPropagationLoss(
        "ns3::FriisPropagationLossModel");
    channel.AddPropagationLoss(
        "ns3::NakagamiPropagationLossModel",
        "m0", ns3::DoubleValue(m_cfg.nakagami_m0),
        "m1", ns3::DoubleValue(m_cfg.nakagami_m1),
        "m2", ns3::DoubleValue(m_cfg.nakagami_m2));

    ns3::YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    // 5 GHz band, channel 36  (UNCHANGED)
    phy.Set("ChannelSettings",
        ns3::StringValue("{36, 20, BAND_5GHZ, 0}"));

    // Tx power 20 dBm  (UNCHANGED)
    phy.Set("TxPowerStart",
        ns3::DoubleValue(m_cfg.tx_power_dbm));
    phy.Set("TxPowerEnd",
        ns3::DoubleValue(m_cfg.tx_power_dbm));

    // MAC: adhoc  (UNCHANGED)
    ns3::WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    // WiFi standard: 802.11a  (UNCHANGED)
    ns3::WifiHelper wifi;
    wifi.SetStandard(ns3::WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode",
        ns3::StringValue(m_cfg.data_rate),
        "ControlMode",
        ns3::StringValue(m_cfg.control_rate));

    // PATCH: install on topo.wifi_nodes which now includes SKDCs
    topo.wifi_devices = wifi.Install(phy, mac, topo.wifi_nodes);

    NS_LOG_INFO("TopologyBuilder: WiFi adhoc installed on "
        << topo.wifi_nodes.GetN()
        << " nodes (3 SKDCs + 18 UAVs + 1 Jammer) "
        << "802.11a " << m_cfg.data_rate);
}

// ===========================================================================
// Step 4: Internet stack + OLSR routing
// PATCH: InternetStack + OLSR installed on wifi_nodes which includes SKDCs.
//        SKDC nodes must NOT also have internet stack installed via
//        ground_nodes — so ground_nodes install is restricted to KDC only.
// ===========================================================================
void TopologyBuilder::InstallInternetStack(
    TopologyResult& topo)
{
    // OLSR for wifi_nodes (SKDCs + UAVs + jammer)
    ns3::OlsrHelper olsr;
    olsr.Set("HelloInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_HELLO_INTERVAL)));
    olsr.Set("TcInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_TC_INTERVAL)));

    ns3::Ipv4ListRoutingHelper list_routing;
    list_routing.Add(olsr, 10);

    ns3::InternetStackHelper internet_wifi;
    internet_wifi.SetRoutingHelper(list_routing);
    // PATCH: this installs on SKDCs + UAVs + jammer
    internet_wifi.Install(topo.wifi_nodes);

    // PATCH: Static routing for KDC only (not SKDCs — already installed above)
    ns3::InternetStackHelper internet_kdc;
    internet_kdc.Install(topo.kdc_node);

    NS_LOG_INFO("TopologyBuilder: Internet stack + OLSR installed"
        " on wifi_nodes (SKDCs+UAVs+jammer) + KDC");
}

// ===========================================================================
// Step 5: Assign IP addresses
// PATCH: wifi_interfaces now covers 22 nodes:
//   [0..2]  = SKDC0,1,2  (10.1.1.1, .2, .3)
//   [3..20] = UAV0..17   (10.1.1.4 .. .21)
//   [21]    = Jammer      (10.1.1.22)
// csma_interfaces covers 4 nodes (KDC + 3 SKDCs) — UNCHANGED
// ===========================================================================
void TopologyBuilder::AssignAddresses(TopologyResult& topo) {
    ns3::Ipv4AddressHelper addr;

    // WiFi: 10.1.1.0/24 — assign to all wifi_nodes (22 nodes)
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.wifi_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.wifi_mask.c_str()));
    topo.wifi_interfaces = addr.Assign(topo.wifi_devices);

    // CSMA: 192.168.0.0/24 — KDC + 3 SKDCs (UNCHANGED)
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.csma_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.csma_mask.c_str()));
    topo.csma_interfaces = addr.Assign(topo.csma_devices);

    NS_LOG_INFO("TopologyBuilder: Addresses assigned."
        << " WiFi: " << topo.wifi_interfaces.GetN()
        << " interfaces (SKDC0=" << topo.wifi_interfaces.GetAddress(0)
        << " UAV0=" << topo.wifi_interfaces.GetAddress(
            TopologyResult::WIFI_UAV_BASE)
        << ")"
        << " CSMA: " << topo.csma_interfaces.GetN()
        << " interfaces (KDC=" << topo.csma_interfaces.GetAddress(0)
        << " SKDC0=" << topo.csma_interfaces.GetAddress(1) << ")");

    // Debug log: SKDC WiFi addresses
    for (utils::u32 c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("[SKDC_WIFI_ADDR] t=0s"
            " cluster=" << c
            << " node=" << (c + 1)
            << " wifi_addr=" << topo.wifi_interfaces.GetAddress(
                TopologyResult::WIFI_SKDC_BASE + c)
            << " csma_addr=" << topo.csma_interfaces.GetAddress(c + 1));
    }
}

// ===========================================================================
// Step 6: Initial node positions
// PATCH: SKDCs now need a ConstantPosition mobility model too, because they
//        participate in the WiFi adhoc network. The ground_nodes mobility
//        (which includes SKDCs) is already set below — no change needed
//        since ground_mobility.Install(topo.ground_nodes) covers them.
//        SKDC positions at z=0 (ground-level) are valid for WiFi adhoc.
// ===========================================================================
void TopologyBuilder::ConfigureInitialPositions(
    TopologyResult& topo)
{
    // Ground nodes: fixed positions  (UNCHANGED)
    ns3::MobilityHelper ground_mobility;
    ground_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");

    ns3::Ptr<ns3::ListPositionAllocator> ground_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    // KDC at center
    ground_pos->Add(ns3::Vector(750.0, 750.0, 0.0));
    // SKDC0 at left — same x,y as cluster 0 UAV center
    ground_pos->Add(ns3::Vector(250.0, 750.0, 0.0));
    // SKDC1 at bottom center — same as cluster 1 UAV center
    ground_pos->Add(ns3::Vector(750.0, 250.0, 0.0));
    // SKDC2 at right — same as cluster 2 UAV center
    ground_pos->Add(ns3::Vector(1250.0, 750.0, 0.0));

    ground_mobility.SetPositionAllocator(ground_pos);
    ground_mobility.Install(topo.ground_nodes);

    // UAV initial positions  (UNCHANGED)
    double cluster_centers[3][2] = {
        {250.0,  750.0},
        {750.0,  250.0},
        {1250.0, 750.0}
    };

    ns3::MobilityHelper uav_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> uav_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    double altitude_base = 100.0;
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        double cx = cluster_centers[c][0];
        double cy = cluster_centers[c][1];
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            double angle  = (2.0 * M_PI * u) /
                             m_cfg.uavs_per_cluster;
            double radius = 100.0;
            double x = cx + radius * std::cos(angle);
            double y = cy + radius * std::sin(angle);
            double z = altitude_base + 10.0 * static_cast<double>(u);
            uav_pos->Add(ns3::Vector(x, y, z));
        }
    }

    uav_mobility.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds", ns3::BoxValue(ns3::Box(
            0.0, 1500.0, 0.0, 1500.0, 50.0, 150.0)),
        "TimeStep", ns3::TimeValue(ns3::Seconds(0.5)),
        "Alpha", ns3::DoubleValue(0.3),
        "MeanVelocity", ns3::StringValue(
            "ns3::ConstantRandomVariable[Constant=20.0]"),
        "MeanDirection", ns3::StringValue(
            "ns3::UniformRandomVariable[Min=0|Max=6.283]"),
        "MeanPitch", ns3::StringValue(
            "ns3::ConstantRandomVariable[Constant=0.0]"),
        "NormalVelocity", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=8.0]"),
        "NormalDirection", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.3]"),
        "NormalPitch", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.02]"));
    uav_mobility.SetPositionAllocator(uav_pos);
    uav_mobility.Install(topo.uav_nodes);

    // Jammer initial position  (UNCHANGED)
    ns3::MobilityHelper jammer_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> jammer_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();
    jammer_pos->Add(ns3::Vector(750.0, 750.0, 50.0));
    jammer_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");
    jammer_mobility.SetPositionAllocator(jammer_pos);
    jammer_mobility.Install(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Initial positions configured"
        " (SKDCs at ground level, UAVs at 100m altitude)");
}

// ===========================================================================
// Enable PCAP tracing  (UNCHANGED)
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

// ===========================================================================
// ConfigureOlsr  (stub — OLSR configured inside InstallInternetStack)
// ===========================================================================
void TopologyBuilder::ConfigureOlsr(TopologyResult& /*topo*/) {
    // OLSR is configured inside InstallInternetStack via OlsrHelper.
    // This stub is preserved for API compatibility.
}

} // namespace routing
} // namespace uav/**
 * routing/uav-topology.cc  [PATCHED — dual-interface SKDC]
 *
 * PATCH SUMMARY (incremental, minimal):
 *   CreateNodes:        wifi_nodes.Add(topo.skdc_nodes) before UAVs
 *   ConfigureWifiAdhoc: wifi.Install(topo.wifi_nodes) now includes SKDCs
 *   InstallInternetStack: OLSR installed on wifi_nodes (now includes SKDCs)
 *                         InternetStack NOT installed on skdc_nodes again
 *   AssignAddresses:    wifi address block covers 22 nodes (SKDCs+UAVs+jammer)
 *   GetSkdcCsmaAddr:    unchanged (CSMA index cluster+1)
 *   GetSkdcWifiAddr:    NEW — inline in header, implementation not needed
 *   GetUavWifiAddr:     unchanged call — uses WIFI_UAV_BASE offset in header
 *
 * INTERFACE LAYOUT PRODUCED:
 *   wifi_interfaces[0]  = SKDC0  10.1.1.1
 *   wifi_interfaces[1]  = SKDC1  10.1.1.2
 *   wifi_interfaces[2]  = SKDC2  10.1.1.3
 *   wifi_interfaces[3]  = UAV0   10.1.1.4
 *   ...
 *   wifi_interfaces[20] = UAV17  10.1.1.21
 *   wifi_interfaces[21] = Jammer 10.1.1.22
 *   csma_interfaces[0]  = KDC    192.168.0.1
 *   csma_interfaces[1]  = SKDC0  192.168.0.2
 *   csma_interfaces[2]  = SKDC1  192.168.0.3
 *   csma_interfaces[3]  = SKDC2  192.168.0.4
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

ns3::Ipv4Address TopologyResult::GetSkdcCsmaAddr(
    utils::u32 cluster) const
{
    // CSMA: [0]=KDC, [1]=SKDC0, [2]=SKDC1, [3]=SKDC2  (UNCHANGED)
    return csma_interfaces.GetAddress(cluster + 1);
}

ns3::Ipv4Address TopologyResult::GetKdcCsmaAddr() const
{
    return csma_interfaces.GetAddress(0);
}

// ===========================================================================
// TopologyBuilder constructor
// ===========================================================================
TopologyBuilder::TopologyBuilder(const TopologyConfig& cfg)
    : m_cfg(cfg)
{}

// ===========================================================================
// Build — orchestrate all steps (UNCHANGED)
// ===========================================================================
TopologyResult TopologyBuilder::Build() {
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: "
        << m_cfg.total_uavs << " UAVs, "
        << m_cfg.num_clusters << " clusters"
        << " [dual-interface SKDC]");

    TopologyResult topo;

    CreateNodes(topo);
    ConfigureCsmaBackbone(topo);
    ConfigureWifiAdhoc(topo);
    InstallInternetStack(topo);
    AssignAddresses(topo);
    ConfigureInitialPositions(topo);

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "TopologyBuilder::Build: complete. "
        << "Total: " << topo.all_nodes.GetN() << " nodes"
        << " WiFi: " << topo.wifi_nodes.GetN()
        << " (SKDCs+UAVs+jammer)");

    return topo;
}

// ===========================================================================
// Step 1: Create all nodes
// PATCH: wifi_nodes.Add(skdc_nodes) FIRST so SKDCs get
//        lower wifi_interfaces indices (0,1,2) before UAVs (3-20).
// ===========================================================================
void TopologyBuilder::CreateNodes(TopologyResult& topo) {
    // Ground nodes: KDC(1) + SKDCs(3) = 4  (UNCHANGED)
    topo.ground_nodes.Create(4);

    // UAV nodes: 18  (UNCHANGED)
    topo.uav_nodes.Create(m_cfg.total_uavs);

    // Jammer: 1  (UNCHANGED)
    topo.jammer_node.Create(1);

    // KDC = ground_nodes[0]  (UNCHANGED)
    topo.kdc_node.Add(topo.ground_nodes.Get(0));

    // SKDCs = ground_nodes[1..3]  (UNCHANGED)
    for (utils::u32 i = 0; i < m_cfg.num_clusters; ++i) {
        topo.skdc_nodes.Add(topo.ground_nodes.Get(i + 1));
    }

    // Per-cluster UAV containers  (UNCHANGED)
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            utils::u32 idx = c * m_cfg.uavs_per_cluster + u;
            topo.cluster_nodes[c].Add(topo.uav_nodes.Get(idx));
        }
    }

    // PATCH: wifi_nodes = SKDCs + UAVs + jammer  (was: UAVs + jammer)
    // Order matters — SKDCs get wifi_interfaces[0,1,2]
    //                 UAVs  get wifi_interfaces[3..20]
    //                 Jammer gets wifi_interfaces[21]
    topo.wifi_nodes.Add(topo.skdc_nodes);   // PATCH: SKDCs first
    topo.wifi_nodes.Add(topo.uav_nodes);
    topo.wifi_nodes.Add(topo.jammer_node);

    // All nodes = ground + UAVs + jammer  (UNCHANGED)
    topo.all_nodes.Add(topo.ground_nodes);
    topo.all_nodes.Add(topo.uav_nodes);
    topo.all_nodes.Add(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Created "
        << topo.all_nodes.GetN() << " nodes"
        << " wifi_nodes=" << topo.wifi_nodes.GetN()
        << " (3 SKDCs + 18 UAVs + 1 Jammer)");
}

// ===========================================================================
// Step 2: CSMA backbone (KDC + SKDCs)  (UNCHANGED)
// ===========================================================================
void TopologyBuilder::ConfigureCsmaBackbone(
    TopologyResult& topo)
{
    ns3::CsmaHelper csma;
    csma.SetChannelAttribute("DataRate",
        ns3::StringValue(m_cfg.csma_data_rate));
    csma.SetChannelAttribute("Delay",
        ns3::StringValue(m_cfg.csma_delay));
    csma.SetDeviceAttribute("Mtu",
        ns3::UintegerValue(1500));

    topo.csma_devices = csma.Install(topo.ground_nodes);

    NS_LOG_INFO("TopologyBuilder: CSMA backbone installed "
        << m_cfg.csma_data_rate);
}

// ===========================================================================
// Step 3: WiFi adhoc (SKDCs + UAVs + jammer)
// PATCH: wifi.Install(topo.wifi_nodes) now includes SKDCs automatically
//        because topo.wifi_nodes includes skdc_nodes (added in CreateNodes).
// ===========================================================================
void TopologyBuilder::ConfigureWifiAdhoc(
    TopologyResult& topo)
{
    // PHY layer  (UNCHANGED)
    ns3::YansWifiChannelHelper channel =
        ns3::YansWifiChannelHelper::Default();

    channel.AddPropagationLoss(
        "ns3::FriisPropagationLossModel");
    channel.AddPropagationLoss(
        "ns3::NakagamiPropagationLossModel",
        "m0", ns3::DoubleValue(m_cfg.nakagami_m0),
        "m1", ns3::DoubleValue(m_cfg.nakagami_m1),
        "m2", ns3::DoubleValue(m_cfg.nakagami_m2));

    ns3::YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    // 5 GHz band, channel 36  (UNCHANGED)
    phy.Set("ChannelSettings",
        ns3::StringValue("{36, 20, BAND_5GHZ, 0}"));

    // Tx power 20 dBm  (UNCHANGED)
    phy.Set("TxPowerStart",
        ns3::DoubleValue(m_cfg.tx_power_dbm));
    phy.Set("TxPowerEnd",
        ns3::DoubleValue(m_cfg.tx_power_dbm));

    // MAC: adhoc  (UNCHANGED)
    ns3::WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    // WiFi standard: 802.11a  (UNCHANGED)
    ns3::WifiHelper wifi;
    wifi.SetStandard(ns3::WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode",
        ns3::StringValue(m_cfg.data_rate),
        "ControlMode",
        ns3::StringValue(m_cfg.control_rate));

    // PATCH: install on topo.wifi_nodes which now includes SKDCs
    topo.wifi_devices = wifi.Install(phy, mac, topo.wifi_nodes);

    NS_LOG_INFO("TopologyBuilder: WiFi adhoc installed on "
        << topo.wifi_nodes.GetN()
        << " nodes (3 SKDCs + 18 UAVs + 1 Jammer) "
        << "802.11a " << m_cfg.data_rate);
}

// ===========================================================================
// Step 4: Internet stack + OLSR routing
// PATCH: InternetStack + OLSR installed on wifi_nodes which includes SKDCs.
//        SKDC nodes must NOT also have internet stack installed via
//        ground_nodes — so ground_nodes install is restricted to KDC only.
// ===========================================================================
void TopologyBuilder::InstallInternetStack(
    TopologyResult& topo)
{
    // OLSR for wifi_nodes (SKDCs + UAVs + jammer)
    ns3::OlsrHelper olsr;
    olsr.Set("HelloInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_HELLO_INTERVAL)));
    olsr.Set("TcInterval",
        ns3::TimeValue(ns3::Seconds(OLSR_TC_INTERVAL)));

    ns3::Ipv4ListRoutingHelper list_routing;
    list_routing.Add(olsr, 10);

    ns3::InternetStackHelper internet_wifi;
    internet_wifi.SetRoutingHelper(list_routing);
    // PATCH: this installs on SKDCs + UAVs + jammer
    internet_wifi.Install(topo.wifi_nodes);

    // PATCH: Static routing for KDC only (not SKDCs — already installed above)
    ns3::InternetStackHelper internet_kdc;
    internet_kdc.Install(topo.kdc_node);

    NS_LOG_INFO("TopologyBuilder: Internet stack + OLSR installed"
        " on wifi_nodes (SKDCs+UAVs+jammer) + KDC");
}

// ===========================================================================
// Step 5: Assign IP addresses
// PATCH: wifi_interfaces now covers 22 nodes:
//   [0..2]  = SKDC0,1,2  (10.1.1.1, .2, .3)
//   [3..20] = UAV0..17   (10.1.1.4 .. .21)
//   [21]    = Jammer      (10.1.1.22)
// csma_interfaces covers 4 nodes (KDC + 3 SKDCs) — UNCHANGED
// ===========================================================================
void TopologyBuilder::AssignAddresses(TopologyResult& topo) {
    ns3::Ipv4AddressHelper addr;

    // WiFi: 10.1.1.0/24 — assign to all wifi_nodes (22 nodes)
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.wifi_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.wifi_mask.c_str()));
    topo.wifi_interfaces = addr.Assign(topo.wifi_devices);

    // CSMA: 192.168.0.0/24 — KDC + 3 SKDCs (UNCHANGED)
    addr.SetBase(
        ns3::Ipv4Address(m_cfg.csma_base_addr.c_str()),
        ns3::Ipv4Mask(m_cfg.csma_mask.c_str()));
    topo.csma_interfaces = addr.Assign(topo.csma_devices);

    NS_LOG_INFO("TopologyBuilder: Addresses assigned."
        << " WiFi: " << topo.wifi_interfaces.GetN()
        << " interfaces (SKDC0=" << topo.wifi_interfaces.GetAddress(0)
        << " UAV0=" << topo.wifi_interfaces.GetAddress(
            TopologyResult::WIFI_UAV_BASE)
        << ")"
        << " CSMA: " << topo.csma_interfaces.GetN()
        << " interfaces (KDC=" << topo.csma_interfaces.GetAddress(0)
        << " SKDC0=" << topo.csma_interfaces.GetAddress(1) << ")");

    // Debug log: SKDC WiFi addresses
    for (utils::u32 c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("[SKDC_WIFI_ADDR] t=0s"
            " cluster=" << c
            << " node=" << (c + 1)
            << " wifi_addr=" << topo.wifi_interfaces.GetAddress(
                TopologyResult::WIFI_SKDC_BASE + c)
            << " csma_addr=" << topo.csma_interfaces.GetAddress(c + 1));
    }
}

// ===========================================================================
// Step 6: Initial node positions
// PATCH: SKDCs now need a ConstantPosition mobility model too, because they
//        participate in the WiFi adhoc network. The ground_nodes mobility
//        (which includes SKDCs) is already set below — no change needed
//        since ground_mobility.Install(topo.ground_nodes) covers them.
//        SKDC positions at z=0 (ground-level) are valid for WiFi adhoc.
// ===========================================================================
void TopologyBuilder::ConfigureInitialPositions(
    TopologyResult& topo)
{
    // Ground nodes: fixed positions  (UNCHANGED)
    ns3::MobilityHelper ground_mobility;
    ground_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");

    ns3::Ptr<ns3::ListPositionAllocator> ground_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    // KDC at center
    ground_pos->Add(ns3::Vector(750.0, 750.0, 0.0));
    // SKDC0 at left — same x,y as cluster 0 UAV center
    ground_pos->Add(ns3::Vector(250.0, 750.0, 0.0));
    // SKDC1 at bottom center — same as cluster 1 UAV center
    ground_pos->Add(ns3::Vector(750.0, 250.0, 0.0));
    // SKDC2 at right — same as cluster 2 UAV center
    ground_pos->Add(ns3::Vector(1250.0, 750.0, 0.0));

    ground_mobility.SetPositionAllocator(ground_pos);
    ground_mobility.Install(topo.ground_nodes);

    // UAV initial positions  (UNCHANGED)
    double cluster_centers[3][2] = {
        {250.0,  750.0},
        {750.0,  250.0},
        {1250.0, 750.0}
    };

    ns3::MobilityHelper uav_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> uav_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();

    double altitude_base = 100.0;
    for (utils::u32 c = 0; c < m_cfg.num_clusters; ++c) {
        double cx = cluster_centers[c][0];
        double cy = cluster_centers[c][1];
        for (utils::u32 u = 0; u < m_cfg.uavs_per_cluster; ++u) {
            double angle  = (2.0 * M_PI * u) /
                             m_cfg.uavs_per_cluster;
            double radius = 100.0;
            double x = cx + radius * std::cos(angle);
            double y = cy + radius * std::sin(angle);
            double z = altitude_base + 10.0 * static_cast<double>(u);
            uav_pos->Add(ns3::Vector(x, y, z));
        }
    }

    uav_mobility.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds", ns3::BoxValue(ns3::Box(
            0.0, 1500.0, 0.0, 1500.0, 50.0, 150.0)),
        "TimeStep", ns3::TimeValue(ns3::Seconds(0.5)),
        "Alpha", ns3::DoubleValue(0.3),
        "MeanVelocity", ns3::StringValue(
            "ns3::ConstantRandomVariable[Constant=20.0]"),
        "MeanDirection", ns3::StringValue(
            "ns3::UniformRandomVariable[Min=0|Max=6.283]"),
        "MeanPitch", ns3::StringValue(
            "ns3::ConstantRandomVariable[Constant=0.0]"),
        "NormalVelocity", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=8.0]"),
        "NormalDirection", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.3]"),
        "NormalPitch", ns3::StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.02]"));
    uav_mobility.SetPositionAllocator(uav_pos);
    uav_mobility.Install(topo.uav_nodes);

    // Jammer initial position  (UNCHANGED)
    ns3::MobilityHelper jammer_mobility;
    ns3::Ptr<ns3::ListPositionAllocator> jammer_pos =
        ns3::CreateObject<ns3::ListPositionAllocator>();
    jammer_pos->Add(ns3::Vector(750.0, 750.0, 50.0));
    jammer_mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");
    jammer_mobility.SetPositionAllocator(jammer_pos);
    jammer_mobility.Install(topo.jammer_node);

    NS_LOG_INFO("TopologyBuilder: Initial positions configured"
        " (SKDCs at ground level, UAVs at 100m altitude)");
}

// ===========================================================================
// Enable PCAP tracing  (UNCHANGED)
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

// ===========================================================================
// ConfigureOlsr  (stub — OLSR configured inside InstallInternetStack)
// ===========================================================================
void TopologyBuilder::ConfigureOlsr(TopologyResult& /*topo*/) {
    // OLSR is configured inside InstallInternetStack via OlsrHelper.
    // This stub is preserved for API compatibility.
}

} // namespace routing
} // namespace uav