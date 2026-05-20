/**
 * main.cc - UAV Secure FANET Simulation Entry Point
 * Tests Modules 24-29: Full Phase 4
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "routing/uav-topology.h"
#include "routing/uav-wifi-config.h"
#include "routing/uav-csma-backbone.h"
#include "routing/uav-olsr-manager.h"
#include "routing/uav-flowmonitor.h"
#include "routing/uav-queue-manager.h"

NS_LOG_COMPONENT_DEFINE("UavSecureFanet");

using namespace ns3;
using namespace uav;

int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    OpenSSLInit::Bootstrap();

    log::Logger::Instance().Initialize(
        "logs", log::LogLevel::INFO, true);

    // Phase 4: Full network core
    routing::TopologyConfig cfg;
    routing::TopologyBuilder builder(cfg);
    routing::TopologyResult topo = builder.Build();

    routing::WifiConfigManager wifi_mgr(topo);
    wifi_mgr.SetJammerTxPower();
    wifi_mgr.SetAllUavTxPowers();

    routing::CsmaBackboneManager backbone(topo);
    backbone.ConfigureStaticRoutes();

    routing::OlsrManager olsr_mgr(topo);

    routing::FlowMonitorManager flow_mgr(topo);
    flow_mgr.Install();

    // Module 29: Queue Management
    NS_LOG_UNCOND("=== Module 29: Queue Management ===");
    routing::QueueManager queue_mgr(topo);
    queue_mgr.ConfigureAll();

    // Verify queue limits
    NS_LOG_UNCOND("Max queue size: "
        << routing::QueueManager::MAX_QUEUE_SIZE
        << " packets");
    NS_LOG_UNCOND("WiFi queue size: "
        << routing::QueueManager::WIFI_QUEUE_SIZE);
    NS_LOG_UNCOND("CSMA queue size: "
        << routing::QueueManager::CSMA_QUEUE_SIZE);

    // Test drop tracking
    queue_mgr.RecordDrop(4);  // UAV 0 (NS-3 node 4)
    queue_mgr.RecordDrop(4);
    queue_mgr.RecordDrop(5);  // UAV 1
    NS_LOG_UNCOND("Total drops: "
        << queue_mgr.GetTotalDrops());

    // Install traffic
    uint16_t port = 9100;
    Ipv4Address uav1_addr =
        topo.wifi_interfaces.GetAddress(1);

    UdpEchoServerHelper server(port);
    auto srv = server.Install(topo.uav_nodes.Get(1));
    srv.Start(Seconds(1.0));
    srv.Stop(Seconds(9.0));

    UdpEchoClientHelper client(uav1_addr, port);
    client.SetAttribute("MaxPackets", UintegerValue(20));
    client.SetAttribute("Interval",
        TimeValue(Seconds(0.2)));
    client.SetAttribute("PacketSize", UintegerValue(512));
    auto cli = client.Install(topo.uav_nodes.Get(0));
    cli.Start(Seconds(2.0));
    cli.Stop(Seconds(9.0));

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();

    // Collect metrics
    flow_mgr.CollectMetrics(10.0);
    queue_mgr.PrintQueueStats();
    flow_mgr.PrintSummary();

    NS_LOG_UNCOND("\nPhase 4 Complete — Modules 24-29: OK");
    Simulator::Destroy();
    return 0;
}
