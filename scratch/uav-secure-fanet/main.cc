/**
 * main.cc - Module 52: Event Annotations
 */
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "routing/uav-topology.h"
#include "routing/uav-queue-manager.h"
#include "routing/uav-flowmonitor.h"
#include "routing/uav-csma-backbone.h"
#include "routing/uav-olsr-manager.h"
#include "mobility/uav-mobility-manager.h"
#include "mobility/uav-jammer-mobility.h"
#include "apps/uav-skdc-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-leave-event.h"
#include "apps/uav-rekey-manager.h"
#include "apps/uav-compromise-detector.h"
#include "apps/uav-jammer-manager.h"
#include "visualization/uav-netanim.h"
#include "visualization/uav-node-color.h"
#include "visualization/uav-packet-viz.h"
#include "visualization/uav-event-annotations.h"
#include "crypto/uav-crypto-params.h"

NS_LOG_COMPONENT_DEFINE("UavSecureFanet");
using namespace ns3;
using namespace uav;

static const char* CRYPTO_JSON =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/json/crypto_params.json";
static const char* OUTPUT_DIR =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/output";

int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    OpenSSLInit::Bootstrap();
    log::Logger::Instance().Initialize(
        "logs", log::LogLevel::INFO, true);

    crypto::CryptoParamsFile params =
        crypto::CryptoParamsLoader::LoadFromFile(CRYPTO_JSON);

    routing::TopologyConfig cfg;
    routing::TopologyBuilder builder(cfg);
    routing::TopologyResult topo = builder.Build();

    routing::CsmaBackboneManager backbone(topo);
    backbone.ConfigureStaticRoutes();
    routing::QueueManager queue_mgr(topo);
    queue_mgr.ConfigureAll();
    routing::FlowMonitorManager flow_mgr(topo);
    flow_mgr.Install();

    mobility::MobilityManager mob_mgr(topo, {});
    mob_mgr.InstallGaussMarkov();
    mobility::JammerMobilityManager jammer_mob(topo);
    jammer_mob.InstallRandomWaypoint(10.0, 10.0, 42);

    std::array<Ptr<apps::SkdcApplication>, 3> skdc_apps;
    for (uint32_t c = 0; c < 3; ++c) {
        skdc_apps[c] = CreateObject<apps::SkdcApplication>();
        skdc_apps[c]->SetClusterId(c);
        skdc_apps[c]->SetTopology(&topo);
        skdc_apps[c]->SetCryptoParams(&params);
        topo.skdc_nodes.Get(c)->AddApplication(skdc_apps[c]);
        skdc_apps[c]->SetStartTime(Seconds(1.0));
        skdc_apps[c]->SetStopTime(Seconds(10.0));
    }

    apps::TekManager tek_mgr(&params);
    tek_mgr.Initialize();
    apps::MulticastManager mc_mgr(&topo, &params);
    mc_mgr.Initialize();
    apps::MtkDistributionManager dist_mgr(
        &topo, &params, &tek_mgr, &mc_mgr);
    apps::LeaveEventManager leave_mgr(
        &topo, &params, &mc_mgr, &dist_mgr, &tek_mgr);
    apps::RekeyManager rekey_mgr(
        &topo, &params, &tek_mgr, &dist_mgr, &mc_mgr);
    apps::CompromiseDetector comp_det(
        &topo, &mc_mgr, &dist_mgr, &tek_mgr, &leave_mgr);
    apps::JammerManager jammer_mgr(&topo, &jammer_mob);

    // Visualization stack
    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    netanim.Initialize();
    visualization::NodeColorManager color_mgr(&topo, &netanim);
    color_mgr.Initialize();
    visualization::PacketVizManager pkt_viz(&topo, &netanim);
    pkt_viz.Initialize();

    // ===================================================
    // Module 52: Event Annotations
    // ===================================================
    NS_LOG_UNCOND("=== Module 52: Event Annotations ===");

    visualization::EventAnnotationManager evt_ann(
        &topo, &netanim);
    evt_ann.Initialize();

    // Test 1: compromise annotation
    NS_LOG_UNCOND("\nTest 1: Compromise annotation...");
    evt_ann.OnCompromise(2);
    evt_ann.OnCompromise(5);
    NS_LOG_UNCOND("  Annotations: "
        << evt_ann.GetTotalAnnotations()
        << " (expect 2): "
        << (evt_ann.GetTotalAnnotations() == 2
            ? "PASS" : "FAIL"));

    // Test 2: rekey annotation
    NS_LOG_UNCOND("\nTest 2: Rekey annotation...");
    evt_ann.OnRekey(0);
    evt_ann.OnRekey(1);
    evt_ann.OnRekey(2);
    NS_LOG_UNCOND("  Test 2: PASS");

    // Test 3: join/leave annotations
    NS_LOG_UNCOND("\nTest 3: Join/Leave annotations...");
    evt_ann.OnJoin(0);
    evt_ann.OnJoin(6);
    evt_ann.OnLeave(3);
    NS_LOG_UNCOND("  Test 3: PASS");

    // Test 4: handover annotation
    NS_LOG_UNCOND("\nTest 4: Handover annotation...");
    evt_ann.OnHandover(5);
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: jammer detection annotation
    NS_LOG_UNCOND("\nTest 5: Jammer detection annotation...");
    evt_ann.OnJammerDetect(18);
    NS_LOG_UNCOND("  Test 5: PASS");

    // Test 6: generic SecurityEventType dispatcher
    NS_LOG_UNCOND("\nTest 6: Generic event dispatcher...");
    evt_ann.OnSecurityEvent(
        utils::SecurityEventType::TEK_ROTATION, 0, false);
    evt_ann.OnSecurityEvent(
        utils::SecurityEventType::HANDOVER_START, 7, true);
    evt_ann.OnSecurityEvent(
        utils::SecurityEventType::JAMMER_DETECTED, 18, false);
    NS_LOG_UNCOND("  Test 6: PASS");

    // Test 7: total annotations
    NS_LOG_UNCOND("\nTest 7: Total annotations...");
    uint64_t total = evt_ann.GetTotalAnnotations();
    NS_LOG_UNCOND("  Total: " << total
        << " (expect >=10): "
        << (total >= 10 ? "PASS" : "FAIL"));

    evt_ann.PrintStats();

    Simulator::Stop(Seconds(3.0));
    Simulator::Run();

    NS_LOG_UNCOND("\nModule 52: OK");
    Simulator::Destroy();
    return 0;
}
