/**
 * main.cc - Module 45: Compromise Detection
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
#include "apps/uav-kdc-app.h"
#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-leave-event.h"
#include "apps/uav-compromise-detector.h"
#include "crypto/uav-crypto-params.h"

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

    crypto::CryptoParamsFile params =
        crypto::CryptoParamsLoader::LoadFromFile(
            "/home/udit/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet/json/crypto_params.json");

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
    mobility::JammerMobilityManager jammer(topo);
    jammer.InstallRandomWaypoint(10.0, 10.0, 42);

    std::array<Ptr<apps::SkdcApplication>, 3> skdc_apps;
    for (uint32_t c = 0; c < 3; ++c) {
        skdc_apps[c] =
            CreateObject<apps::SkdcApplication>();
        skdc_apps[c]->SetClusterId(c);
        skdc_apps[c]->SetTopology(&topo);
        skdc_apps[c]->SetCryptoParams(&params);
        topo.skdc_nodes.Get(c)
            ->AddApplication(skdc_apps[c]);
        skdc_apps[c]->SetStartTime(Seconds(1.0));
        skdc_apps[c]->SetStopTime(Seconds(20.0));
    }

    apps::TekManager tek_mgr(&params);
    tek_mgr.Initialize();
    apps::MulticastManager mc_mgr(&topo, &params);
    mc_mgr.Initialize();
    apps::MtkDistributionManager dist_mgr(
        &topo, &params, &tek_mgr, &mc_mgr);
    apps::LeaveEventManager leave_mgr(
        &topo, &params,
        &mc_mgr, &dist_mgr, &tek_mgr);

    // Module 45: Compromise Detector
    NS_LOG_UNCOND(
        "=== Module 45: Compromise Detection ===");

    apps::CompromiseDetector detector(
        &topo, &mc_mgr, &dist_mgr,
        &tek_mgr, &leave_mgr);

    detector.SetCallback([](
        const apps::CompromiseEvent& ev)
    {
        NS_LOG_UNCOND("  [COMPROMISE] UAV"
            << ev.uav_id
            << " C" << ev.cluster_id
            << " reason="
            << apps::CompromiseReasonStr(ev.reason)
            << " revoked=" << ev.revoked);
    });

    // Test 1: HMAC failure detection
    NS_LOG_UNCOND("\nTest 1: HMAC failure UAV2 C0...");
    detector.ReportHmacFailure(
        2, 0, 2, skdc_apps[0]);
    NS_LOG_UNCOND("  Compromised: "
        << detector.IsCompromised(2));
    NS_LOG_UNCOND("  Revoked:     "
        << detector.IsRevoked(2));
    bool t1_ok = detector.IsCompromised(2) &&
                 detector.IsRevoked(2);
    NS_LOG_UNCOND("  Test 1: "
        << (t1_ok ? "PASS" : "FAIL"));

    // Test 2: Replay attack detection
    NS_LOG_UNCOND("\nTest 2: Replay attack UAV8 C1...");
    detector.ReportReplayAttack(
        8, 1, 2, skdc_apps[1]);
    bool t2_ok = detector.IsRevoked(8);
    NS_LOG_UNCOND("  Test 2: "
        << (t2_ok ? "PASS" : "FAIL"));

    // Test 3: Invalid TEK
    NS_LOG_UNCOND("\nTest 3: Invalid TEK UAV14 C2...");
    detector.ReportInvalidTek(
        14, 2, 2, skdc_apps[2]);
    bool t3_ok = detector.IsRevoked(14);
    NS_LOG_UNCOND("  Test 3: "
        << (t3_ok ? "PASS" : "FAIL"));

    // Test 4: Duplicate report (already revoked)
    NS_LOG_UNCOND("\nTest 4: Duplicate report UAV2...");
    utils::u64 detections_before =
        detector.GetTotalDetections();
    detector.ReportExternal(
        2, 0, 2, skdc_apps[0]);
    bool t4_ok = (detector.GetTotalDetections()
                  == detections_before);
    NS_LOG_UNCOND("  Duplicate ignored: "
        << (t4_ok ? "PASS" : "FAIL"));

    // Print status
    detector.PrintStatus();

    // Verify cluster sizes after revocations
    NS_LOG_UNCOND("\nCluster sizes:");
    for (uint32_t c = 0; c < 3; ++c)
        NS_LOG_UNCOND("  C" << c << ": "
            << mc_mgr.GetGroupSize(c)
            << " v" << mc_mgr.GetVersion(c));

    bool stats_ok =
        (detector.GetTotalDetections() == 3) &&
        (detector.GetTotalRevocations() == 3);
    NS_LOG_UNCOND("\nDetector stats: "
        << (stats_ok ? "PASS" : "FAIL"));

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    NS_LOG_UNCOND("\nModule 45: OK");
    Simulator::Destroy();
    return 0;
}
