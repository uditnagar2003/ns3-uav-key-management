/**
 * main.cc - Module 41: Join Security Event
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
#include "apps/uav-join-event.h"
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
    routing::OlsrManager olsr_mgr(topo);
    routing::QueueManager queue_mgr(topo);
    queue_mgr.ConfigureAll();
    routing::FlowMonitorManager flow_mgr(topo);
    flow_mgr.Install();

    mobility::MobilityManager mob_mgr(topo, {});
    mob_mgr.InstallGaussMarkov();
    mobility::JammerMobilityManager jammer(topo);
    jammer.InstallRandomWaypoint(10.0, 10.0, 42);

    // KDC + SKDCs + UAVs
    Ptr<apps::KdcApplication> kdc_app =
        CreateObject<apps::KdcApplication>();
    kdc_app->SetTopology(&topo);
    kdc_app->SetCryptoParams(&params);
    topo.kdc_node.Get(0)->AddApplication(kdc_app);
    kdc_app->SetStartTime(Seconds(0.5));
    kdc_app->SetStopTime(Seconds(20.0));

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

    std::vector<Ptr<apps::UavApplication>> uav_apps;
    for (uint32_t uav = 0; uav < 18; ++uav) {
        auto app =
            CreateObject<apps::UavApplication>();
        app->SetUavId(uav, uav%6, uav/6);
        app->SetTopology(&topo);
        app->SetCryptoParams(&params);
        topo.uav_nodes.Get(uav)->AddApplication(app);
        app->SetStartTime(Seconds(2.0));
        app->SetStopTime(Seconds(20.0));
        uav_apps.push_back(app);
    }

    // Security managers
    apps::TekManager tek_mgr(&params);
    tek_mgr.Initialize();

    apps::MulticastManager mc_mgr(&topo, &params);
    mc_mgr.Initialize();

    apps::MtkDistributionManager dist_mgr(
        &topo, &params, &tek_mgr, &mc_mgr);

    // Module 41: Join Event Manager
    NS_LOG_UNCOND(
        "=== Module 41: Join Security Event ===");

    apps::JoinEventManager join_mgr(
        &topo, &params,
        &mc_mgr, &dist_mgr, &tek_mgr);

    join_mgr.SetJoinCallback([](
        const apps::JoinRecord& rec)
    {
        NS_LOG_UNCOND("  [JOIN] UAV" << rec.uav_id
            << " C" << rec.cluster_id
            << " auth=" << rec.authenticated
            << " joined=" << rec.joined
            << " tek=" << rec.tek_received);
    });

    // Test 1: Valid join — new UAV (id=18, idx=0)
    // First remove one to make room
    NS_LOG_UNCOND("\nStep 1: Remove UAV5 from C0...");
    mc_mgr.RemoveMember(0, 5, 5);
    NS_LOG_UNCOND("  C0 size: "
        << mc_mgr.GetGroupSize(0));

    NS_LOG_UNCOND("\nStep 2: UAV18 joins C0...");
    bool ok1 = join_mgr.ProcessJoin(
        18, 5, 0,
        skdc_apps[0].operator->(),
        nullptr);
    NS_LOG_UNCOND("  Join result: "
        << (ok1 ? "PASS" : "FAIL"));

    // Test 2: Second join same cluster
    NS_LOG_UNCOND("\nStep 3: UAV19 joins C1...");
    // First make room in C1
    mc_mgr.RemoveMember(1, 10, 10);
    bool ok2 = join_mgr.ProcessJoin(
        19, 4, 1,
        skdc_apps[1].operator->(),
        nullptr);
    NS_LOG_UNCOND("  Join result: "
        << (ok2 ? "PASS" : "FAIL"));

    // Test 3: Verify cluster sizes updated
    NS_LOG_UNCOND("\nCluster sizes after joins:");
    for (uint32_t c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("  C" << c << ": "
            << mc_mgr.GetGroupSize(c)
            << " members v"
            << mc_mgr.GetVersion(c));
    }

    // Test 4: Print join stats
    join_mgr.PrintJoinStats();

    // Test 5: Verify MT_K distributions
    NS_LOG_UNCOND("\nMT_K distributions: "
        << dist_mgr.GetTotalBroadcasts());

    bool stats_ok =
        (join_mgr.GetTotalJoins() == 2) &&
        (join_mgr.GetFailedJoins() == 0);
    NS_LOG_UNCOND("Join stats: "
        << (stats_ok ? "PASS" : "FAIL"));

    // Run simulation
    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    NS_LOG_UNCOND("\nModule 41: OK");
    Simulator::Destroy();
    return 0;
}
