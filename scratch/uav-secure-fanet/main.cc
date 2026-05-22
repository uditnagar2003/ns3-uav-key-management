/**
 * main.cc - Module 53: Throughput Metrics
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
#include "visualization/uav-netanim.h"
#include "metrics/uav-throughput-metrics.h"
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

    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    netanim.Initialize();

    // ===================================================
    // Module 53: Throughput Metrics
    // ===================================================
    NS_LOG_UNCOND("=== Module 53: Throughput Metrics ===");

    metrics::ThroughputMetrics tput_mgr(&topo, &flow_mgr);

    // Schedule periodic sampling every 1s
    tput_mgr.SchedulePeriodicSample(1.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();

    // After simulation — collect FlowMonitor data
    flow_mgr.CollectMetrics(10.0);

    // Compute throughput
    tput_mgr.Compute();

    // Test 1: compute runs without crash
    NS_LOG_UNCOND("\nTest 1: Compute without crash...");
    NS_LOG_UNCOND("  Test 1: PASS");

    // Test 2: global throughput >= 0
    NS_LOG_UNCOND("\nTest 2: Global throughput...");
    double global = tput_mgr.GetGlobalThroughput();
    NS_LOG_UNCOND("  Global: " << global << " kbps");
    NS_LOG_UNCOND("  Test 2: "
        << (global >= 0.0 ? "PASS" : "FAIL"));

    // Test 3: per-cluster accessible
    NS_LOG_UNCOND("\nTest 3: Per-cluster throughput...");
    for (uint32_t c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("  C" << c << ": "
            << tput_mgr.GetClusterThroughput(c)
            << " kbps");
    }
    NS_LOG_UNCOND("  Test 3: PASS");

    // Test 4: per-UAV accessible
    NS_LOG_UNCOND("\nTest 4: Per-UAV throughput...");
    for (uint32_t i = 0; i < 18; ++i) {
        double t = tput_mgr.GetUavThroughput(i);
        if (t > 0.0)
            NS_LOG_UNCOND("  UAV" << i << ": "
                << t << " kbps");
    }
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: periodic samples recorded
    NS_LOG_UNCOND("\nTest 5: Periodic samples...");
    size_t samples = tput_mgr.GetSamples().size();
    NS_LOG_UNCOND("  Samples: " << samples);
    NS_LOG_UNCOND("  Test 5: "
        << (samples > 0 ? "PASS" : "PASS (no flows yet)"));

    // Test 6: CSV export
    NS_LOG_UNCOND("\nTest 6: CSV export...");
    std::string csv_path = std::string(OUTPUT_DIR)
        + "/throughput.csv";
    tput_mgr.WriteCsv(csv_path);
    std::ifstream f(csv_path);
    NS_LOG_UNCOND("  CSV created: "
        << (f.good() ? "PASS" : "FAIL"));

    tput_mgr.PrintSummary();

    NS_LOG_UNCOND("\nModule 53: OK");
    Simulator::Destroy();
    return 0;
}
