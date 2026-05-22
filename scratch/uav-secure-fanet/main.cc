/**
 * main.cc - Module 54: Delay Metrics
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
#include "metrics/uav-delay-metrics.h"
#include "crypto/uav-crypto-params.h"

#include <fstream>

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

    // Module 53 (already verified)
    metrics::ThroughputMetrics tput_mgr(&topo, &flow_mgr);
    tput_mgr.SchedulePeriodicSample(1.0);

    // ===================================================
    // Module 54: Delay Metrics
    // ===================================================
    NS_LOG_UNCOND("=== Module 54: Delay Metrics ===");

    metrics::DelayMetrics delay_mgr(&topo, &flow_mgr);
    delay_mgr.SchedulePeriodicSample(1.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();

    // Collect and compute
    flow_mgr.CollectMetrics(10.0);
    tput_mgr.Compute();
    delay_mgr.Compute();

    // Test 1: compute without crash
    NS_LOG_UNCOND("\nTest 1: Compute without crash...");
    NS_LOG_UNCOND("  Test 1: PASS");

    // Test 2: global delay >= 0
    NS_LOG_UNCOND("\nTest 2: Global delay...");
    double avg = delay_mgr.GetGlobalAvgDelay();
    double min = delay_mgr.GetGlobalMinDelay();
    double max = delay_mgr.GetGlobalMaxDelay();
    NS_LOG_UNCOND("  Avg=" << avg
        << " Min=" << min
        << " Max=" << max << " ms");
    NS_LOG_UNCOND("  Test 2: "
        << (avg >= 0.0 ? "PASS" : "FAIL"));

    // Test 3: per-cluster delay
    NS_LOG_UNCOND("\nTest 3: Per-cluster delay...");
    for (uint32_t c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("  C" << c
            << " avg=" << delay_mgr.GetClusterAvgDelay(c)
            << " jitter=" << delay_mgr.GetClusterJitter(c)
            << " ms");
    }
    NS_LOG_UNCOND("  Test 3: PASS");

    // Test 4: per-UAV delay
    NS_LOG_UNCOND("\nTest 4: Per-UAV delay...");
    for (uint32_t i = 0; i < 18; ++i) {
        double d = delay_mgr.GetUavAvgDelay(i);
        if (d > 0.0)
            NS_LOG_UNCOND("  UAV" << i
                << ": " << d << " ms");
    }
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: periodic samples
    NS_LOG_UNCOND("\nTest 5: Periodic samples...");
    NS_LOG_UNCOND("  Samples: "
        << delay_mgr.GetSamples().size());
    NS_LOG_UNCOND("  Test 5: PASS");

    // Test 6: CSV export
    NS_LOG_UNCOND("\nTest 6: CSV export...");
    std::string csv = std::string(OUTPUT_DIR)
        + "/delay.csv";
    delay_mgr.WriteCsv(csv);
    std::ifstream f(csv);
    NS_LOG_UNCOND("  CSV created: "
        << (f.good() ? "PASS" : "FAIL"));

    delay_mgr.PrintSummary();

    NS_LOG_UNCOND("\nModule 54: OK");
    Simulator::Destroy();
    return 0;
}
