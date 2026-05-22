/**
 * main.cc - Module 59: CSV Export Manager
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
#include "metrics/uav-pdr-metrics.h"
#include "metrics/uav-routing-overhead.h"
#include "metrics/uav-rekey-latency.h"
#include "metrics/uav-sinr-metrics.h"
#include "metrics/uav-csv-export.h"
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
    apps::JammerManager jammer_mgr(&topo, &jammer_mob);

    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    netanim.Initialize();

    // All metrics
    metrics::ThroughputMetrics     tput_mgr(&topo, &flow_mgr);
    metrics::DelayMetrics          delay_mgr(&topo, &flow_mgr);
    metrics::PdrMetrics            pdr_mgr(&topo, &flow_mgr);
    metrics::RoutingOverheadMetrics overhead_mgr(&topo, &flow_mgr);
    metrics::RekeyLatencyMetrics   rekey_lat(&topo, &flow_mgr, &rekey_mgr);
    metrics::SinrMetrics           sinr_mgr(&topo, &jammer_mgr);

    // Trigger rekeys for history
    rekey_mgr.TriggerRekey(0, apps::RekeyReason::LEAVE,
        skdc_apps[0].operator->());
    rekey_mgr.GlobalRekey(skdc_apps,
        apps::RekeyReason::KDC_INIT);

    // ===================================================
    // Module 59: CSV Export Manager
    // ===================================================
    NS_LOG_UNCOND("=== Module 59: CSV Export Manager ===");

    metrics::CsvExportManager csv_mgr(
        &topo, OUTPUT_DIR,
        &tput_mgr, &delay_mgr, &pdr_mgr,
        &overhead_mgr, &rekey_lat, &sinr_mgr,
        &flow_mgr);

    // Initialize with 1s interval per spec
    csv_mgr.Initialize(1.0);

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    // Post-sim: collect and compute all metrics
    flow_mgr.CollectMetrics(5.0);
    tput_mgr.Compute();
    delay_mgr.Compute();
    pdr_mgr.Compute();
    overhead_mgr.Compute(5.0);
    rekey_lat.Compute();
    sinr_mgr.Compute();

    // Export all
    csv_mgr.ExportAll(5.0);

    // Test 1: all CSV files created
    NS_LOG_UNCOND("\nTest 1: CSV files created...");
    std::vector<std::string> files = {
        "throughput.csv", "delay.csv", "pdr.csv",
        "routing_overhead.csv", "rekey_latency.csv",
        "sinr.csv", "metrics_global.csv",
        "metrics_per_cluster.csv", "metrics_per_uav.csv"
    };
    int ok_count = 0;
    for (const auto& fn : files) {
        std::string path = std::string(OUTPUT_DIR) + "/" + fn;
        std::ifstream f(path);
        bool ok = f.good();
        NS_LOG_UNCOND("  " << fn << ": "
            << (ok ? "PASS" : "FAIL"));
        if (ok) ++ok_count;
    }
    NS_LOG_UNCOND("  Files created: " << ok_count
        << "/" << files.size() << ": "
        << (ok_count == (int)files.size()
            ? "PASS" : "FAIL"));

    // Test 2: total exports
    NS_LOG_UNCOND("\nTest 2: Total exports...");
    NS_LOG_UNCOND("  Total: "
        << csv_mgr.GetTotalExports()
        << " (expect 9): "
        << (csv_mgr.GetTotalExports() == 9
            ? "PASS" : "FAIL"));

    // Test 3: metrics_global.csv has correct fields
    NS_LOG_UNCOND("\nTest 3: metrics_global.csv content...");
    {
        std::ifstream f(std::string(OUTPUT_DIR)
            + "/metrics_global.csv");
        std::string line;
        int lines = 0;
        while (std::getline(f, line)) ++lines;
        NS_LOG_UNCOND("  Lines: " << lines
            << " (expect >=15): "
            << (lines >= 15 ? "PASS" : "FAIL"));
    }

    // Test 4: metrics_per_uav.csv has 19 lines (header + 18)
    NS_LOG_UNCOND("\nTest 4: metrics_per_uav.csv rows...");
    {
        std::ifstream f(std::string(OUTPUT_DIR)
            + "/metrics_per_uav.csv");
        std::string line;
        int lines = 0;
        while (std::getline(f, line)) ++lines;
        NS_LOG_UNCOND("  Lines: " << lines
            << " (expect 19): "
            << (lines == 19 ? "PASS" : "FAIL"));
    }

    // Test 5: metrics_per_cluster.csv has 4 lines
    NS_LOG_UNCOND("\nTest 5: metrics_per_cluster.csv rows...");
    {
        std::ifstream f(std::string(OUTPUT_DIR)
            + "/metrics_per_cluster.csv");
        std::string line;
        int lines = 0;
        while (std::getline(f, line)) ++lines;
        NS_LOG_UNCOND("  Lines: " << lines
            << " (expect 4): "
            << (lines == 4 ? "PASS" : "FAIL"));
    }

    NS_LOG_UNCOND("\nModule 59: OK");
    Simulator::Destroy();
    return 0;
}
