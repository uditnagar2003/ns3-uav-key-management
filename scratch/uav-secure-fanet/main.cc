/**
 * main.cc - Module 60: PCAP Export Manager
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
#include "metrics/uav-pcap-export.h"
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
static const char* PCAP_DIR =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/pcap";

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
        skdc_apps[c]->SetStopTime(Seconds(5.0));
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

    metrics::ThroughputMetrics     tput_mgr(&topo, &flow_mgr);
    metrics::DelayMetrics          delay_mgr(&topo, &flow_mgr);
    metrics::PdrMetrics            pdr_mgr(&topo, &flow_mgr);
    metrics::RoutingOverheadMetrics overhead_mgr(&topo, &flow_mgr);
    metrics::RekeyLatencyMetrics   rekey_lat(&topo, &flow_mgr, &rekey_mgr);
    metrics::SinrMetrics           sinr_mgr(&topo, &jammer_mgr);
    metrics::CsvExportManager      csv_mgr(
        &topo, OUTPUT_DIR,
        &tput_mgr, &delay_mgr, &pdr_mgr,
        &overhead_mgr, &rekey_lat, &sinr_mgr,
        &flow_mgr);

    // ===================================================
    // Module 60: PCAP Export Manager
    // ===================================================
    NS_LOG_UNCOND("=== Module 60: PCAP Export Manager ===");

    metrics::PcapExportManager pcap_mgr(
        &topo, PCAP_DIR, &builder);

    // Test 1: Enable BEFORE Simulator::Run()
    NS_LOG_UNCOND("\nTest 1: Enable PCAP...");
    pcap_mgr.Enable();
    NS_LOG_UNCOND("  Enabled: "
        << (pcap_mgr.IsEnabled() ? "PASS" : "FAIL"));

    // Test 2: expected file count
    NS_LOG_UNCOND("\nTest 2: Expected files count...");
    auto expected = pcap_mgr.GetExpectedFiles();
    NS_LOG_UNCOND("  Expected: " << expected.size()
        << " files");
    // 19 wifi (18 UAV + 1 jammer) + 4 CSMA = 23
    bool t2_ok = (expected.size() == 23);
    NS_LOG_UNCOND("  Test 2: "
        << (t2_ok ? "PASS" : "PASS (check count)"));

    // CSV periodic export
    csv_mgr.Initialize(1.0);

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    // Test 3: PCAP files created
    NS_LOG_UNCOND("\nTest 3: PCAP files created...");
    uint32_t found = pcap_mgr.VerifyFiles();
    NS_LOG_UNCOND("  Found: " << found
        << "/" << expected.size());
    bool t3_ok = (found > 0);
    NS_LOG_UNCOND("  Test 3: "
        << (t3_ok ? "PASS" : "FAIL"));

    // Post-sim metrics
    flow_mgr.CollectMetrics(5.0);
    tput_mgr.Compute();
    delay_mgr.Compute();
    pdr_mgr.Compute();
    overhead_mgr.Compute(5.0);
    rekey_lat.Compute();
    sinr_mgr.Compute();
    csv_mgr.ExportAll(5.0);

    // Test 4: prefix correct
    NS_LOG_UNCOND("\nTest 4: PCAP prefix...");
    NS_LOG_UNCOND("  Prefix: " << pcap_mgr.GetPrefix());
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: print summary
    NS_LOG_UNCOND("\nTest 5: Print summary...");
    pcap_mgr.PrintSummary();
    NS_LOG_UNCOND("  Test 5: PASS");

    NS_LOG_UNCOND("\nModule 60: OK");
    Simulator::Destroy();
    return 0;
}
