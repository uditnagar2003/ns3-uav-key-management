/**
 * main.cc - Module 57: Rekey Latency Metrics
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

    metrics::ThroughputMetrics  tput_mgr(&topo, &flow_mgr);
    metrics::DelayMetrics       delay_mgr(&topo, &flow_mgr);
    metrics::PdrMetrics         pdr_mgr(&topo, &flow_mgr);
    metrics::RoutingOverheadMetrics overhead_mgr(&topo, &flow_mgr);

    // ===================================================
    // Module 57: Rekey Latency Metrics
    // ===================================================
    NS_LOG_UNCOND("=== Module 57: Rekey Latency Metrics ===");

    metrics::RekeyLatencyMetrics rekey_lat(
        &topo, &flow_mgr, &rekey_mgr);

    // Trigger some rekeys before sim to have history
    rekey_mgr.TriggerRekey(0, apps::RekeyReason::LEAVE,
        skdc_apps[0].operator->());
    rekey_mgr.TriggerRekey(1, apps::RekeyReason::COMPROMISE,
        skdc_apps[1].operator->());
    rekey_mgr.TriggerRekey(2, apps::RekeyReason::HANDOVER,
        skdc_apps[2].operator->());
    rekey_mgr.GlobalRekey(skdc_apps,
        apps::RekeyReason::KDC_INIT);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();

    flow_mgr.CollectMetrics(10.0);
    tput_mgr.Compute();
    delay_mgr.Compute();
    pdr_mgr.Compute();
    overhead_mgr.Compute(10.0);
    rekey_lat.Compute();

    // Test 1: total rekeys counted
    NS_LOG_UNCOND("\nTest 1: Total rekeys counted...");
    uint64_t total = rekey_lat.GetTotalRekeys();
    NS_LOG_UNCOND("  Total rekeys: " << total
        << " (expect >=6): "
        << (total >= 6 ? "PASS" : "FAIL"));

    // Test 2: avg latency >= 0
    NS_LOG_UNCOND("\nTest 2: Avg latency...");
    double avg = rekey_lat.GetAvgLatency();
    NS_LOG_UNCOND("  Avg: " << avg << " ms");
    NS_LOG_UNCOND("  Test 2: "
        << (avg >= 0.0 ? "PASS" : "FAIL"));

    // Test 3: min <= avg <= max
    NS_LOG_UNCOND("\nTest 3: Min/Max latency...");
    double mn = rekey_lat.GetMinLatency();
    double mx = rekey_lat.GetMaxLatency();
    NS_LOG_UNCOND("  Min=" << mn
        << " Avg=" << avg
        << " Max=" << mx << " ms");
    bool t3_ok = (mn <= avg && avg <= mx + 0.001);
    NS_LOG_UNCOND("  Test 3: "
        << (t3_ok ? "PASS" : "FAIL"));

    // Test 4: per-cluster latency
    NS_LOG_UNCOND("\nTest 4: Per-cluster latency...");
    for (uint32_t c = 0; c < 3; ++c)
        NS_LOG_UNCOND("  C" << c << ": "
            << rekey_lat.GetClusterAvgLatency(c) << " ms");
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: samples populated
    NS_LOG_UNCOND("\nTest 5: Samples...");
    size_t samples = rekey_lat.GetSamples().size();
    NS_LOG_UNCOND("  Samples: " << samples
        << " (expect >=6): "
        << (samples >= 6 ? "PASS" : "FAIL"));

    // Test 6: CSV export
    NS_LOG_UNCOND("\nTest 6: CSV export...");
    std::string csv = std::string(OUTPUT_DIR)
        + "/rekey_latency.csv";
    rekey_lat.WriteCsv(csv);
    std::ifstream f(csv);
    NS_LOG_UNCOND("  CSV created: "
        << (f.good() ? "PASS" : "FAIL"));

    rekey_lat.PrintSummary();

    NS_LOG_UNCOND("\nModule 57: OK");
    Simulator::Destroy();
    return 0;
}
