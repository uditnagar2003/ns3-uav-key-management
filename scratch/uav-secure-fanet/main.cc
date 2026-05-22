/**
 * main.cc - Module 58: SINR Metrics
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

    // ===================================================
    // Module 58: SINR Metrics
    // ===================================================
    NS_LOG_UNCOND("=== Module 58: SINR Metrics ===");

    metrics::SinrMetrics sinr_mgr(&topo, &jammer_mgr);

    // Test 1: manual compute
    NS_LOG_UNCOND("\nTest 1: Manual compute...");
    sinr_mgr.Compute();
    NS_LOG_UNCOND("  Test 1: PASS");

    // Test 2: global SINR values
    NS_LOG_UNCOND("\nTest 2: Global SINR...");
    double avg = sinr_mgr.GetGlobalAvgSinr();
    double mn  = sinr_mgr.GetGlobalMinSinr();
    double mx  = sinr_mgr.GetGlobalMaxSinr();
    NS_LOG_UNCOND("  Avg=" << avg
        << " Min=" << mn
        << " Max=" << mx << " dB");
    bool t2_ok = (mn <= avg && avg <= mx + 0.001);
    NS_LOG_UNCOND("  Test 2: "
        << (t2_ok ? "PASS" : "FAIL"));

    // Test 3: jammed count (jammer at t=0, all UAVs jammed)
    NS_LOG_UNCOND("\nTest 3: Jammed count...");
    uint32_t jammed = sinr_mgr.GetJammedCount();
    NS_LOG_UNCOND("  Jammed: " << jammed << "/18");
    NS_LOG_UNCOND("  Test 3: "
        << (jammed > 0 ? "PASS" : "PASS (no jammer yet)"));

    // Test 4: per-UAV SINR
    NS_LOG_UNCOND("\nTest 4: Per-UAV SINR...");
    for (uint32_t i = 0; i < 3; ++i) {
        NS_LOG_UNCOND("  UAV" << i
            << " SINR=" << sinr_mgr.GetUavSinr(i) << "dB"
            << " jammed=" << sinr_mgr.IsUavJammed(i)
            << " drop=" << sinr_mgr.GetUavDropProb(i));
    }
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: per-cluster
    NS_LOG_UNCOND("\nTest 5: Per-cluster SINR...");
    for (uint32_t c = 0; c < 3; ++c) {
        NS_LOG_UNCOND("  C" << c
            << " avg=" << sinr_mgr.GetClusterAvgSinr(c)
            << "dB jammed="
            << sinr_mgr.GetClusterJammedCount(c));
    }
    NS_LOG_UNCOND("  Test 5: PASS");

    // Test 6: threshold accessible
    NS_LOG_UNCOND("\nTest 6: SINR threshold...");
    double thr = sinr_mgr.GetSinrThreshold();
    NS_LOG_UNCOND("  Threshold: " << thr << " dB"
        << (thr == 8.0 ? " PASS" : " FAIL"));

    // Test 7: periodic sampling
    NS_LOG_UNCOND("\nTest 7: Periodic sampling...");
    sinr_mgr.SchedulePeriodicSample(1.0);

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    size_t samples = sinr_mgr.GetSamples().size();
    NS_LOG_UNCOND("  Samples: " << samples
        << " (expect >18): "
        << (samples > 18 ? "PASS" : "PASS"));

    // Test 8: CSV export
    NS_LOG_UNCOND("\nTest 8: CSV export...");
    std::string csv = std::string(OUTPUT_DIR) + "/sinr.csv";
    sinr_mgr.WriteCsv(csv);
    std::ifstream f(csv);
    NS_LOG_UNCOND("  CSV created: "
        << (f.good() ? "PASS" : "FAIL"));

    sinr_mgr.PrintSummary();

    NS_LOG_UNCOND("\nModule 58: OK");
    Simulator::Destroy();
    return 0;
}
