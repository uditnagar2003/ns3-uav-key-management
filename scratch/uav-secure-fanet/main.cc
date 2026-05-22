/**
 * main.cc - Module 46: Rekey Event Logic
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
#include "apps/uav-rekey-manager.h"
#include "crypto/uav-crypto-params.h"

NS_LOG_COMPONENT_DEFINE("UavSecureFanet");
using namespace ns3;
using namespace uav;

static const char* CRYPTO_JSON =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/json/crypto_params.json";

int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    OpenSSLInit::Bootstrap();
    log::Logger::Instance().Initialize(
        "logs", log::LogLevel::INFO, true);

    crypto::CryptoParamsFile params =
        crypto::CryptoParamsLoader::LoadFromFile(
            CRYPTO_JSON);

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
        skdc_apps[c] = CreateObject<apps::SkdcApplication>();
        skdc_apps[c]->SetClusterId(c);
        skdc_apps[c]->SetTopology(&topo);
        skdc_apps[c]->SetCryptoParams(&params);
        topo.skdc_nodes.Get(c)->AddApplication(skdc_apps[c]);
        skdc_apps[c]->SetStartTime(Seconds(1.0));
        skdc_apps[c]->SetStopTime(Seconds(20.0));
    }

    apps::TekManager tek_mgr(&params);
    tek_mgr.Initialize();
    apps::MulticastManager mc_mgr(&topo, &params);
    mc_mgr.Initialize();
    apps::MtkDistributionManager dist_mgr(
        &topo, &params, &tek_mgr, &mc_mgr);

    NS_LOG_UNCOND("=== Module 46: Rekey Event Logic ===");

    apps::RekeyManager rekey_mgr(
        &topo, &params, &tek_mgr, &dist_mgr, &mc_mgr);

    rekey_mgr.SetRekeyCallback([](const apps::RekeyEvent& ev) {
        NS_LOG_UNCOND("  [REKEY] C" << ev.cluster_id
            << " " << apps::RekeyReasonStr(ev.reason)
            << " v" << ev.old_version
            << "->" << ev.new_version
            << " ok=" << ev.success);
    });

    // Test 1: Leave rekey C0
    NS_LOG_UNCOND("\nTest 1: Leave rekey C0...");
    uint32_t v0 = tek_mgr.GetVersion(0);
    bool ok1 = rekey_mgr.TriggerRekey(
        0, apps::RekeyReason::LEAVE,
        skdc_apps[0].operator->());
    NS_LOG_UNCOND("  v" << v0 << "->"
        << tek_mgr.GetVersion(0)
        << " " << (ok1 ? "PASS" : "FAIL"));

    // Test 2: Compromise rekey C1
    NS_LOG_UNCOND("\nTest 2: Compromise rekey C1...");
    bool ok2 = rekey_mgr.TriggerRekey(
        1, apps::RekeyReason::COMPROMISE,
        skdc_apps[1].operator->());
    NS_LOG_UNCOND("  C1 v" << tek_mgr.GetVersion(1)
        << " " << (ok2 ? "PASS" : "FAIL"));

    // Test 3: Global KDC rekey
    NS_LOG_UNCOND("\nTest 3: Global KDC rekey...");
    rekey_mgr.GlobalRekey(skdc_apps, apps::RekeyReason::KDC_INIT);
    for (uint32_t c = 0; c < 3; ++c)
        NS_LOG_UNCOND("  C" << c << " v" << tek_mgr.GetVersion(c));

    // Test 4: TEK derivation
    NS_LOG_UNCOND("\nTest 4: TEK derivation...");
    auto old_tek = crypto::AesGcm::GenerateKey();
    utils::Nonce128 nonce;
    nonce.fill(0);
    RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));
    auto new_tek = rekey_mgr.DeriveTek(
        old_tek, utils::TimeUtils::NowEpochMicros(), nonce);
    NS_LOG_UNCOND("  TEK changed: "
        << (old_tek != new_tek ? "PASS" : "FAIL"));

    // Test 5: Periodic schedule
    NS_LOG_UNCOND("\nTest 5: Periodic C2 (2s)...");
    rekey_mgr.SchedulePeriodic(2, skdc_apps[2], 2.0);

    rekey_mgr.PrintRekeyStats();

    bool stats_ok = (rekey_mgr.GetTotalRekeys() == 5)
        && (rekey_mgr.GetRekeyCount(0) >= 2)
        && (rekey_mgr.GetRekeyCount(1) >= 2);
    NS_LOG_UNCOND("\nRekey stats: "
        << (stats_ok ? "PASS" : "FAIL"));

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    NS_LOG_UNCOND("\nTotal rekeys after sim: "
        << rekey_mgr.GetTotalRekeys());
    NS_LOG_UNCOND("\nModule 46: OK");
    Simulator::Destroy();
    return 0;
}
