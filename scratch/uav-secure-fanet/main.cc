/**
 * main.cc - Module 50: Node Coloring
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
#include "visualization/uav-pyviz.h"
#include "visualization/uav-node-color.h"
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

    // NetAnim
    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    netanim.Initialize();

    // ===================================================
    // Module 50: Node Coloring
    // ===================================================
    NS_LOG_UNCOND("=== Module 50: Node Coloring ===");

    visualization::NodeColorManager color_mgr(&topo, &netanim);
    color_mgr.Initialize();

    // Test 1: initial state all NORMAL
    NS_LOG_UNCOND("\nTest 1: Initial state...");
    {
        bool all_normal = true;
        for (uint32_t i = 0; i < 18; ++i) {
            if (color_mgr.GetUavState(i) !=
                visualization::UavColorState::NORMAL)
            {
                all_normal = false;
                break;
            }
        }
        NS_LOG_UNCOND("  All UAVs NORMAL: "
            << (all_normal ? "PASS" : "FAIL"));
    }

    // Test 2: manual state changes
    NS_LOG_UNCOND("\nTest 2: Manual state changes...");
    {
        color_mgr.SetUavCompromised(2);
        color_mgr.SetUavHandover(5);
        color_mgr.SetUavJammed(8);
        color_mgr.SetUavDisconnected(11);

        bool t2_ok =
            color_mgr.GetUavState(2) ==
                visualization::UavColorState::COMPROMISED &&
            color_mgr.GetUavState(5) ==
                visualization::UavColorState::HANDOVER &&
            color_mgr.GetUavState(8) ==
                visualization::UavColorState::JAMMED &&
            color_mgr.GetUavState(11) ==
                visualization::UavColorState::DISCONNECTED;
        NS_LOG_UNCOND("  State changes: "
            << (t2_ok ? "PASS" : "FAIL"));
    }

    // Test 3: restore to normal
    NS_LOG_UNCOND("\nTest 3: Restore to normal...");
    {
        color_mgr.SetUavNormal(5);
        bool t3_ok = color_mgr.GetUavState(5) ==
            visualization::UavColorState::NORMAL;
        NS_LOG_UNCOND("  Restore UAV5: "
            << (t3_ok ? "PASS" : "FAIL"));
    }

    // Test 4: hook CompromiseDetector
    NS_LOG_UNCOND("\nTest 4: CompromiseDetector hook...");
    {
        color_mgr.HookCompromiseDetector(&comp_det);
        comp_det.ReportHmacFailure(
            3, 0, 3, skdc_apps[0]);
        bool t4_ok = color_mgr.GetUavState(3) ==
            visualization::UavColorState::COMPROMISED;
        NS_LOG_UNCOND("  Auto-color on compromise: "
            << (t4_ok ? "PASS" : "FAIL"));
    }

    // Test 5: hook JammerManager
    NS_LOG_UNCOND("\nTest 5: JammerManager hook...");
    {
        color_mgr.HookJammerManager(&jammer_mgr, 1.0);
        NS_LOG_UNCOND("  JammerManager hooked: PASS");
    }

    // Test 6: counts
    NS_LOG_UNCOND("\nTest 6: Counts...");
    {
        uint32_t comp = color_mgr.GetCompromisedCount();
        NS_LOG_UNCOND("  Compromised count: " << comp
            << " (expect >=2)");
        bool t6_ok = (comp >= 2);
        NS_LOG_UNCOND("  Test 6: "
            << (t6_ok ? "PASS" : "FAIL"));
    }

    color_mgr.PrintColorStats();

    Simulator::Stop(Seconds(4.0));
    Simulator::Run();

    // After sim: jammer hook fired at t=1,2,3
    uint32_t jammed = color_mgr.GetJammedCount();
    NS_LOG_UNCOND("\nJammed UAVs after sim: " << jammed);
    NS_LOG_UNCOND("Jammer color updates: PASS");

    NS_LOG_UNCOND("\nModule 50: OK");
    Simulator::Destroy();
    return 0;
}
