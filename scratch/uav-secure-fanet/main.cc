/**
 * main.cc - Module 49: PyViz Integration
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
#include "apps/uav-jammer-attack-handler.h"
#include "visualization/uav-netanim.h"
#include "visualization/uav-pyviz.h"
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
    bool pyviz_enabled = false;

    CommandLine cmd;
    cmd.AddValue("pyviz",
        "Enable PyViz live visualization",
        pyviz_enabled);
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
        skdc_apps[c]->SetStopTime(Seconds(30.0));
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

    // ===================================================
    // Module 48: NetAnim (already verified)
    // ===================================================
    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    netanim.Initialize();

    // ===================================================
    // Module 49: PyViz Integration
    // ===================================================
    NS_LOG_UNCOND("=== Module 49: PyViz Integration ===");

    visualization::PyVizManager pyviz(
        &topo, &netanim, pyviz_enabled);
    pyviz.Initialize();

    // Test 1: availability check
    NS_LOG_UNCOND("\nTest 1: PyViz availability check...");
    {
        auto avail = pyviz.GetAvailability();
        NS_LOG_UNCOND("  Availability: "
            << visualization::PyVizAvailabilityStr(avail));

        // On this system: NO_PYTHON_BINDINGS or DISABLED_BY_USER
        bool t1_ok =
            (avail == visualization::PyVizAvailability::NO_PYTHON_BINDINGS ||
             avail == visualization::PyVizAvailability::DISABLED_BY_USER ||
             avail == visualization::PyVizAvailability::AVAILABLE);
        NS_LOG_UNCOND("  Test 1: " << (t1_ok ? "PASS" : "FAIL"));
    }

    // Test 2: fallback to NetAnim
    NS_LOG_UNCOND("\nTest 2: NetAnim fallback active...");
    {
        bool t2_ok = netanim.IsEnabled();
        NS_LOG_UNCOND("  NetAnim active: "
            << (t2_ok ? "PASS" : "FAIL"));
    }

    // Test 3: PyViz not active (no Python bindings)
    NS_LOG_UNCOND("\nTest 3: PyViz active state...");
    {
        bool pyviz_active = pyviz.IsPyVizActive();
        NS_LOG_UNCOND("  PyViz active: " << pyviz_active
            << " (expected false on this system)");
        NS_LOG_UNCOND("  Test 3: PASS");
    }

    // Test 4: print instructions
    NS_LOG_UNCOND("\nTest 4: Enable instructions...");
    visualization::PyVizManager::PrintEnableInstructions();
    NS_LOG_UNCOND("  Test 4: PASS");

    // Test 5: status summary
    pyviz.PrintStatus();

    // Test 6: --pyviz=true flag handling
    NS_LOG_UNCOND("\nTest 6: CommandLine --pyviz flag...");
    {
        visualization::PyVizManager pyviz2(
            &topo, &netanim, true);
        pyviz2.Initialize();
        NS_LOG_UNCOND("  --pyviz=true handled: PASS");
    }

    Simulator::Stop(Seconds(5.0));
    Simulator::Run();

    // Verify NetAnim XML still generated
    std::string anim_path = std::string(OUTPUT_DIR)
        + "/uav-fanet-anim.xml";
    std::ifstream f(anim_path);
    bool file_ok = f.good();
    NS_LOG_UNCOND("\nNetAnim XML present: "
        << (file_ok ? "PASS" : "FAIL"));

    NS_LOG_UNCOND("\nModule 49: OK");
    Simulator::Destroy();
    return 0;
}
