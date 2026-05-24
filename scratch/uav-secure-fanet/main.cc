/**
 * main.cc - Module 61: Final Integration
 *
 * FULL 300-second simulation integrating ALL modules:
 *   - 1 KDC + 3 SKDCs + 18 UAVs + 1 Jammer
 *   - CRT/GCRT multicast key management
 *   - AES-256 payload encryption
 *   - HMAC-SHA256 integrity
 *   - OLSR routing
 *   - GaussMarkov 3D mobility
 *   - Jammer attack handling
 *   - Join/Leave/Rekey/Handover security events
 *   - NetAnim visualization
 *   - FlowMonitor metrics
 *   - PCAP traces
 *   - CSV exports every 1 second
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/gauss-markov-mobility-model.h"

#include "crypto/uav-openssl-ctx.h"
#include "crypto/uav-crypto-params.h"

#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "routing/uav-topology.h"
#include "routing/uav-queue-manager.h"
#include "routing/uav-flowmonitor.h"
#include "routing/uav-csma-backbone.h"
#include "routing/uav-olsr-manager.h"

#include "mobility/uav-mobility-manager.h"
#include "mobility/uav-jammer-mobility.h"
#include "mobility/uav-cluster-movement.h"

#include "apps/uav-kdc-app.h"
#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-join-event.h"
#include "apps/uav-leave-event.h"
#include "apps/uav-rekey-manager.h"
#include "apps/uav-handover-manager.h"
#include "apps/uav-compromise-detector.h"
#include "apps/uav-jammer-manager.h"
#include "apps/uav-jammer-attack-handler.h"

#include "visualization/uav-netanim.h"
#include "visualization/uav-pyviz.h"
#include "visualization/uav-node-color.h"
#include "visualization/uav-packet-viz.h"
#include "visualization/uav-event-annotations.h"

#include "metrics/uav-throughput-metrics.h"
#include "metrics/uav-delay-metrics.h"
#include "metrics/uav-pdr-metrics.h"
#include "metrics/uav-routing-overhead.h"
#include "metrics/uav-rekey-latency.h"
#include "metrics/uav-sinr-metrics.h"
#include "metrics/uav-csv-export.h"
#include "metrics/uav-pcap-export.h"

#include "scenario/rekey_perf_scenario.h"

#include <fstream>
#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavSecureFanet");
using namespace ns3;
using namespace uav;

// ===========================================================================
// Paths
// ===========================================================================
static const char* CRYPTO_JSON =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/json/crypto_params.json";
static const char* OUTPUT_DIR =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/output";
static const char* PCAP_DIR =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/pcap";
static const char* LOG_DIR =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/logs";

// ===========================================================================
// Simulation parameters
// ===========================================================================
static constexpr double SIM_DURATION_S   = 300.0;  // 5 minutes
static constexpr uint32_t RNG_SEED       = 42;
static constexpr uint32_t NUM_UAVS       = 18;
static constexpr uint32_t NUM_CLUSTERS   = 3;
static constexpr uint32_t UAVS_PER_CLUSTER = 6;

// ===========================================================================
// Scheduled security events (injected during simulation)
// ===========================================================================

// Leave event: UAV 3 leaves C0 at t=30s
static void ScheduledLeave(
    apps::LeaveEventManager*                      leave_mgr,
    apps::RekeyManager*                           rekey_mgr,
    std::array<Ptr<apps::SkdcApplication>, 3>*    skdc_apps,
    visualization::NodeColorManager*              color_mgr,
    visualization::PacketVizManager*              pkt_viz,
    visualization::EventAnnotationManager*        evt_ann)
{
    NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds()
        << "s] LEAVE EVENT: UAV3 leaving C0");
    leave_mgr->ProcessLeave(3, 3, 0,
        (*skdc_apps)[0].operator->());
    pkt_viz->OnRekeyBroadcast(0, 0);
    evt_ann->OnLeave(3);
    evt_ann->OnRekey(0);
}

// Handover: UAV5 C0→C1 at t=60s
static void ScheduledHandover(
    apps::HandoverManager*                        ho_mgr,
    std::array<Ptr<apps::SkdcApplication>, 3>*    skdc_apps,
    visualization::NodeColorManager*              color_mgr,
    visualization::PacketVizManager*              pkt_viz,
    visualization::EventAnnotationManager*        evt_ann)
{
    NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds()
        << "s] HANDOVER: UAV5 C0→C1");
    color_mgr->SetUavHandover(5);
    ho_mgr->ProcessHandover(5, 5, 0, 1, *skdc_apps);
    color_mgr->SetUavNormal(5);
    pkt_viz->OnHandover(5, 0, 1);
    evt_ann->OnHandover(5);
    evt_ann->OnRekey(0);
    evt_ann->OnRekey(1);
}

// Join: UAV 19 (new) joins C2 at t=90s
static void ScheduledJoin(
    apps::JoinEventManager*                       join_mgr,
    std::array<Ptr<apps::SkdcApplication>, 3>*    skdc_apps,
    visualization::PacketVizManager*              pkt_viz,
    visualization::EventAnnotationManager*        evt_ann)
{
    NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds()
        << "s] JOIN: UAV6 rejoining C2");
    join_mgr->ProcessJoin(6, 0, 2,
        (*skdc_apps)[2].operator->(), nullptr);
    pkt_viz->OnJoinRequest(6, 2);
    pkt_viz->OnMtkBroadcast(2, 2, 1);
    evt_ann->OnJoin(6);
}

// Global rekey at t=150s
static void ScheduledGlobalRekey(
    apps::RekeyManager*                           rekey_mgr,
    std::array<Ptr<apps::SkdcApplication>, 3>*    skdc_apps,
    visualization::PacketVizManager*              pkt_viz,
    visualization::EventAnnotationManager*        evt_ann)
{
    NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds()
        << "s] GLOBAL REKEY: KDC-initiated");
    rekey_mgr->GlobalRekey(*skdc_apps,
        apps::RekeyReason::KDC_INIT);
    for (uint32_t c = 0; c < 3; ++c) {
        pkt_viz->OnRekeyBroadcast(c, c);
        evt_ann->OnRekey(c);
        evt_ann->OnTekRotation(c);
    }
}

// ===========================================================================
// main
// ===========================================================================

// ===========================================================================
// Automatic handover detection — called every 5s
// Tracks current cluster per UAV independently of m_original_cluster
// so same UAV can handover multiple times during simulation
// ===========================================================================

// Per-UAV current cluster assignment (updated after each handover)
static std::array<utils::u32, 18> g_uav_current_cluster = {
    0,0,0,0,0,0,   // C0: UAV 0-5
    1,1,1,1,1,1,   // C1: UAV 6-11
    2,2,2,2,2,2    // C2: UAV 12-17
};

static void AutoHandoverCheck(
    mobility::MobilityManager*                    mob_mgr,
    apps::HandoverManager*                        ho_mgr,
    std::array<Ptr<apps::SkdcApplication>, 3>*    skdc_apps,
    visualization::NodeColorManager*              color_mgr,
    visualization::PacketVizManager*              pkt_viz,
    visualization::EventAnnotationManager*        evt_ann,
    double                                        interval_s)
{
    double now = Simulator::Now().GetSeconds();

    for (uint32_t i = 0; i < 18; ++i) {
        utils::u32 current_cluster = g_uav_current_cluster[i];
        utils::u32 nearest_cluster =
            mob_mgr->GetNearestCluster(i);

        if (nearest_cluster != current_cluster) {
            NS_LOG_UNCOND("[t=" << now
                << "s] AUTO-HANDOVER: UAV" << i
                << " C" << current_cluster
                << "→C" << nearest_cluster);

            color_mgr->SetUavHandover(i);
            bool ok = ho_mgr->ProcessHandover(
                i, i % 6,
                current_cluster, nearest_cluster,
                *skdc_apps);

            if (ok) {
                // Update our tracking
                g_uav_current_cluster[i] = nearest_cluster;
                color_mgr->SetUavNormal(i);
                pkt_viz->OnHandover(
                    i, current_cluster, nearest_cluster);
                evt_ann->OnHandover(i);
                evt_ann->OnRekey(current_cluster);
                evt_ann->OnRekey(nearest_cluster);
            } else {
                color_mgr->SetUavNormal(i);
            }
        }
    }

    // Reschedule
    Simulator::Schedule(
        Seconds(interval_s),
        &AutoHandoverCheck,
        mob_mgr, ho_mgr, skdc_apps,
        color_mgr, pkt_viz, evt_ann,
        interval_s);
}

int main(int argc, char* argv[])
{
    // -----------------------------------------------------------------------
    // Command line
    // -----------------------------------------------------------------------
    uint32_t seed        = RNG_SEED;
    double   duration    = SIM_DURATION_S;
    bool     enable_pcap = true;
    bool     enable_anim = true;

    CommandLine cmd;
    cmd.AddValue("seed",     "RNG seed",            seed);
    cmd.AddValue("duration", "Sim duration (s)",    duration);
    cmd.AddValue("pcap",     "Enable PCAP",         enable_pcap);
    cmd.AddValue("anim",     "Enable NetAnim",       enable_anim);
    cmd.Parse(argc, argv);
     
    std::string scenario_name = "baseline";
    cmd.AddValue("scenario", "Scenario to run", scenario_name);
    
    if (scenario_name == "rekey_perf") {
    uav::scenario::RekeyPerfScenarioConfig cfg;
    uav::scenario::RekeyPerfScenario s(cfg);
    s.RunAll();
    return 0;
    }
    RngSeedManager::SetSeed(seed);

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------
    OpenSSLInit::Bootstrap();
    log::Logger::Instance().Initialize(
        LOG_DIR, log::LogLevel::INFO, true);

    NS_LOG_UNCOND("========================================");
    NS_LOG_UNCOND(" UAV Secure FANET — Final Simulation");
    NS_LOG_UNCOND(" Duration: " << duration << "s");
    NS_LOG_UNCOND(" Seed:     " << seed);
    NS_LOG_UNCOND(" UAVs:     " << NUM_UAVS);
    NS_LOG_UNCOND("========================================");

    // -----------------------------------------------------------------------
    // Crypto parameters
    // -----------------------------------------------------------------------
    crypto::CryptoParamsFile params =
        crypto::CryptoParamsLoader::LoadFromFile(CRYPTO_JSON);

    // -----------------------------------------------------------------------
    // Network topology
    // -----------------------------------------------------------------------
    routing::TopologyConfig cfg;
    routing::TopologyBuilder builder(cfg);
    routing::TopologyResult topo = builder.Build();

    routing::CsmaBackboneManager backbone(topo);
    backbone.ConfigureStaticRoutes();

    routing::QueueManager queue_mgr(topo);
    queue_mgr.ConfigureAll();

    routing::FlowMonitorManager flow_mgr(topo);
    flow_mgr.Install();

    // -----------------------------------------------------------------------
    // Mobility
    // -----------------------------------------------------------------------
    // Custom mobility config — lower alpha for more exploration
    // alpha=0.3 means UAVs change direction frequently
    // variance=8.0 means larger velocity perturbations
    // This enables natural handovers during 300s simulation
    mobility::MobilityConfig mob_cfg;
    mob_cfg.alpha              = 0.3;   // low memory = more random
    mob_cfg.mean_velocity      = 20.0;  // faster UAVs
    mob_cfg.variance           = 8.0;   // high velocity variance
    mob_cfg.formation_radius_m = 50.0;  // tighter initial formation
    mob_cfg.update_interval_s  = 0.5;
    mob_cfg.min_altitude_m     = 50.0;
    mob_cfg.max_altitude_m     = 150.0;
    mob_cfg.area_x_m           = 1500.0;
    mob_cfg.area_y_m           = 1500.0;

    mobility::MobilityManager mob_mgr(topo, mob_cfg);
    mob_mgr.InstallGaussMarkov();



    mobility::JammerMobilityManager jammer_mob(topo);
    jammer_mob.InstallRandomWaypoint(10.0, 10.0, seed);

    // -----------------------------------------------------------------------
    // Applications — KDC
    // -----------------------------------------------------------------------
    Ptr<apps::KdcApplication> kdc_app =
        CreateObject<apps::KdcApplication>();
    kdc_app->SetTopology(&topo);
    kdc_app->SetCryptoParams(&params);
    topo.kdc_node.Get(0)->AddApplication(kdc_app);
    kdc_app->SetStartTime(Seconds(0.5));
    kdc_app->SetStopTime(Seconds(duration));

    // -----------------------------------------------------------------------
    // Applications — SKDCs
    // -----------------------------------------------------------------------
    std::array<Ptr<apps::SkdcApplication>, 3> skdc_apps;
    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
        skdc_apps[c] = CreateObject<apps::SkdcApplication>();
        skdc_apps[c]->SetClusterId(c);
        skdc_apps[c]->SetTopology(&topo);
        skdc_apps[c]->SetCryptoParams(&params);
        topo.skdc_nodes.Get(c)->AddApplication(skdc_apps[c]);
        skdc_apps[c]->SetStartTime(Seconds(1.0));
        skdc_apps[c]->SetStopTime(Seconds(duration));
    }

    // -----------------------------------------------------------------------
    // Applications — UAVs
    // -----------------------------------------------------------------------
    for (uint32_t i = 0; i < NUM_UAVS; ++i) {
        Ptr<apps::UavApplication> uav_app =
            CreateObject<apps::UavApplication>();
        uav_app->SetUavId(i, i % UAVS_PER_CLUSTER,
                          i / UAVS_PER_CLUSTER);
        uav_app->SetTopology(&topo);
        uav_app->SetCryptoParams(&params);
        topo.uav_nodes.Get(i)->AddApplication(uav_app);
        uav_app->SetStartTime(Seconds(2.0));
        uav_app->SetStopTime(Seconds(duration));
    }

    // -----------------------------------------------------------------------
    // Security managers
    // -----------------------------------------------------------------------
    apps::TekManager tek_mgr(&params);
    tek_mgr.Initialize();

    apps::MulticastManager mc_mgr(&topo, &params);
    mc_mgr.Initialize();

    apps::MtkDistributionManager dist_mgr(
        &topo, &params, &tek_mgr, &mc_mgr);

    apps::JoinEventManager join_mgr(
        &topo, &params, &mc_mgr, &dist_mgr, &tek_mgr);

    apps::LeaveEventManager leave_mgr(
        &topo, &params, &mc_mgr, &dist_mgr, &tek_mgr);

    apps::RekeyManager rekey_mgr(
        &topo, &params, &tek_mgr, &dist_mgr, &mc_mgr);

    apps::HandoverManager ho_mgr(
        &topo, &params, &mc_mgr, &dist_mgr, &tek_mgr,
        &join_mgr, &leave_mgr);

    apps::CompromiseDetector comp_det(
        &topo, &mc_mgr, &dist_mgr, &tek_mgr, &leave_mgr);

    apps::JammerManager jammer_mgr(&topo, &jammer_mob);

    apps::JammerAttackHandler attack_handler(
        &topo, &jammer_mgr, &rekey_mgr,
        &comp_det, &mc_mgr, &skdc_apps);
    attack_handler.SetRekeyThreshold(0.5);

    // -----------------------------------------------------------------------
    // MT_K initial broadcast + periodic refresh
    // -----------------------------------------------------------------------
    dist_mgr.BroadcastAll(skdc_apps);
    dist_mgr.ScheduleRefresh(skdc_apps);

    // -----------------------------------------------------------------------
    // Periodic rekey (every 60s per spec)
    // -----------------------------------------------------------------------
    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
        rekey_mgr.SchedulePeriodic(c, skdc_apps[c], 60.0);
    }

    // -----------------------------------------------------------------------
    // Jammer periodic scan
    // -----------------------------------------------------------------------
    jammer_mgr.StartPeriodicScan(1.0);
    attack_handler.SchedulePeriodicHandling(1.0);


    // -----------------------------------------------------------------------
    // Visualization
    // -----------------------------------------------------------------------
    visualization::NetAnimManager netanim(&topo, OUTPUT_DIR);
    if (enable_anim) netanim.Initialize();

    visualization::NodeColorManager color_mgr(&topo, &netanim);
    if (enable_anim) {
        color_mgr.Initialize();
        color_mgr.HookCompromiseDetector(&comp_det);
        color_mgr.HookJammerManager(&jammer_mgr, 1.0);
    }

    visualization::PacketVizManager pkt_viz(&topo, &netanim);
    if (enable_anim) pkt_viz.Initialize();

    visualization::EventAnnotationManager evt_ann(
        &topo, &netanim);
    if (enable_anim) evt_ann.Initialize();

    // Annotate initial MT_K broadcasts
    for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
        pkt_viz.OnMtkBroadcast(c, c, 1);
        evt_ann.OnRekey(c);
    }

    // -----------------------------------------------------------------------
    // Metrics
    // -----------------------------------------------------------------------
    metrics::ThroughputMetrics      tput_mgr(&topo, &flow_mgr);
    metrics::DelayMetrics           delay_mgr(&topo, &flow_mgr);
    metrics::PdrMetrics             pdr_mgr(&topo, &flow_mgr);
    metrics::RoutingOverheadMetrics overhead_mgr(&topo, &flow_mgr);
    metrics::RekeyLatencyMetrics    rekey_lat(&topo, &flow_mgr, &rekey_mgr);
    metrics::SinrMetrics            sinr_mgr(&topo, &jammer_mgr);

    tput_mgr.SchedulePeriodicSample(1.0);
    delay_mgr.SchedulePeriodicSample(1.0);
    pdr_mgr.SchedulePeriodicSample(1.0);
    overhead_mgr.SchedulePeriodicSample(1.0);
    sinr_mgr.SchedulePeriodicSample(1.0);

    metrics::CsvExportManager csv_mgr(
        &topo, OUTPUT_DIR,
        &tput_mgr, &delay_mgr, &pdr_mgr,
        &overhead_mgr, &rekey_lat, &sinr_mgr,
        &flow_mgr);
    csv_mgr.Initialize(1.0);

    // -----------------------------------------------------------------------
    // PCAP
    // -----------------------------------------------------------------------
    metrics::PcapExportManager pcap_mgr(
        &topo, PCAP_DIR, &builder);
    if (enable_pcap) pcap_mgr.Enable();

    // -----------------------------------------------------------------------
    // Automatic handover detection every 5s
    // -----------------------------------------------------------------------
    Simulator::Schedule(
        Seconds(5.0),
        &AutoHandoverCheck,
        &mob_mgr, &ho_mgr, &skdc_apps,
        &color_mgr, &pkt_viz, &evt_ann,
        5.0);

    // -----------------------------------------------------------------------
    // Scheduled security events
    // -----------------------------------------------------------------------
    // t=30s: Leave
    Simulator::Schedule(Seconds(30.0),
        &ScheduledLeave,
        &leave_mgr, &rekey_mgr, &skdc_apps,
        &color_mgr, &pkt_viz, &evt_ann);

    // t=60s: Handover
    Simulator::Schedule(Seconds(60.0),
        &ScheduledHandover,
        &ho_mgr, &skdc_apps,
        &color_mgr, &pkt_viz, &evt_ann);

    // t=90s: Join
    Simulator::Schedule(Seconds(90.0),
        &ScheduledJoin,
        &join_mgr, &skdc_apps, &pkt_viz, &evt_ann);

    // t=150s: Global rekey
    Simulator::Schedule(Seconds(150.0),
        &ScheduledGlobalRekey,
        &rekey_mgr, &skdc_apps, &pkt_viz, &evt_ann);

    // -----------------------------------------------------------------------
    // Run simulation
    // -----------------------------------------------------------------------
    NS_LOG_UNCOND("\nStarting simulation...");
    Simulator::Stop(Seconds(duration));
}
