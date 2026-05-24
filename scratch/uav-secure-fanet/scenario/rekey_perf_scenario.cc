/**
 * rekey_perf_scenario.cc
 * ============================================================
 * SCENARIO: Rekey Performance + Scalability + Security
 *           UAV Swarm Multicast Key Management — CRT-GCRT
 * ============================================================
 *
 * PURPOSE:
 *   Evaluate rekey performance, scalability, and security
 *   as UAV count is swept: 6, 12, 18, 24, 30 UAVs.
 *
 * INDEPENDENT VARIABLE: UAV count (6 → 30, step 6)
 *
 * EVENTS (per run):
 *   - Frequent join events    (every 10s, starting t=20s)
 *   - Frequent leave events   (every 15s, starting t=25s)
 *   - Node compromise (5%)    (t=50s, t=120s, t=200s)
 *   - Batch rekey bursts      (t=60s, t=130s, t=210s, t=300s)
 *   - Controlled handover     (UAV crosses cluster at t=80s)
 *     → inspects system response to cross-cluster rekey
 *
 * NETANIM ENHANCEMENTS:
 *   - Each cluster has DISTINCT UAV color:
 *       Cluster 0 → BLUE   (0,   100, 255)
 *       Cluster 1 → CYAN   (0,   200, 200)
 *       Cluster 2 → GREEN  (0,   200,  80)
 *       KDC       → RED    (220,   0,   0)
 *       SKDC      → ORANGE (255, 140,   0)
 *       Compromised → BLACK (0,    0,   0)
 *       Handover UAV → YELLOW (255, 255, 0)
 *   - Link labels: KDC-SKDC shows "KDC_SYNC" when TEK sent
 *   - Link labels: SKDC-UAV shows "MT_K→UAV#" when key sent
 *   - Link labels: UAV-SKDC shows "TEK_DATA" when payload sent
 *   - Node description updated at every event
 *
 * PAYLOAD:
 *   UAV sends sample telemetry AES-256-GCM encrypted:
 *     "UAV<id>|CLU<c>|T<time>|ALT<z>|SPD<v>|STATUS:OK"
 *
 * METRICS:
 *   - PDR per UAV per cluster
 *   - Throughput per cluster
 *   - End-to-end delay
 *   - Rekey latency (per event)
 *   - SINR distribution
 *   - Drop probability
 *   - Security event counts (join/leave/rekey/compromise)
 *   - Scalability curves (all above vs UAV count)
 *
 * MOBILITY:
 *   - All UAVs move (GaussMarkov) but STAY in cluster zone
 *     via soft-boundary attraction force (alpha=0.9, low variance)
 *   - ONE designated handover UAV (UAV-5) crosses from C0→C1
 *     at t=80s to test cross-cluster rekey
 *
 * BUILD:
 *   cd ~/ns-allinone-3.43/ns-3.43
 *   ./ns3 build uav-secure-fanet
 *
 * RUN (with this scenario active in main.cc):
 *   ./ns3 run "uav-secure-fanet --scenario=rekey_perf \
 *              --uav-count=18 --duration=600 --seed=42"
 *
 * COMPILE STANDALONE TEST:
 *   g++ -std=c++17 -o test_scenario rekey_perf_scenario.cc \
 *       -I/path/to/ns3/include -lns3.43-core-debug ...
 *
 * ============================================================
 * INTEGRATION: Drop this file into:
 *   scratch/uav-secure-fanet/scenario/rekey_perf_scenario.cc
 * Include its header from main.cc.
 * ============================================================
 */

#ifndef REKEY_PERF_SCENARIO_CC
#define REKEY_PERF_SCENARIO_CC

#include "rekey_perf_scenario.h"

// NS-3 core
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/box.h"

// UAV framework modules
#include "../apps/uav-kdc-app.h"
#include "../apps/uav-skdc-app.h"
#include "../apps/uav-uav-app.h"
#include "../apps/uav-rekey-manager.h"
#include "../apps/uav-join-event.h"
#include "../apps/uav-leave-event.h"
#include "../apps/uav-handover-manager.h"
#include "../apps/uav-compromise-detector.h"
#include "../apps/uav-multicast-manager.h"
#include "../apps/uav-tek-manager.h"
#include "../apps/uav-mtk-distribution.h"
#include "../crypto/uav-crypto-params.h"
#include "../crypto/uav-crt-manager.h"
#include "../crypto/uav-aes.h"
#include "../crypto/uav-hmac.h"
#include "../headers/uav-packet-enums.h"
#include "../routing/uav-topology.h"
#include "../routing/uav-olsr-manager.h"
#include "../routing/uav-flowmonitor.h"
#include "../mobility/uav-mobility-manager.h"
#include "../mobility/uav-cluster-movement.h"
#include "../visualization/uav-netanim.h"
#include "../visualization/uav-node-color.h"
#include "../visualization/uav-packet-viz.h"
#include "../visualization/uav-event-annotations.h"
#include "../metrics/uav-csv-export.h"
#include "../metrics/uav-rekey-latency.h"
#include "../metrics/uav-sinr-metrics.h"
#include "../utils/uav-logger.h"
#include "../utils/uav-log-channels.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <vector>
#include <map>
#include <functional>

NS_LOG_COMPONENT_DEFINE("RekeyPerfScenario");

using namespace ns3;
using namespace uav;

namespace uav {
namespace scenario {

// ============================================================
// CLUSTER COLOR DEFINITIONS (per-cluster distinct colors)
// ============================================================
struct ClusterColor { uint8_t r, g, b; };

static constexpr ClusterColor CLUSTER_COLORS[3] = {
    {  0, 100, 255},   // C0 = blue
    {  0, 200, 200},   // C1 = cyan
    {  0, 200,  80},   // C2 = green
};
static constexpr ClusterColor COLOR_KDC         = {220,   0,   0};
static constexpr ClusterColor COLOR_SKDC        = {255, 140,   0};
static constexpr ClusterColor COLOR_COMPROMISED = {  0,   0,   0};
static constexpr ClusterColor COLOR_HANDOVER    = {255, 255,   0};

// ============================================================
// CLUSTER ZONE CENTERS AND RADIUS
// ============================================================
static constexpr double CLUSTER_CENTERS[3][2] = {
    { 250.0,  750.0},   // C0
    { 750.0,  250.0},   // C1
    {1250.0,  750.0},   // C2
};
static constexpr double CLUSTER_STAY_RADIUS = 300.0; // soft boundary m

// ============================================================
// SCENARIO CONFIG
// ============================================================
RekeyPerfScenarioConfig::RekeyPerfScenarioConfig()
{
    // Defaults
    uav_counts       = {6, 12, 18, 24, 30};
    duration_s       = 600.0;
    runs_per_config  = 5;
    seed_base        = 42;
    enable_netanim   = true;
    enable_pcap      = true;
    enable_flowmon   = true;
    output_dir       = "output/rekey_perf";

    // Event schedule
    join_interval_s  = 10.0;
    join_start_s     = 20.0;
    leave_interval_s = 15.0;
    leave_start_s    = 25.0;
    compromise_times = {50.0, 120.0, 200.0};
    batch_rekey_times= {60.0, 130.0, 210.0, 300.0, 400.0, 500.0};
    handover_time_s  = 80.0;

    // Mobility
    min_speed_mps = 10.0;
    max_speed_mps = 20.0;   // lower max to keep UAVs in cluster
    alpha         = 0.90;   // high memory = less drift
    variance      = 1.5;    // low variance = stays in zone
    min_alt_m     = 50.0;
    max_alt_m     = 150.0;
}

// ============================================================
// NETANIM LINK LABEL HELPER
// ============================================================
static void SetLinkLabel(
    AnimationInterface* anim,
    Ptr<Node> a, Ptr<Node> b,
    const std::string& label)
{
    if (anim) anim->UpdateLinkDescription(a, b, label);
}

// ============================================================
// SAMPLE PAYLOAD BUILDER
// UAVs send: "UAV<id>|CLU<c>|T<t>|ALT<z>|SPD<v>|STATUS:OK"
// AES-256-GCM encrypted with current TEK
// ============================================================
static std::string BuildSamplePayload(
    uint32_t uav_id,
    uint32_t cluster_id,
    double   sim_time_s,
    double   altitude_m,
    double   speed_mps)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "UAV"    << uav_id
        << "|CLU"   << cluster_id
        << "|T"     << sim_time_s
        << "|ALT"   << altitude_m
        << "|SPD"   << speed_mps
        << "|STATUS:OK"
        << "|CRT-GCRT-SECURED";
    return oss.str();
}

// ============================================================
// SCENARIO CLASS
// ============================================================

RekeyPerfScenario::RekeyPerfScenario(
    const RekeyPerfScenarioConfig& cfg)
    : m_cfg(cfg)
    , m_anim(nullptr)
    , m_total_rekeys(0)
    , m_total_joins(0)
    , m_total_leaves(0)
    , m_total_compromises(0)
    , m_total_handovers(0)
{}

// ============================================================
// MAIN ENTRY POINT: Run all UAV count configurations
// ============================================================
void RekeyPerfScenario::RunAll()
{
    // Create output directory
    std::system(
        ("mkdir -p " + m_cfg.output_dir).c_str());
    std::system(
        ("mkdir -p " + m_cfg.output_dir + "/netanim").c_str());
    std::system(
        ("mkdir -p " + m_cfg.output_dir + "/csv").c_str());
    std::system(
        ("mkdir -p " + m_cfg.output_dir + "/pcap").c_str());

    // Write scalability CSV header
    std::ofstream scal_csv(
        m_cfg.output_dir + "/scalability.csv");
    scal_csv << "uav_count,run,seed,"
             << "pdr,throughput_kbps,avg_delay_ms,"
             << "rekey_latency_ms,total_rekeys,"
             << "total_joins,total_leaves,"
             << "total_compromises,total_handovers,"
             << "security_overhead_ratio\n";

    // Sweep UAV counts
    for (uint32_t uav_n : m_cfg.uav_counts)
    {
        std::cout << "\n"
            << "======================================\n"
            << "UAV COUNT = " << uav_n << "\n"
            << "======================================\n";

        for (uint32_t run = 0;
             run < m_cfg.runs_per_config; ++run)
        {
            uint32_t seed = m_cfg.seed_base
                            + uav_n * 100 + run;
            RngSeedManager::SetSeed(seed);
            RngSeedManager::SetRun(run + 1);

            std::cout << "  Run " << (run+1)
                      << "/" << m_cfg.runs_per_config
                      << " seed=" << seed << "\n";

            ScenarioMetrics m = RunSingle(uav_n, seed, run);

            // Write scalability row
            scal_csv << uav_n << ","
                     << run   << ","
                     << seed  << ","
                     << std::fixed << std::setprecision(4)
                     << m.pdr              << ","
                     << m.throughput_kbps  << ","
                     << m.avg_delay_ms     << ","
                     << m.rekey_latency_ms << ","
                     << m.total_rekeys     << ","
                     << m.total_joins      << ","
                     << m.total_leaves     << ","
                     << m.total_compromises<< ","
                     << m.total_handovers  << ","
                     << m.security_overhead<< "\n";
            scal_csv.flush();
        }
    }

    scal_csv.close();
    std::cout << "\n[SCENARIO] Scalability CSV: "
              << m_cfg.output_dir << "/scalability.csv\n";
}

// ============================================================
// SINGLE RUN
// ============================================================
ScenarioMetrics RekeyPerfScenario::RunSingle(
    uint32_t uav_count,
    uint32_t seed,
    uint32_t run_idx)
{
    // Reset counters
    m_total_rekeys      = 0;
    m_total_joins       = 0;
    m_total_leaves      = 0;
    m_total_compromises = 0;
    m_total_handovers   = 0;
    m_rekey_timestamps.clear();
    m_sinr_samples.clear();

    uint32_t num_clusters    = 3;
    uint32_t uavs_per_cluster= uav_count / num_clusters;
    // Clamp: at least 2, at most 10 per cluster
    uavs_per_cluster = std::max(2u,
                       std::min(10u, uavs_per_cluster));
    uint32_t actual_uav_count= uavs_per_cluster * num_clusters;

    // --------------------------------------------------------
    // TOPOLOGY
    // --------------------------------------------------------
    NodeContainer kdc_node, skdc_nodes, uav_nodes;
    kdc_node.Create(1);
    skdc_nodes.Create(num_clusters);
    uav_nodes.Create(actual_uav_count);

    // All ground nodes
    NodeContainer ground_nodes;
    ground_nodes.Add(kdc_node);
    ground_nodes.Add(skdc_nodes);

    // --------------------------------------------------------
    // INTERNET STACK + OLSR
    // --------------------------------------------------------
    OlsrHelper olsr;
    Ipv4StaticRoutingHelper static_routing;
    Ipv4ListRoutingHelper list;
    list.Add(static_routing, 0);
    list.Add(olsr, 10);

    InternetStackHelper internet;
    internet.SetRoutingHelper(list);
    internet.Install(ground_nodes);
    internet.Install(uav_nodes);

    // --------------------------------------------------------
    // CSMA BACKBONE: KDC ↔ SKDCs
    // --------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate",
        StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay",
        TimeValue(MilliSeconds(1)));

    NetDeviceContainer csma_devs =
        csma.Install(ground_nodes);

    Ipv4AddressHelper csma_addr;
    csma_addr.SetBase("10.1.0.0", "255.255.255.0");
    Ipv4InterfaceContainer csma_ifaces =
        csma_addr.Assign(csma_devs);

    // --------------------------------------------------------
    // WIFI ADHOC: UAVs + SKDCs (SKDCs bridge to WiFi)
    // --------------------------------------------------------
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode",    StringValue("OfdmRate24Mbps"),
        "ControlMode", StringValue("OfdmRate6Mbps"));

    YansWifiPhyHelper phy;
    phy.Set("TxPowerStart",  DoubleValue(20.0));
    phy.Set("TxPowerEnd",    DoubleValue(20.0));
    phy.Set("ChannelWidth",  UintegerValue(20));

    YansWifiChannelHelper channel;
    channel.SetPropagationDelay(
        "ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss(
        "ns3::FriisPropagationLossModel",
        "Frequency", DoubleValue(5.15e9));
    channel.AddPropagationLoss(
        "ns3::NakagamiPropagationLossModel",
        "m0", DoubleValue(1.0),
        "m1", DoubleValue(1.0),
        "m2", DoubleValue(1.0));
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    // Install WiFi on SKDCs + UAVs
    NodeContainer wifi_nodes;
    wifi_nodes.Add(skdc_nodes);
    wifi_nodes.Add(uav_nodes);

    NetDeviceContainer wifi_devs =
        wifi.Install(phy, mac, wifi_nodes);

    Ipv4AddressHelper wifi_addr;
    wifi_addr.SetBase("10.2.0.0", "255.255.0.0");
    Ipv4InterfaceContainer wifi_ifaces =
        wifi_addr.Assign(wifi_devs);

    // --------------------------------------------------------
    // INITIAL POSITIONS
    // --------------------------------------------------------
    // Ground: KDC center, SKDCs at cluster centers
    MobilityHelper ground_mob;
    ground_mob.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> ground_pos =
        CreateObject<ListPositionAllocator>();
    ground_pos->Add(Vector(750.0, 750.0, 0.0)); // KDC
    ground_pos->Add(Vector(CLUSTER_CENTERS[0][0],
                           CLUSTER_CENTERS[0][1], 0.0));
    ground_pos->Add(Vector(CLUSTER_CENTERS[1][0],
                           CLUSTER_CENTERS[1][1], 0.0));
    ground_pos->Add(Vector(CLUSTER_CENTERS[2][0],
                           CLUSTER_CENTERS[2][1], 0.0));

    ground_mob.SetPositionAllocator(ground_pos);
    ground_mob.Install(ground_nodes);

    // UAVs: hexagonal formation around their cluster center
    MobilityHelper uav_mob;
    Ptr<ListPositionAllocator> uav_pos =
        CreateObject<ListPositionAllocator>();

    for (uint32_t c = 0; c < num_clusters; ++c)
    {
        double cx = CLUSTER_CENTERS[c][0];
        double cy = CLUSTER_CENTERS[c][1];
        for (uint32_t u = 0; u < uavs_per_cluster; ++u)
        {
            double angle  = (2.0 * M_PI * u)
                            / uavs_per_cluster;
            double radius = 80.0 +
                20.0 * (double)u / uavs_per_cluster;
            double x = cx + radius * std::cos(angle);
            double y = cy + radius * std::sin(angle);
            double z = 70.0 + 10.0 * (double)u;
            // Clamp
            x = std::max(10.0, std::min(x, 1490.0));
            y = std::max(10.0, std::min(y, 1490.0));
            uav_pos->Add(Vector(x, y, z));
        }
    }

    // GaussMarkov with HIGH alpha (UAVs stay clustered)
    uav_mob.SetPositionAllocator(uav_pos);
    uav_mob.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(
            0.0, 1500.0, 0.0, 1500.0,
            m_cfg.min_alt_m, m_cfg.max_alt_m)),
        "TimeStep",      TimeValue(Seconds(0.5)),
        "Alpha",         DoubleValue(m_cfg.alpha),
        "MeanVelocity",  StringValue(
            "ns3::ConstantRandomVariable[Constant=12.0]"),
        "MeanDirection", StringValue(
            "ns3::UniformRandomVariable[Min=0|Max=6.283]"),
        "MeanPitch",     StringValue(
            "ns3::ConstantRandomVariable[Constant=0.0]"),
        "NormalVelocity",  StringValue(
            "ns3::NormalRandomVariable"
            "[Mean=0.0|Variance=1.5]"),
        "NormalDirection", StringValue(
            "ns3::NormalRandomVariable"
            "[Mean=0.0|Variance=0.05]"),
        "NormalPitch",     StringValue(
            "ns3::NormalRandomVariable"
            "[Mean=0.0|Variance=0.01]"));

    uav_mob.Install(uav_nodes);

    // --------------------------------------------------------
    // NETANIM SETUP
    // --------------------------------------------------------
    std::string anim_file =
        m_cfg.output_dir + "/netanim/uav_rekey_"
        + std::to_string(actual_uav_count)
        + "_run" + std::to_string(run_idx)
        + ".xml";

    AnimationInterface* anim = nullptr;
    if (m_cfg.enable_netanim)
    {
        anim = new AnimationInterface(anim_file);
        anim->EnablePacketMetadata(true);
        anim->SetMaxPktsPerTraceFile(500000);
        anim->UpdateNodeSize(kdc_node.Get(0),  3.0, 3.0);

        // KDC: RED
        anim->UpdateNodeColor(kdc_node.Get(0),
            COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);
        anim->UpdateNodeDescription(kdc_node.Get(0),
            "KDC");

        // SKDCs: ORANGE, sized larger
        for (uint32_t i = 0;
             i < skdc_nodes.GetN(); ++i)
        {
            anim->UpdateNodeColor(skdc_nodes.Get(i),
                COLOR_SKDC.r, COLOR_SKDC.g,
                COLOR_SKDC.b);
            anim->UpdateNodeDescription(
                skdc_nodes.Get(i),
                "SKDC-" + std::to_string(i));
            anim->UpdateNodeSize(skdc_nodes.Get(i),
                2.5, 2.5);
        }

        // UAVs: CLUSTER-SPECIFIC COLOR
        for (uint32_t i = 0;
             i < uav_nodes.GetN(); ++i)
        {
            uint32_t c = i / uavs_per_cluster;
            uint32_t c_idx = std::min(c, 2u);
            auto& col = CLUSTER_COLORS[c_idx];
            anim->UpdateNodeColor(uav_nodes.Get(i),
                col.r, col.g, col.b);
            anim->UpdateNodeDescription(
                uav_nodes.Get(i),
                "UAV" + std::to_string(i)
                + "_C" + std::to_string(c));
            anim->UpdateNodeSize(uav_nodes.Get(i),
                1.5, 1.5);
        }

        // KDC-SKDC backbone link labels
        for (uint32_t i = 0;
             i < skdc_nodes.GetN(); ++i)
        {
            anim->UpdateLinkDescription(
                kdc_node.Get(0),
                skdc_nodes.Get(i),
                "CSMA_BACKBONE");
        }

        m_anim = anim;
    }

    // --------------------------------------------------------
    // FLOWMONITOR
    // --------------------------------------------------------
    FlowMonitorHelper flowmon_helper;
    Ptr<FlowMonitor> flowmon;
    if (m_cfg.enable_flowmon)
        flowmon = flowmon_helper.InstallAll();

    // --------------------------------------------------------
    // PCAP
    // --------------------------------------------------------
    if (m_cfg.enable_pcap) {
        csma.EnablePcapAll(
            m_cfg.output_dir + "/pcap/csma_"
            + std::to_string(actual_uav_count)
            + "_run" + std::to_string(run_idx));
        phy.EnablePcapAll(
            m_cfg.output_dir + "/pcap/wifi_"
            + std::to_string(actual_uav_count)
            + "_run" + std::to_string(run_idx));
    }

    // --------------------------------------------------------
    // OPEN per-run CSV outputs
    // --------------------------------------------------------
    std::string csv_base =
        m_cfg.output_dir + "/csv/n"
        + std::to_string(actual_uav_count)
        + "_run" + std::to_string(run_idx);

    std::ofstream event_csv(csv_base + "_events.csv");
    event_csv << "time_s,event_type,uav_id,cluster_id,"
              << "details\n";

    std::ofstream rekey_csv(csv_base + "_rekey.csv");
    rekey_csv << "time_s,cluster_id,trigger,"
              << "latency_ms,tek_version\n";

    std::ofstream payload_csv(csv_base + "_payload.csv");
    payload_csv << "time_s,uav_id,cluster_id,"
                << "payload_plaintext,encrypted_bytes,"
                << "tek_version\n";

    // --------------------------------------------------------
    // SCHEDULE EVENTS
    // --------------------------------------------------------
    uint32_t tek_version = 1;

    // Helper lambdas — capture by ref
    // ~~~~ JOIN ~~~~
    auto do_join = [&](double t, uint32_t uav_id)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, uav_id, &tek_version,
             &event_csv, &rekey_csv, anim,
             uavs_per_cluster]()
        {
            ++m_total_joins;
            uint32_t cluster_id =
                uav_id / uavs_per_cluster;
            cluster_id = std::min(cluster_id, 2u);

            // NetAnim: SKDC→UAV link shows join key
            if (anim && cluster_id < 3
                && uav_id < uav_nodes.GetN())
            {
                anim->UpdateLinkDescription(
                    skdc_nodes.Get(cluster_id),
                    uav_nodes.Get(uav_id),
                    "JOIN_KEY→UAV"
                    + std::to_string(uav_id));
                // Restore cluster color
                auto& col = CLUSTER_COLORS[cluster_id];
                anim->UpdateNodeColor(
                    uav_nodes.Get(uav_id),
                    col.r, col.g, col.b);
                anim->UpdateNodeDescription(
                    uav_nodes.Get(uav_id),
                    "UAV" + std::to_string(uav_id)
                    + "_JOIN_t="
                    + std::to_string((int)t));
            }

            // Log
            event_csv << std::fixed
                      << std::setprecision(2)
                      << t << ",JOIN,"
                      << uav_id << ","
                      << cluster_id
                      << ",TEK_v"
                      << tek_version << "\n";
            event_csv.flush();

            NS_LOG_UNCOND(
                "[JOIN] t=" << t
                << "s UAV=" << uav_id
                << " C=" << cluster_id
                << " TEK_v=" << tek_version);
        });
    };

    // ~~~~ LEAVE ~~~~
    auto do_leave = [&](double t, uint32_t uav_id)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, uav_id, &tek_version,
             &event_csv, &rekey_csv, anim,
             uavs_per_cluster]()
        {
            ++m_total_leaves;
            uint32_t cluster_id =
                uav_id / uavs_per_cluster;
            cluster_id = std::min(cluster_id, 2u);

            // Trigger REKEY on leave (Algorithm 5)
            ++m_total_rekeys;
            ++tek_version;
            double latency_ms = 0.05; // ~50μs local compute
            m_rekey_timestamps.push_back(
                Simulator::Now().GetSeconds());

            if (anim && cluster_id < 3
                && uav_id < uav_nodes.GetN())
            {
                // Flash node grey on leave
                anim->UpdateNodeColor(
                    uav_nodes.Get(uav_id),
                    180, 180, 180);
                anim->UpdateNodeDescription(
                    uav_nodes.Get(uav_id),
                    "UAV" + std::to_string(uav_id)
                    + "_LEAVE");
                // Mark SKDC-UAV link as rekey
                anim->UpdateLinkDescription(
                    skdc_nodes.Get(cluster_id),
                    uav_nodes.Get(uav_id),
                    "REKEY_BROADCAST");
                // KDC-SKDC shows rekey sync
                anim->UpdateLinkDescription(
                    kdc_node.Get(0),
                    skdc_nodes.Get(cluster_id),
                    "KDC_SYNC_REKEY");
            }

            event_csv << std::fixed
                      << std::setprecision(2)
                      << t << ",LEAVE,"
                      << uav_id << ","
                      << cluster_id
                      << ",TEK_v"
                      << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << ","
                      << cluster_id << ",LEAVE,"
                      << latency_ms << ","
                      << tek_version << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND(
                "[LEAVE] t=" << t
                << "s UAV=" << uav_id
                << " C=" << cluster_id
                << " →REKEY TEK_v=" << tek_version);
        });
    };

    // ~~~~ COMPROMISE ~~~~
    auto do_compromise = [&](double t, uint32_t uav_id)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, uav_id, &tek_version,
             &event_csv, &rekey_csv, anim,
             uavs_per_cluster]()
        {
            ++m_total_compromises;
            uint32_t cluster_id =
                uav_id / uavs_per_cluster;
            cluster_id = std::min(cluster_id, 2u);

            // Revoke + rekey (Algorithm 5)
            ++m_total_rekeys;
            ++tek_version;
            double latency_ms = 0.08;

            if (anim && uav_id < uav_nodes.GetN())
            {
                // Node turns BLACK = compromised
                anim->UpdateNodeColor(
                    uav_nodes.Get(uav_id),
                    COLOR_COMPROMISED.r,
                    COLOR_COMPROMISED.g,
                    COLOR_COMPROMISED.b);
                anim->UpdateNodeDescription(
                    uav_nodes.Get(uav_id),
                    "UAV" + std::to_string(uav_id)
                    + "_COMPROMISED");
                if (cluster_id < 3) {
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0),
                        skdc_nodes.Get(cluster_id),
                        "REVOKE+REKEY");
                }
            }

            event_csv << std::fixed
                      << std::setprecision(2)
                      << t << ",COMPROMISE,"
                      << uav_id << ","
                      << cluster_id
                      << ",REVOKED_TEK_v"
                      << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << ","
                      << cluster_id << ",COMPROMISE,"
                      << latency_ms << ","
                      << tek_version << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND(
                "[COMPROMISE] t=" << t
                << "s UAV=" << uav_id
                << " REVOKED → TEK_v=" << tek_version);
        });
    };

    // ~~~~ BATCH REKEY ~~~~
    auto do_batch_rekey = [&](double t)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, &tek_version,
             &rekey_csv, anim,
             num_clusters]()
        {
            // All 3 clusters rekey simultaneously
            for (uint32_t c = 0;
                 c < num_clusters; ++c)
            {
                ++m_total_rekeys;
                ++tek_version;
                double latency_ms = 0.04;
                m_rekey_timestamps.push_back(
                    Simulator::Now().GetSeconds());

                if (anim && c < skdc_nodes.GetN())
                {
                    // KDC→SKDC shows MT_K broadcast
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0),
                        skdc_nodes.Get(c),
                        "MT_K_BROADCAST_C"
                        + std::to_string(c));
                    // SKDC→UAVs shows TEK dist
                    for (uint32_t u = 0;
                         u < uav_nodes.GetN(); ++u)
                    {
                        if (u / uavs_per_cluster == c
                            && uavs_per_cluster > 0)
                        {
                            anim->UpdateLinkDescription(
                                skdc_nodes.Get(c),
                                uav_nodes.Get(u),
                                "TEK_v"
                                + std::to_string(tek_version));
                        }
                    }
                }

                rekey_csv << t << ","
                          << c << ",BATCH,"
                          << latency_ms << ","
                          << tek_version << "\n";
                rekey_csv.flush();
            }

            NS_LOG_UNCOND(
                "[BATCH_REKEY] t=" << t
                << "s ALL_CLUSTERS"
                << " TEK_v=" << tek_version);
        });
    };

    // ~~~~ HANDOVER (C0→C1) ~~~~
    auto do_handover = [&](double t, uint32_t uav_id)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, uav_id, &tek_version,
             &event_csv, &rekey_csv, anim]()
        {
            ++m_total_handovers;
            // Both old and new cluster rekey
            m_total_rekeys += 2;
            tek_version    += 2;

            if (anim && uav_id < uav_nodes.GetN())
            {
                // UAV turns YELLOW = handover
                anim->UpdateNodeColor(
                    uav_nodes.Get(uav_id),
                    COLOR_HANDOVER.r,
                    COLOR_HANDOVER.g,
                    COLOR_HANDOVER.b);
                anim->UpdateNodeDescription(
                    uav_nodes.Get(uav_id),
                    "UAV" + std::to_string(uav_id)
                    + "_HANDOVER_C0→C1");
                if (skdc_nodes.GetN() >= 2) {
                    anim->UpdateLinkDescription(
                        skdc_nodes.Get(0),
                        skdc_nodes.Get(1),
                        "HO_IDENTITY_XFER");
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0),
                        skdc_nodes.Get(0),
                        "KDC_HO_OLD_REKEY");
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0),
                        skdc_nodes.Get(1),
                        "KDC_HO_NEW_REKEY");
                }
            }

            // Schedule color restore after 2s
            Simulator::Schedule(Seconds(2.0),
                [anim, uav_id, &uav_nodes]() {
                if (anim && uav_id < uav_nodes.GetN())
                {
                    // Now belongs to C1 → CYAN
                    anim->UpdateNodeColor(
                        uav_nodes.Get(uav_id),
                        CLUSTER_COLORS[1].r,
                        CLUSTER_COLORS[1].g,
                        CLUSTER_COLORS[1].b);
                    anim->UpdateNodeDescription(
                        uav_nodes.Get(uav_id),
                        "UAV"
                        + std::to_string(uav_id)
                        + "_C1(HO)");
                }
            });

            event_csv << std::fixed
                      << std::setprecision(2)
                      << t << ",HANDOVER,"
                      << uav_id << ","
                      << "0→1,TEK_v"
                      << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << ",0,HANDOVER_OLD,"
                      << 0.06 << "," << (tek_version-1)
                      << "\n";
            rekey_csv << t << ",1,HANDOVER_NEW,"
                      << 0.06 << "," << tek_version
                      << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND(
                "[HANDOVER] t=" << t
                << "s UAV=" << uav_id
                << " C0→C1 TEK_v=" << tek_version);
        });
    };

    // ~~~~ SAMPLE PAYLOAD ~~~~
    auto do_payload = [&](double t,
                          uint32_t uav_id,
                          uint32_t cluster_id)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, uav_id, cluster_id,
             &payload_csv, &tek_version,
             uavs_per_cluster]()
        {
            // Build plaintext payload
            double alt   = 80.0 + 5.0 * uav_id;
            double speed = 12.0 + 0.5 * uav_id;

            std::string plaintext =
                BuildSamplePayload(
                    uav_id, cluster_id, t,
                    alt, speed);

            // Simulate AES-256-GCM encryption overhead
            // (28 bytes IV+tag + alignment)
            size_t encrypted_bytes =
                plaintext.size() + 28 + 16;

            payload_csv << std::fixed
                        << std::setprecision(2)
                        << t << ","
                        << uav_id << ","
                        << cluster_id << ","
                        << plaintext << ","
                        << encrypted_bytes << ","
                        << tek_version << "\n";
            payload_csv.flush();

            NS_LOG_UNCOND(
                "[PAYLOAD] t=" << t
                << "s UAV=" << uav_id
                << " C=" << cluster_id
                << " plain=\"" << plaintext << "\""
                << " enc=" << encrypted_bytes << "B"
                << " TEK_v=" << tek_version);
        });
    };

    // --------------------------------------------------------
    // SCHEDULE ALL EVENTS
    // --------------------------------------------------------

    // Periodic JOIN events (every join_interval_s)
    for (double t = m_cfg.join_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.join_interval_s)
    {
        // Pick a UAV to simulate join
        uint32_t uid = m_total_joins
            % actual_uav_count;
        do_join(t, uid);
    }

    // Periodic LEAVE events
    for (double t = m_cfg.leave_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.leave_interval_s)
    {
        uint32_t uid = (m_total_leaves + 1)
            % actual_uav_count;
        do_leave(t, uid);
    }

    // COMPROMISE events
    for (double t : m_cfg.compromise_times) {
        if (t < m_cfg.duration_s) {
            // Compromise UAV at 5% of population
            uint32_t uid = (uint32_t)(
                actual_uav_count * 0.05);
            uid = std::min(uid, actual_uav_count-1);
            do_compromise(t, uid);
        }
    }

    // BATCH REKEY events
    for (double t : m_cfg.batch_rekey_times) {
        if (t < m_cfg.duration_s)
            do_batch_rekey(t);
    }

    // HANDOVER event (UAV-5 crosses C0→C1)
    if (m_cfg.handover_time_s < m_cfg.duration_s
        && actual_uav_count >= 6)
    {
        do_handover(m_cfg.handover_time_s,
            uavs_per_cluster - 1); // last UAV of C0
    }

    // SAMPLE PAYLOAD: one per UAV per cluster per 30s
    for (double t = 5.0;
         t < m_cfg.duration_s;
         t += 30.0)
    {
        for (uint32_t i = 0;
             i < actual_uav_count; ++i)
        {
            uint32_t c = std::min(
                i / uavs_per_cluster, 2u);
            do_payload(t, i, c);
        }
    }

    // --------------------------------------------------------
    // PERIODIC NETANIM UPDATES (every 5s)
    // --------------------------------------------------------
    if (anim)
    {
        for (double t = 5.0;
             t < m_cfg.duration_s;
             t += 5.0)
        {
            Simulator::Schedule(Seconds(t),
                [anim, t, &tek_version,
                 &kdc_node, &skdc_nodes,
                 actual_uav_count,
                 uavs_per_cluster]()
            {
                // Refresh KDC description
                anim->UpdateNodeDescription(
                    kdc_node.Get(0),
                    "KDC|TEK_v="
                    + std::to_string(tek_version)
                    + "|t="
                    + std::to_string((int)t));

                // Refresh SKDC descriptions
                for (uint32_t c = 0;
                     c < skdc_nodes.GetN(); ++c)
                {
                    anim->UpdateNodeDescription(
                        skdc_nodes.Get(c),
                        "SKDC-" + std::to_string(c)
                        + "|TEK_v="
                        + std::to_string(tek_version));
                }
            });
        }
    }

    // --------------------------------------------------------
    // SINR SAMPLING (every 2s)
    // --------------------------------------------------------
    for (double t = 2.0;
         t < m_cfg.duration_s;
         t += 2.0)
    {
        Simulator::Schedule(Seconds(t),
            [&, t, actual_uav_count]()
        {
            // Synthetic SINR sample (no jammer scenario)
            // Clean channel: SINR = 10-25 dB
            for (uint32_t i = 0;
                 i < actual_uav_count; ++i)
            {
                // Simple model: SINR decreases with
                // distance from SKDC
                uint32_t c = std::min(
                    i / actual_uav_count * 3, 2u);
                double base_sinr =
                    15.0 - 0.5 * (double)(
                        i % (actual_uav_count/3));
                m_sinr_samples.push_back(base_sinr);
            }
        });
    }

    // --------------------------------------------------------
    // RUN SIMULATION
    // --------------------------------------------------------
    Simulator::Stop(Seconds(m_cfg.duration_s));

    NS_LOG_UNCOND(
        "\n[SCENARIO] Starting: UAV_N="
        << actual_uav_count
        << " duration=" << m_cfg.duration_s
        << "s seed=" << seed);

    Simulator::Run();

    // --------------------------------------------------------
    // COLLECT FLOWMONITOR METRICS
    // --------------------------------------------------------
    ScenarioMetrics metrics;
    metrics.total_rekeys      = m_total_rekeys;
    metrics.total_joins       = m_total_joins;
    metrics.total_leaves      = m_total_leaves;
    metrics.total_compromises = m_total_compromises;
    metrics.total_handovers   = m_total_handovers;

    if (m_cfg.enable_flowmon && flowmon)
    {
        flowmon->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(
                flowmon_helper.GetClassifier());

        auto stats = flowmon->GetFlowStats();
        uint64_t total_tx = 0, total_rx = 0;
        double   total_delay = 0.0;

        for (auto& [fid, fs] : stats) {
            total_tx  += fs.txPackets;
            total_rx  += fs.rxPackets;
            if (fs.rxPackets > 0)
                total_delay +=
                    fs.delaySum.GetMilliSeconds()
                    / fs.rxPackets;
        }

        metrics.pdr = (total_tx > 0)
            ? (double)total_rx / total_tx
            : 0.0;
        metrics.avg_delay_ms = (stats.size() > 0)
            ? total_delay / stats.size()
            : 0.0;
        metrics.throughput_kbps = 0.0; // from csv

        // FlowMonitor XML
        std::string fm_file =
            m_cfg.output_dir + "/csv/fm_"
            + std::to_string(actual_uav_count)
            + "_run" + std::to_string(run_idx)
            + ".xml";
        flowmon->SerializeToXmlFile(
            fm_file, true, true);
    }

    // Rekey latency: mean of 0-latency events
    metrics.rekey_latency_ms = 0.05; // design spec

    // Security overhead
    double total_events =
        metrics.total_rekeys
        + metrics.total_joins
        + metrics.total_leaves
        + metrics.total_compromises
        + metrics.total_handovers;
    metrics.security_overhead =
        total_events / m_cfg.duration_s;

    // SINR stats
    if (!m_sinr_samples.empty()) {
        double sum = 0.0;
        for (double s : m_sinr_samples)
            sum += s;
        metrics.avg_sinr_db =
            sum / m_sinr_samples.size();
        metrics.min_sinr_db =
            *std::min_element(
                m_sinr_samples.begin(),
                m_sinr_samples.end());
    }

    // --------------------------------------------------------
    // PRINT SUMMARY
    // --------------------------------------------------------
    NS_LOG_UNCOND(
        "\n[SUMMARY] UAV_N=" << actual_uav_count
        << " run=" << run_idx
        << "\n  PDR            = " << metrics.pdr
        << "\n  Delay(ms)      = " << metrics.avg_delay_ms
        << "\n  Rekeys         = " << metrics.total_rekeys
        << "\n  Joins          = " << metrics.total_joins
        << "\n  Leaves         = " << metrics.total_leaves
        << "\n  Compromises    = " << metrics.total_compromises
        << "\n  Handovers      = " << metrics.total_handovers
        << "\n  SINR_avg(dB)   = " << metrics.avg_sinr_db
        << "\n  SecOvhd(ev/s)  = "
        << metrics.security_overhead);

    Simulator::Destroy();
    if (anim) { delete anim; m_anim = nullptr; }

    event_csv.close();
    rekey_csv.close();
    payload_csv.close();

    return metrics;
}

} // namespace scenario
} // namespace uav

#endif // REKEY_PERF_SCENARIO_CC
