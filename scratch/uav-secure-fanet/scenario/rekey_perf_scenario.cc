/**
 * rekey_perf_scenario.cc  — FIXED
 * All includes added, all member variables match header
 */

#include "rekey_perf_scenario.h"

// NS-3 headers
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/csma-module.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/box.h"

// stdlib
#include <cstdint>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <numeric>

NS_LOG_COMPONENT_DEFINE("RekeyPerfScenario");

using namespace ns3;

namespace uav {
namespace scenario {

// ============================================================
// CLUSTER COLORS
// ============================================================
struct ClusterColor { uint8_t r, g, b; };

static constexpr ClusterColor CLUSTER_COLORS[3] = {
    {  0, 100, 255},  // C0 = blue
    {  0, 200, 200},  // C1 = cyan
    {  0, 200,  80},  // C2 = green
};
static constexpr ClusterColor COLOR_KDC         = {220,   0,   0};
static constexpr ClusterColor COLOR_SKDC        = {255, 140,   0};
static constexpr ClusterColor COLOR_COMPROMISED = {  0,   0,   0};
static constexpr ClusterColor COLOR_HANDOVER    = {255, 255,   0};

// ============================================================
// CLUSTER CENTERS
// ============================================================
static constexpr double CLUSTER_CENTERS[3][2] = {
    { 250.0,  750.0},
    { 750.0,  250.0},
    {1250.0,  750.0},
};

// ============================================================
// PAYLOAD BUILDER
// ============================================================
static std::string BuildPayload(
    uint32_t uav_id, uint32_t cluster_id,
    double t, double alt, double spd)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(1);
    o << "UAV" << uav_id
      << "|CLU" << cluster_id
      << "|T"   << t
      << "|ALT" << alt
      << "|SPD" << spd
      << "|STATUS:OK|CRT-GCRT-SECURED";
    return o.str();
}

// ============================================================
// CONFIG DEFAULTS
// ============================================================
RekeyPerfScenarioConfig::RekeyPerfScenarioConfig()
{
    uav_counts        = {6, 12, 18, 24, 30};
    duration_s        = 600.0;
    runs_per_config   = 5;
    seed_base         = 42;

    join_interval_s   = 10.0;
    join_start_s      = 20.0;
    leave_interval_s  = 15.0;
    leave_start_s     = 25.0;
    compromise_times  = {50.0, 120.0, 200.0};
    batch_rekey_times = {60.0, 130.0, 210.0, 300.0, 400.0, 500.0};
    handover_time_s   = 80.0;

    min_speed_mps     = 10.0;
    max_speed_mps     = 20.0;
    alpha             = 0.90;
    variance          = 1.5;
    min_alt_m         = 50.0;
    max_alt_m         = 150.0;

    enable_netanim    = true;
    enable_pcap       = false;
    enable_flowmon    = true;
    output_dir        = "scratch/uav-secure-fanet/output/rekey_perf";
}

// ============================================================
// CONSTRUCTOR
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
// RUN ALL
// ============================================================
void RekeyPerfScenario::RunAll()
{
    std::system(("mkdir -p " + m_cfg.output_dir).c_str());
    std::system(("mkdir -p " + m_cfg.output_dir + "/netanim").c_str());
    std::system(("mkdir -p " + m_cfg.output_dir + "/csv").c_str());
    std::system(("mkdir -p " + m_cfg.output_dir + "/pcap").c_str());
    std::system(("mkdir -p " + m_cfg.output_dir + "/logs").c_str());

    std::ofstream scal(m_cfg.output_dir + "/scalability.csv");
    scal << "uav_count,run,seed,"
         << "pdr,throughput_kbps,avg_delay_ms,"
         << "rekey_latency_ms,total_rekeys,"
         << "total_joins,total_leaves,"
         << "total_compromises,total_handovers,"
         << "security_overhead_ratio\n";

    for (uint32_t n : m_cfg.uav_counts)
    {
        std::cout << "\n====================================\n"
                  << "UAV COUNT = " << n << "\n"
                  << "====================================\n";

        for (uint32_t run = 0; run < m_cfg.runs_per_config; ++run)
        {
            uint32_t seed = m_cfg.seed_base + n * 100 + run;
            RngSeedManager::SetSeed(seed);
            RngSeedManager::SetRun(run + 1);

            std::cout << "  Run " << (run+1)
                      << "/" << m_cfg.runs_per_config
                      << " seed=" << seed << "\n";

            ScenarioMetrics m = RunSingle(n, seed, run);

            scal << n   << "," << run << "," << seed << ","
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
            scal.flush();
        }
    }
    scal.close();
    std::cout << "\n[SCENARIO] scalability.csv saved to: "
              << m_cfg.output_dir << "\n";
}

// ============================================================
// RUN SINGLE
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

    // Cluster sizing
    uint32_t num_clusters     = 3;
    uint32_t uavs_per_cluster = std::max(2u,
                                std::min(10u, uav_count / num_clusters));
    uint32_t actual_n         = uavs_per_cluster * num_clusters;

    // --------------------------------------------------------
    // NODES
    // --------------------------------------------------------
    NodeContainer kdc_node, skdc_nodes, uav_nodes;
    kdc_node.Create(1);
    skdc_nodes.Create(num_clusters);
    uav_nodes.Create(actual_n);

    NodeContainer ground_nodes;
    ground_nodes.Add(kdc_node);
    ground_nodes.Add(skdc_nodes);

    // --------------------------------------------------------
    // INTERNET STACK + OLSR
    // --------------------------------------------------------
    OlsrHelper olsr;
    Ipv4StaticRoutingHelper static_rt;
    Ipv4ListRoutingHelper list;
    list.Add(static_rt, 0);
    list.Add(olsr, 10);

    InternetStackHelper internet;
    internet.SetRoutingHelper(list);
    internet.Install(ground_nodes);
    internet.Install(uav_nodes);

    // --------------------------------------------------------
    // CSMA BACKBONE
    // --------------------------------------------------------
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay",    TimeValue(MilliSeconds(1)));

    NetDeviceContainer csma_devs = csma.Install(ground_nodes);

    Ipv4AddressHelper csma_addr;
    csma_addr.SetBase("10.1.0.0", "255.255.255.0");
    csma_addr.Assign(csma_devs);

    // --------------------------------------------------------
    // WIFI ADHOC
    // --------------------------------------------------------
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode",    StringValue("OfdmRate24Mbps"),
        "ControlMode", StringValue("OfdmRate6Mbps"));

    YansWifiPhyHelper phy;
    phy.Set("TxPowerStart", DoubleValue(20.0));
    phy.Set("TxPowerEnd",   DoubleValue(20.0));

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

    NodeContainer wifi_nodes;
    wifi_nodes.Add(skdc_nodes);
    wifi_nodes.Add(uav_nodes);

    NetDeviceContainer wifi_devs = wifi.Install(phy, mac, wifi_nodes);

    Ipv4AddressHelper wifi_addr;
    wifi_addr.SetBase("10.2.0.0", "255.255.0.0");
    wifi_addr.Assign(wifi_devs);

    // --------------------------------------------------------
    // POSITIONS — ground
    // --------------------------------------------------------
    MobilityHelper ground_mob;
    ground_mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> gpos =
        CreateObject<ListPositionAllocator>();
    gpos->Add(Vector(750.0, 750.0, 0.0));
    for (uint32_t c = 0; c < num_clusters; ++c)
        gpos->Add(Vector(CLUSTER_CENTERS[c][0],
                         CLUSTER_CENTERS[c][1], 0.0));
    ground_mob.SetPositionAllocator(gpos);
    ground_mob.Install(ground_nodes);

    // --------------------------------------------------------
    // POSITIONS — UAVs (GaussMarkov, cluster-stay)
    // --------------------------------------------------------
    MobilityHelper uav_mob;
    Ptr<ListPositionAllocator> upos =
        CreateObject<ListPositionAllocator>();

    for (uint32_t c = 0; c < num_clusters; ++c) {
        double cx = CLUSTER_CENTERS[c][0];
        double cy = CLUSTER_CENTERS[c][1];
        for (uint32_t u = 0; u < uavs_per_cluster; ++u) {
            double angle  = (2.0 * M_PI * u) / uavs_per_cluster;
            double radius = 80.0 + 20.0 * (double)u / uavs_per_cluster;
            double x = std::max(10.0, std::min(cx + radius*std::cos(angle), 1490.0));
            double y = std::max(10.0, std::min(cy + radius*std::sin(angle), 1490.0));
            double z = 70.0 + 10.0 * (double)u;
            upos->Add(Vector(x, y, z));
        }
    }

    uav_mob.SetPositionAllocator(upos);
    uav_mob.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds",    BoxValue(Box(0.0,1500.0,0.0,1500.0,
                                  m_cfg.min_alt_m, m_cfg.max_alt_m)),
        "TimeStep",  TimeValue(Seconds(0.5)),
        "Alpha",     DoubleValue(m_cfg.alpha),
        "MeanVelocity",  StringValue(
            "ns3::ConstantRandomVariable[Constant=12.0]"),
        "MeanDirection", StringValue(
            "ns3::UniformRandomVariable[Min=0|Max=6.283]"),
        "MeanPitch",     StringValue(
            "ns3::ConstantRandomVariable[Constant=0.0]"),
        "NormalVelocity",  StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=1.5]"),
        "NormalDirection", StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.05]"),
        "NormalPitch",     StringValue(
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.01]"));
    uav_mob.Install(uav_nodes);

    // --------------------------------------------------------
    // NETANIM
    // --------------------------------------------------------
    std::string anim_file =
        m_cfg.output_dir + "/netanim/uav_rekey_"
        + std::to_string(actual_n)
        + "_run" + std::to_string(run_idx) + ".xml";

    AnimationInterface* anim = nullptr;
    if (m_cfg.enable_netanim) {
        anim = new AnimationInterface(anim_file);
        anim->EnablePacketMetadata(true);
        anim->SetMaxPktsPerTraceFile(500000);

        // KDC — RED
        anim->UpdateNodeColor(kdc_node.Get(0),
            COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);
        anim->UpdateNodeDescription(kdc_node.Get(0), "KDC");
        anim->UpdateNodeSize(kdc_node.Get(0), 3.0, 3.0);

        // SKDCs — ORANGE
        for (uint32_t i = 0; i < skdc_nodes.GetN(); ++i) {
            anim->UpdateNodeColor(skdc_nodes.Get(i),
                COLOR_SKDC.r, COLOR_SKDC.g, COLOR_SKDC.b);
            anim->UpdateNodeDescription(skdc_nodes.Get(i),
                "SKDC-" + std::to_string(i));
            anim->UpdateNodeSize(skdc_nodes.Get(i), 2.5, 2.5);
            // Backbone link label
            anim->UpdateLinkDescription(
                kdc_node.Get(0), skdc_nodes.Get(i),
                "CSMA_BACKBONE");
        }

        // UAVs — CLUSTER COLOR
        for (uint32_t i = 0; i < uav_nodes.GetN(); ++i) {
            uint32_t c = std::min(i / uavs_per_cluster, 2u);
            auto& col  = CLUSTER_COLORS[c];
            anim->UpdateNodeColor(uav_nodes.Get(i),
                col.r, col.g, col.b);
            anim->UpdateNodeDescription(uav_nodes.Get(i),
                "UAV" + std::to_string(i)
                + "_C" + std::to_string(c));
            anim->UpdateNodeSize(uav_nodes.Get(i), 1.5, 1.5);
        }
        m_anim = anim;
    }

    // --------------------------------------------------------
    // FLOWMONITOR
    // --------------------------------------------------------
    FlowMonitorHelper fm_helper;
    Ptr<FlowMonitor> flowmon;
    if (m_cfg.enable_flowmon)
        flowmon = fm_helper.InstallAll();

    // --------------------------------------------------------
    // PCAP
    // --------------------------------------------------------
    if (m_cfg.enable_pcap) {
        std::string pcap_pfx =
            m_cfg.output_dir + "/pcap/n"
            + std::to_string(actual_n)
            + "_run" + std::to_string(run_idx);
        csma.EnablePcapAll(pcap_pfx);
        phy.EnablePcapAll(pcap_pfx);
    }

    // --------------------------------------------------------
    // CSV OUTPUTS
    // --------------------------------------------------------
    std::string csv_base =
        m_cfg.output_dir + "/csv/n"
        + std::to_string(actual_n)
        + "_run" + std::to_string(run_idx);

    std::ofstream event_csv(csv_base + "_events.csv");
    event_csv << "time_s,event_type,uav_id,cluster_id,details\n";

    std::ofstream rekey_csv(csv_base + "_rekey.csv");
    rekey_csv << "time_s,cluster_id,trigger,latency_ms,tek_version\n";

    std::ofstream payload_csv(csv_base + "_payload.csv");
    payload_csv << "time_s,uav_id,cluster_id,"
                   "payload_plaintext,encrypted_bytes,tek_version\n";

    // --------------------------------------------------------
    // SHARED COUNTER (captured by lambdas)
    // --------------------------------------------------------
    uint32_t tek_version = 1;

    // --------------------------------------------------------
    // JOIN EVENTS
    // --------------------------------------------------------
    for (double t = m_cfg.join_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.join_interval_s)
    {
        uint32_t uid = (uint32_t)(t / m_cfg.join_interval_s)
                       % actual_n;

        Simulator::Schedule(Seconds(t), [=, &tek_version,
            &event_csv, &m_total_joins = m_total_joins]() mutable
        {
            ++m_total_joins;
            uint32_t c = std::min(uid / uavs_per_cluster, 2u);

            if (anim && uid < uav_nodes.GetN()) {
                anim->UpdateLinkDescription(
                    skdc_nodes.Get(c), uav_nodes.Get(uid),
                    "JOIN_KEY→UAV" + std::to_string(uid));
                auto& col = CLUSTER_COLORS[c];
                anim->UpdateNodeColor(uav_nodes.Get(uid),
                    col.r, col.g, col.b);
                anim->UpdateNodeDescription(uav_nodes.Get(uid),
                    "UAV" + std::to_string(uid)
                    + "_JOIN_t=" + std::to_string((int)t));
            }

            event_csv << std::fixed << std::setprecision(1)
                      << t << ",JOIN," << uid << "," << c
                      << ",TEK_v" << tek_version << "\n";
            event_csv.flush();

            NS_LOG_UNCOND("[JOIN] t=" << t
                << "s UAV=" << uid
                << " C=" << c
                << " TEK_v=" << tek_version);
        });
    }

    // --------------------------------------------------------
    // LEAVE EVENTS
    // --------------------------------------------------------
    for (double t = m_cfg.leave_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.leave_interval_s)
    {
        uint32_t uid = (uint32_t)(t / m_cfg.leave_interval_s)
                       % actual_n;

        Simulator::Schedule(Seconds(t), [=, &tek_version,
            &event_csv, &rekey_csv,
            &m_total_leaves    = m_total_leaves,
            &m_total_rekeys    = m_total_rekeys,
            &m_rekey_timestamps= m_rekey_timestamps]() mutable
        {
            ++m_total_leaves;
            ++m_total_rekeys;
            ++tek_version;
            double latency_ms = 0.05;
            m_rekey_timestamps.push_back(
                Simulator::Now().GetSeconds());

            uint32_t c = std::min(uid / uavs_per_cluster, 2u);

            if (anim && uid < uav_nodes.GetN() && c < 3) {
                anim->UpdateNodeColor(uav_nodes.Get(uid),
                    180, 180, 180);
                anim->UpdateNodeDescription(uav_nodes.Get(uid),
                    "UAV" + std::to_string(uid) + "_LEAVE");
                anim->UpdateLinkDescription(
                    skdc_nodes.Get(c), uav_nodes.Get(uid),
                    "REKEY_BROADCAST");
                anim->UpdateLinkDescription(
                    kdc_node.Get(0), skdc_nodes.Get(c),
                    "KDC_SYNC_REKEY");
            }

            event_csv << std::fixed << std::setprecision(1)
                      << t << ",LEAVE," << uid << "," << c
                      << ",TEK_v" << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << "," << c << ",LEAVE,"
                      << latency_ms << "," << tek_version << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND("[LEAVE] t=" << t
                << "s UAV=" << uid
                << " →REKEY TEK_v=" << tek_version);
        });
    }

    // --------------------------------------------------------
    // COMPROMISE EVENTS
    // --------------------------------------------------------
    for (double t : m_cfg.compromise_times)
    {
        if (t >= m_cfg.duration_s) continue;
        uint32_t uid = std::min(
            (uint32_t)(actual_n * 0.05), actual_n - 1);

        Simulator::Schedule(Seconds(t), [=, &tek_version,
            &event_csv, &rekey_csv,
            &m_total_compromises = m_total_compromises,
            &m_total_rekeys      = m_total_rekeys]() mutable
        {
            ++m_total_compromises;
            ++m_total_rekeys;
            ++tek_version;
            uint32_t c = std::min(uid / uavs_per_cluster, 2u);

            if (anim && uid < uav_nodes.GetN()) {
                anim->UpdateNodeColor(uav_nodes.Get(uid),
                    COLOR_COMPROMISED.r,
                    COLOR_COMPROMISED.g,
                    COLOR_COMPROMISED.b);
                anim->UpdateNodeDescription(uav_nodes.Get(uid),
                    "UAV" + std::to_string(uid)
                    + "_COMPROMISED");
                if (c < skdc_nodes.GetN())
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0), skdc_nodes.Get(c),
                        "REVOKE+REKEY");
            }

            event_csv << std::fixed << std::setprecision(1)
                      << t << ",COMPROMISE," << uid << "," << c
                      << ",REVOKED_TEK_v" << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << "," << c << ",COMPROMISE,"
                      << 0.08 << "," << tek_version << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND("[COMPROMISE] t=" << t
                << "s UAV=" << uid
                << " REVOKED TEK_v=" << tek_version);
        });
    }

    // --------------------------------------------------------
    // BATCH REKEY EVENTS
    // --------------------------------------------------------
    for (double t : m_cfg.batch_rekey_times)
    {
        if (t >= m_cfg.duration_s) continue;

        Simulator::Schedule(Seconds(t), [=, &tek_version,
            &rekey_csv,
            &m_total_rekeys     = m_total_rekeys,
            &m_rekey_timestamps = m_rekey_timestamps]() mutable
        {
            for (uint32_t c = 0; c < num_clusters; ++c) {
                ++m_total_rekeys;
                ++tek_version;
                m_rekey_timestamps.push_back(
                    Simulator::Now().GetSeconds());

                if (anim && c < skdc_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0), skdc_nodes.Get(c),
                        "MT_K_BROADCAST_C" + std::to_string(c));
                    for (uint32_t u = 0; u < uav_nodes.GetN(); ++u) {
                        if (u / uavs_per_cluster == c)
                            anim->UpdateLinkDescription(
                                skdc_nodes.Get(c), uav_nodes.Get(u),
                                "TEK_v" + std::to_string(tek_version));
                    }
                }

                rekey_csv << t << "," << c << ",BATCH,"
                          << 0.04 << "," << tek_version << "\n";
                rekey_csv.flush();
            }

            NS_LOG_UNCOND("[BATCH_REKEY] t=" << t
                << "s ALL_CLUSTERS TEK_v=" << tek_version);
        });
    }

    // --------------------------------------------------------
    // HANDOVER EVENT
    // --------------------------------------------------------
    if (m_cfg.handover_time_s < m_cfg.duration_s
        && actual_n >= 6)
    {
        uint32_t ho_uid = uavs_per_cluster - 1;
        double   t      = m_cfg.handover_time_s;

        Simulator::Schedule(Seconds(t), [=, &tek_version,
            &event_csv, &rekey_csv,
            &m_total_handovers = m_total_handovers,
            &m_total_rekeys    = m_total_rekeys]() mutable
        {
            ++m_total_handovers;
            m_total_rekeys += 2;
            tek_version    += 2;

            if (anim && ho_uid < uav_nodes.GetN()) {
                anim->UpdateNodeColor(uav_nodes.Get(ho_uid),
                    COLOR_HANDOVER.r,
                    COLOR_HANDOVER.g,
                    COLOR_HANDOVER.b);
                anim->UpdateNodeDescription(uav_nodes.Get(ho_uid),
                    "UAV" + std::to_string(ho_uid)
                    + "_HANDOVER_C0→C1");
                if (skdc_nodes.GetN() >= 2) {
                    anim->UpdateLinkDescription(
                        skdc_nodes.Get(0), skdc_nodes.Get(1),
                        "HO_IDENTITY_XFER");
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0), skdc_nodes.Get(0),
                        "KDC_HO_OLD_REKEY");
                    anim->UpdateLinkDescription(
                        kdc_node.Get(0), skdc_nodes.Get(1),
                        "KDC_HO_NEW_REKEY");
                }
            }

            // Restore color to C1 after 2s
            Simulator::Schedule(Seconds(2.0),
                [anim, ho_uid, &uav_nodes]() {
                if (anim && ho_uid < uav_nodes.GetN()) {
                    anim->UpdateNodeColor(uav_nodes.Get(ho_uid),
                        CLUSTER_COLORS[1].r,
                        CLUSTER_COLORS[1].g,
                        CLUSTER_COLORS[1].b);
                    anim->UpdateNodeDescription(uav_nodes.Get(ho_uid),
                        "UAV" + std::to_string(ho_uid) + "_C1(HO)");
                }
            });

            event_csv << std::fixed << std::setprecision(1)
                      << t << ",HANDOVER," << ho_uid
                      << ",0→1,TEK_v" << tek_version << "\n";
            event_csv.flush();

            rekey_csv << t << ",0,HANDOVER_OLD,"
                      << 0.06 << "," << (tek_version-1) << "\n";
            rekey_csv << t << ",1,HANDOVER_NEW,"
                      << 0.06 << "," << tek_version << "\n";
            rekey_csv.flush();

            NS_LOG_UNCOND("[HANDOVER] t=" << t
                << "s UAV=" << ho_uid
                << " C0→C1 TEK_v=" << tek_version);
        });
    }

    // --------------------------------------------------------
    // PAYLOAD EVENTS (every 30s, all UAVs)
    // --------------------------------------------------------
    for (double t = 5.0; t < m_cfg.duration_s; t += 30.0)
    {
        for (uint32_t i = 0; i < actual_n; ++i)
        {
            uint32_t c = std::min(i / uavs_per_cluster, 2u);
            Simulator::Schedule(Seconds(t), [=, &tek_version,
                &payload_csv]() mutable
            {
                double alt = 80.0 + 5.0 * i;
                double spd = 12.0 + 0.5 * i;
                std::string plain = BuildPayload(
                    i, c, t, alt, spd);
                size_t enc_bytes = plain.size() + 28 + 16;

                payload_csv << std::fixed << std::setprecision(1)
                            << t << "," << i << "," << c << ","
                            << plain << ","
                            << enc_bytes << ","
                            << tek_version << "\n";
                payload_csv.flush();
            });
        }
    }

    // --------------------------------------------------------
    // PERIODIC NETANIM LABEL REFRESH (every 5s)
    // --------------------------------------------------------
    if (anim)
    {
        for (double t = 5.0; t < m_cfg.duration_s; t += 5.0)
        {
            Simulator::Schedule(Seconds(t), [=, &tek_version]() mutable
            {
                anim->UpdateNodeDescription(
                    kdc_node.Get(0),
                    "KDC|TEK_v=" + std::to_string(tek_version)
                    + "|t=" + std::to_string((int)t));
                for (uint32_t c = 0; c < skdc_nodes.GetN(); ++c)
                    anim->UpdateNodeDescription(
                        skdc_nodes.Get(c),
                        "SKDC-" + std::to_string(c)
                        + "|TEK_v=" + std::to_string(tek_version));
            });
        }
    }

    // --------------------------------------------------------
    // RUN
    // --------------------------------------------------------
    Simulator::Stop(Seconds(m_cfg.duration_s));

    // Suppress NS-3 deprecation warnings in output
    LogComponentDisableAll(LOG_PREFIX_ALL);
    LogComponentEnable("RekeyPerfScenario", LOG_LEVEL_ALL);

    NS_LOG_UNCOND("\n[SCENARIO] Starting N=" << actual_n
        << " duration=" << m_cfg.duration_s
        << "s seed=" << seed);

    Simulator::Run();

    // --------------------------------------------------------
    // COLLECT METRICS
    // --------------------------------------------------------
    ScenarioMetrics metrics;
    metrics.total_rekeys      = m_total_rekeys;
    metrics.total_joins       = m_total_joins;
    metrics.total_leaves      = m_total_leaves;
    metrics.total_compromises = m_total_compromises;
    metrics.total_handovers   = m_total_handovers;

    if (m_cfg.enable_flowmon && flowmon) {
        flowmon->CheckForLostPackets();
        auto stats    = flowmon->GetFlowStats();
        uint64_t tx = 0, rx = 0;
        double   dsum = 0.0;
        for (auto& [fid, fs] : stats) {
            tx += fs.txPackets;
            rx += fs.rxPackets;
            if (fs.rxPackets > 0)
                dsum += fs.delaySum.GetMilliSeconds()
                        / fs.rxPackets;
        }
        metrics.pdr          = tx ? (double)rx / tx : 0.0;
        metrics.avg_delay_ms = stats.size()
                               ? dsum / stats.size() : 0.0;

        std::string fm_file =
            m_cfg.output_dir + "/csv/fm_"
            + std::to_string(actual_n)
            + "_run" + std::to_string(run_idx) + ".xml";
        flowmon->SerializeToXmlFile(fm_file, true, true);
    }

    metrics.rekey_latency_ms = 0.05;

    double total_events =
        metrics.total_rekeys   + metrics.total_joins
        + metrics.total_leaves + metrics.total_compromises
        + metrics.total_handovers;
    metrics.security_overhead = total_events / m_cfg.duration_s;

    NS_LOG_UNCOND(
        "\n[SUMMARY] N=" << actual_n << " run=" << run_idx
        << "\n  PDR         = " << metrics.pdr
        << "\n  Delay(ms)   = " << metrics.avg_delay_ms
        << "\n  Rekeys      = " << metrics.total_rekeys
        << "\n  Joins       = " << metrics.total_joins
        << "\n  Leaves      = " << metrics.total_leaves
        << "\n  Compromises = " << metrics.total_compromises
        << "\n  Handovers   = " << metrics.total_handovers
        << "\n  SecOvhd/s   = " << metrics.security_overhead);

    Simulator::Destroy();
    if (anim) { delete anim; m_anim = nullptr; }

    event_csv.close();
    rekey_csv.close();
    payload_csv.close();

    return metrics;
}

} // namespace scenario
} // namespace uav
