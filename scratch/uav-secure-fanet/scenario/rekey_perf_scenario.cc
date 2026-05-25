/**
 * scenario/rekey_perf_scenario.cc
 * RekeyPerfScenario — uses REAL existing app layer
 *
 * Keeps: topology, mobility, NetAnim, FlowMonitor, CSV
 * Adds:  KdcApplication, SkdcApplication, UavApplication,
 *        TekManager, MulticastManager, MtkDistributionManager,
 *        RekeyManager, JoinEventManager, LeaveEventManager,
 *        CompromiseDetector, JammerManager
 */

#include "rekey_perf_scenario.h"

// NS-3
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

// Project headers
#include "apps/uav-kdc-app.h"
#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-tek-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-join-event.h"
#include "apps/uav-leave-event.h"
#include "apps/uav-rekey-manager.h"
#include "apps/uav-compromise-detector.h"
#include "crypto/uav-crypto-params.h"
#include "crypto/uav-openssl-ctx.h"
#include "mobility/uav-mobility-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-logger.h"
#include "crypto/uav-openssl-ctx.h"
#include "routing/uav-topology.h"
#include "utils/uav-logger.h"

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
#include <sys/stat.h>

NS_LOG_COMPONENT_DEFINE("RekeyPerfScenario");

using namespace ns3;

namespace uav {
namespace scenario {

// ===========================================================================
// Colors
// ===========================================================================
struct ClusterColor { uint8_t r, g, b; };
static constexpr ClusterColor CLUSTER_COLORS[3] = {
    {  0, 100, 255},
    {  0, 200, 200},
    {  0, 200,  80},
};
static constexpr ClusterColor COLOR_KDC  = {220,   0,   0};
static constexpr ClusterColor COLOR_SKDC = {255, 140,   0};

static constexpr double CLUSTER_CENTERS[3][2] = {
    { 250.0,  750.0},
    { 750.0,  250.0},
    {1250.0,  750.0},
};

static const char* CRYPTO_JSON =
    "/home/udit/ns-allinone-3.43/ns-3.43"
    "/scratch/uav-secure-fanet/json/crypto_params.json";

// ===========================================================================
// Config constructor
// ===========================================================================
RekeyPerfScenarioConfig::RekeyPerfScenarioConfig()
    : uav_counts({6, 9, 12, 15, 18})
    , duration_s(120.0)
    , runs_per_config(3)
    , seed_base(642)
    , join_interval_s(20.0)
    , join_start_s(5.0)
    , leave_interval_s(25.0)
    , leave_start_s(10.0)
    , compromise_times({50.0})
    , batch_rekey_times({60.0})
    , handover_time_s(80.0)
    , min_speed_mps(10.0)
    , max_speed_mps(25.0)
    , alpha(0.3)
    , variance(8.0)
    , min_alt_m(50.0)
    , max_alt_m(150.0)
    , enable_netanim(false)
    , enable_pcap(false)
    , enable_flowmon(true)
    , output_dir("scratch/uav-secure-fanet/output/rekey_perf")
{}

// ===========================================================================
// Constructor
// ===========================================================================
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

// ===========================================================================
// RunAll
// ===========================================================================
void RekeyPerfScenario::RunAll()
{
    // Create output dirs
    mkdir(m_cfg.output_dir.c_str(), 0755);
    mkdir((m_cfg.output_dir+"/csv").c_str(),     0755);
    mkdir((m_cfg.output_dir+"/netanim").c_str(), 0755);
    mkdir((m_cfg.output_dir+"/pcap").c_str(),    0755);

    std::ofstream scalability_csv(
        m_cfg.output_dir + "/scalability.csv");
    scalability_csv
        << "uav_count,run,seed,pdr,throughput_kbps,"
           "avg_delay_ms,rekey_latency_ms,total_rekeys,"
           "total_joins,total_leaves,total_compromises,"
           "total_handovers,security_overhead\n";

    for (uint32_t n : m_cfg.uav_counts) {
        for (uint32_t run = 0;
             run < m_cfg.runs_per_config; ++run)
        {
            uint32_t seed = m_cfg.seed_base + run;
            ScenarioMetrics m = RunSingle(n, seed, run);

            scalability_csv
                << n            << ","
                << run          << ","
                << seed         << ","
                << m.pdr        << ","
                << m.throughput_kbps    << ","
                << m.avg_delay_ms       << ","
                << m.rekey_latency_ms   << ","
                << m.total_rekeys       << ","
                << m.total_joins        << ","
                << m.total_leaves       << ","
                << m.total_compromises  << ","
                << m.total_handovers    << ","
                << m.security_overhead  << "\n";
            scalability_csv.flush();
        }
    }
    scalability_csv.close();
    NS_LOG_UNCOND("[SCENARIO] All runs complete. "
        << "Results: " << m_cfg.output_dir
        << "/scalability.csv");
}

// ===========================================================================
// RunSingle — uses REAL existing app layer
// ===========================================================================
ScenarioMetrics RekeyPerfScenario::RunSingle(
    uint32_t uav_count,
    uint32_t seed,
    uint32_t run_idx)
{
    m_total_rekeys      = 0;
    m_total_joins       = 0;
    m_total_leaves      = 0;
    m_total_compromises = 0;
    m_total_handovers   = 0;
    m_rekey_timestamps.clear();
    m_sinr_samples.clear();

    RngSeedManager::SetSeed(seed);

    // Cluster sizing — always 3 clusters
    uint32_t num_clusters     = 3;
    uint32_t uavs_per_cluster =
        std::max(2u, std::min(10u, uav_count/num_clusters));
    uint32_t actual_n = uavs_per_cluster * num_clusters;

    // --------------------------------------------------------
    // Load crypto params (always 18 UAVs in JSON)
    // Use first actual_n UAVs
    // --------------------------------------------------------
    OpenSSLInit::Bootstrap();

    crypto::CryptoParamsFile params =
        crypto::CryptoParamsLoader::LoadFromFile(CRYPTO_JSON);

    // --------------------------------------------------------
    // Use existing TopologyBuilder for correct node setup
    // --------------------------------------------------------
    routing::TopologyConfig topo_cfg;
    topo_cfg.total_uavs       = actual_n;
    topo_cfg.num_clusters     = num_clusters;
    topo_cfg.uavs_per_cluster = uavs_per_cluster;

    routing::TopologyBuilder builder(topo_cfg);
    routing::TopologyResult  topo = builder.Build();

    // --------------------------------------------------------
    // Mobility — override with scenario config
    // --------------------------------------------------------
    mobility::MobilityConfig mob_cfg;
    mob_cfg.alpha              = m_cfg.alpha;
    mob_cfg.mean_velocity      = (m_cfg.min_speed_mps +
                                  m_cfg.max_speed_mps) / 2.0;
    mob_cfg.variance           = m_cfg.variance;
    mob_cfg.min_altitude_m     = m_cfg.min_alt_m;
    mob_cfg.max_altitude_m     = m_cfg.max_alt_m;
    mob_cfg.update_interval_s  = 0.5;

    mobility::MobilityManager mob_mgr(topo, mob_cfg);
    mob_mgr.InstallGaussMarkov();

    // --------------------------------------------------------
    // FlowMonitor
    // --------------------------------------------------------
    FlowMonitorHelper fm_helper;
    Ptr<FlowMonitor> flowmon;
    if (m_cfg.enable_flowmon)
        flowmon = fm_helper.InstallAll();

    // --------------------------------------------------------
    // PCAP
    // --------------------------------------------------------
    if (m_cfg.enable_pcap) {
        std::string pfx = m_cfg.output_dir + "/pcap/n"
            + std::to_string(actual_n) + "_run"
            + std::to_string(run_idx);
        builder.EnablePcap(pfx, topo);
    }

    // --------------------------------------------------------
    // NetAnim
    // --------------------------------------------------------
    AnimationInterface* anim = nullptr;
    if (m_cfg.enable_netanim) {
        std::string af = m_cfg.output_dir
            + "/netanim/uav_rekey_"
            + std::to_string(actual_n)
            + "_run" + std::to_string(run_idx) + ".xml";
        anim = new AnimationInterface(af);
        anim->EnablePacketMetadata(true);
        anim->SetMobilityPollInterval(MilliSeconds(100));

        // KDC
        anim->UpdateNodeColor(topo.kdc_node.Get(0),
            COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);
        anim->UpdateNodeDescription(
            topo.kdc_node.Get(0), "KDC");
        anim->UpdateNodeSize(
            topo.kdc_node.Get(0), 3.0, 3.0);

        // SKDCs
        for (uint32_t i = 0;
             i < topo.skdc_nodes.GetN(); ++i) {
            anim->UpdateNodeColor(topo.skdc_nodes.Get(i),
                COLOR_SKDC.r, COLOR_SKDC.g, COLOR_SKDC.b);
            anim->UpdateNodeDescription(
                topo.skdc_nodes.Get(i),
                "SKDC-C" + std::to_string(i));
            anim->UpdateNodeSize(
                topo.skdc_nodes.Get(i), 2.5, 2.5);
        }

        // UAVs — cluster color
        for (uint32_t i = 0;
             i < topo.uav_nodes.GetN(); ++i) {
            uint32_t c = i / uavs_per_cluster;
            auto& col  = CLUSTER_COLORS[
                std::min(c, 2u)];
            anim->UpdateNodeColor(
                topo.uav_nodes.Get(i),
                col.r, col.g, col.b);
            anim->UpdateNodeDescription(
                topo.uav_nodes.Get(i),
                "UAV" + std::to_string(i)
                + "_C" + std::to_string(c));
        }
        m_anim = anim;
    }

    // --------------------------------------------------------
    // CSV outputs
    // --------------------------------------------------------
    std::string csv_base = m_cfg.output_dir
        + "/csv/n" + std::to_string(actual_n)
        + "_run" + std::to_string(run_idx);

    std::ofstream event_csv(csv_base + "_events.csv");
    event_csv << "time_s,event_type,uav_id,"
                 "cluster_id,details\n";

    std::ofstream rekey_csv(csv_base + "_rekey.csv");
    rekey_csv << "time_s,cluster_id,trigger,"
                 "latency_ms,tek_version\n";

    // --------------------------------------------------------
    // KDC Application
    // --------------------------------------------------------
    Ptr<apps::KdcApplication> kdc_app =
        CreateObject<apps::KdcApplication>();
    kdc_app->SetTopology(&topo);
    kdc_app->SetCryptoParams(&params);
    topo.kdc_node.Get(0)->AddApplication(kdc_app);
    kdc_app->SetStartTime(Seconds(0.5));
    kdc_app->SetStopTime(Seconds(m_cfg.duration_s));

    // --------------------------------------------------------
    // SKDC Applications
    // --------------------------------------------------------
    std::array<Ptr<apps::SkdcApplication>, 3> skdc_apps;
    for (uint32_t c = 0; c < num_clusters; ++c) {
        skdc_apps[c] =
            CreateObject<apps::SkdcApplication>();
        skdc_apps[c]->SetClusterId(c);
        skdc_apps[c]->SetTopology(&topo);
        skdc_apps[c]->SetCryptoParams(&params);
        topo.skdc_nodes.Get(c)->AddApplication(
            skdc_apps[c]);
        skdc_apps[c]->SetStartTime(Seconds(1.0));
        skdc_apps[c]->SetStopTime(
            Seconds(m_cfg.duration_s));
    }

    // --------------------------------------------------------
    // UAV Applications
    // --------------------------------------------------------
    for (uint32_t i = 0;
         i < topo.uav_nodes.GetN(); ++i) {
        Ptr<apps::UavApplication> uav_app =
            CreateObject<apps::UavApplication>();
        uav_app->SetUavId(i, i % uavs_per_cluster,
                          i / uavs_per_cluster);
        uav_app->SetTopology(&topo);
        uav_app->SetCryptoParams(&params);
        topo.uav_nodes.Get(i)->AddApplication(uav_app);
        uav_app->SetStartTime(Seconds(2.0));
        uav_app->SetStopTime(Seconds(m_cfg.duration_s));
    }

    // --------------------------------------------------------
    // Security Managers
    // --------------------------------------------------------
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

    apps::CompromiseDetector comp_det(
        &topo, &mc_mgr, &dist_mgr, &tek_mgr, &leave_mgr);

    // Initial MTK broadcast
    dist_mgr.BroadcastAll(skdc_apps);
    dist_mgr.ScheduleRefresh(skdc_apps);

    // Periodic rekey every 60s
    for (uint32_t c = 0; c < num_clusters; ++c)
        rekey_mgr.SchedulePeriodic(
            c, skdc_apps[c], 60.0);

    // --------------------------------------------------------
    // Hook callbacks for metrics + CSV + NetAnim
    // --------------------------------------------------------
    rekey_mgr.SetRekeyCallback(
        [&, anim](const apps::RekeyEvent& ev) {
            ++m_total_rekeys;
            double t = Simulator::Now().GetSeconds();
            m_rekey_timestamps.push_back(t);
            rekey_csv << t << ","
                << ev.cluster_id << ","
                << apps::RekeyReasonStr(ev.reason) << ","
                << ev.latency_ms << ","
                << tek_mgr.GetVersion(ev.cluster_id)
                << "\n";
            if (anim) {
                anim->UpdateNodeDescription(
                    topo.skdc_nodes.Get(ev.cluster_id),
                    "SKDC-C" + std::to_string(ev.cluster_id)
                    + "|REKEY|TEK_v="
                    + std::to_string(
                        tek_mgr.GetVersion(ev.cluster_id)));
            }
        });

    comp_det.SetCallback(
        [&, anim](const apps::CompromiseEvent& ev) {
            ++m_total_compromises;
            double t = Simulator::Now().GetSeconds();
            event_csv << t << ",COMPROMISE,"
                << ev.uav_id << ","
                << ev.cluster_id << ","
                << "reason=" << (int)ev.reason << "\n";
            if (anim &&
                ev.uav_id < topo.uav_nodes.GetN()) {
                anim->UpdateNodeColor(
                    topo.uav_nodes.Get(ev.uav_id),
                    0, 0, 0); // black
                anim->UpdateNodeDescription(
                    topo.uav_nodes.Get(ev.uav_id),
                    "UAV" + std::to_string(ev.uav_id)
                    + "_COMPROMISED");
            }
        });

    // --------------------------------------------------------
    // Scheduled Security Events
    // --------------------------------------------------------

    // JOIN events
    for (double t = m_cfg.join_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.join_interval_s)
    {
        uint32_t uid = (uint32_t)(
            t / m_cfg.join_interval_s) % actual_n;
        Simulator::Schedule(Seconds(t),
            [&, uid, t, anim]() {
                uint32_t c = uid / uavs_per_cluster;
                if (c >= 3) return;
                ++m_total_joins;
                join_mgr.ProcessJoin(
                    uid, uid % uavs_per_cluster,
                    c, skdc_apps[c].operator->(),
                    nullptr);
                event_csv << t << ",JOIN,"
                    << uid << "," << c
                    << ",ok\n";
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateLinkDescription(
                        topo.skdc_nodes.Get(c),
                        topo.uav_nodes.Get(uid),
                        "JOIN_KEY");
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_JOINED_C"
                        + std::to_string(c));
                }
            });
    }

    // LEAVE events
    for (double t = m_cfg.leave_start_s;
         t < m_cfg.duration_s - 10.0;
         t += m_cfg.leave_interval_s)
    {
        uint32_t uid = (uint32_t)(
            t / m_cfg.leave_interval_s + 1) % actual_n;
        Simulator::Schedule(Seconds(t),
            [&, uid, t, anim]() {
                uint32_t c = uid / uavs_per_cluster;
                if (c >= 3) return;
                ++m_total_leaves;
                leave_mgr.ProcessLeave(
                    uid, uid % uavs_per_cluster,
                    c, skdc_apps[c].operator->());
                event_csv << t << ",LEAVE,"
                    << uid << "," << c
                    << ",ok\n";
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_LEFT");
                }
            });
    }

    // COMPROMISE events
    for (double t : m_cfg.compromise_times) {
        if (t >= m_cfg.duration_s) continue;
        Simulator::Schedule(Seconds(t),
            [&, t, anim]() {
                uint32_t uid = 0;
                uint32_t c   = 0;
                comp_det.ReportHmacFailure(
                    uid, c, uid, skdc_apps[c]);
                event_csv << t << ",COMPROMISE,"
                    << uid << "," << c
                    << ",hmac_fail\n";
            });
    }

    // BATCH REKEY events
    for (double t : m_cfg.batch_rekey_times) {
        if (t >= m_cfg.duration_s) continue;
        Simulator::Schedule(Seconds(t),
            [&, t, anim]() {
                rekey_mgr.GlobalRekey(
                    skdc_apps,
                    apps::RekeyReason::KDC_INIT);
                event_csv << t << ",BATCH_REKEY,"
                    << 255 << ",ALL,global\n";
                if (anim) {
                    for (uint32_t c = 0;
                         c < num_clusters; ++c) {
                        anim->UpdateNodeDescription(
                            topo.skdc_nodes.Get(c),
                            "SKDC-C"
                            + std::to_string(c)
                            + "|BATCH_REKEY");
                    }
                }
            });
    }

    // HANDOVER event
    if (m_cfg.handover_time_s < m_cfg.duration_s
        && actual_n >= 3)
    {
        Simulator::Schedule(
            Seconds(m_cfg.handover_time_s),
            [&, anim]() {
                uint32_t uid  = 1;
                uint32_t old_c = uid / uavs_per_cluster;
                uint32_t new_c = (old_c + 1) % 3;
                ++m_total_handovers;
                rekey_mgr.TriggerRekey(
                    old_c,
                    apps::RekeyReason::HANDOVER,
                    skdc_apps[old_c].operator->());
                rekey_mgr.TriggerRekey(
                    new_c,
                    apps::RekeyReason::HANDOVER,
                    skdc_apps[new_c].operator->());
                event_csv
                    << m_cfg.handover_time_s
                    << ",HANDOVER," << uid
                    << "," << old_c
                    << "→" << new_c << "\n";
                if (anim &&
                    uid < topo.uav_nodes.GetN()) {
                    anim->UpdateNodeColor(
                        topo.uav_nodes.Get(uid),
                        255, 255, 0); // yellow
                    anim->UpdateNodeDescription(
                        topo.uav_nodes.Get(uid),
                        "UAV" + std::to_string(uid)
                        + "_HANDOVER_C"
                        + std::to_string(old_c)
                        + "→C"
                        + std::to_string(new_c));
                }
            });
    }

    // --------------------------------------------------------
    // RUN
    // --------------------------------------------------------
    NS_LOG_UNCOND("\n[SCENARIO] Starting N=" << actual_n
        << " duration=" << m_cfg.duration_s
        << "s seed=" << seed);

    Simulator::Stop(Seconds(m_cfg.duration_s));
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
        auto stats = flowmon->GetFlowStats();
        uint64_t tx = 0, rx = 0;
        double   dsum = 0.0;
        double   tsum = 0.0;
        for (auto& [fid, fs] : stats) {
            tx += fs.txPackets;
            rx += fs.rxPackets;
            if (fs.rxPackets > 0) {
                dsum += fs.delaySum.GetMilliSeconds()
                        / fs.rxPackets;
                tsum += (double)fs.rxBytes * 8.0
                        / (m_cfg.duration_s * 1000.0);
            }
        }
        metrics.pdr = tx
            ? (double)rx / (double)tx : 0.0;
        metrics.avg_delay_ms = stats.size()
            ? dsum / stats.size() : 0.0;
        metrics.throughput_kbps = tsum;

        std::string fm_file = m_cfg.output_dir
            + "/csv/fm_" + std::to_string(actual_n)
            + "_run" + std::to_string(run_idx) + ".xml";
        flowmon->SerializeToXmlFile(fm_file, true, true);
    }

    // Rekey latency from history
    const auto& rk_hist = rekey_mgr.GetHistory();
    if (!rk_hist.empty()) {
        double sum = 0.0;
        for (const auto& r : rk_hist)
            sum += r.latency_ms;
        metrics.rekey_latency_ms = sum / rk_hist.size();
    }

    double total_events =
        metrics.total_rekeys   + metrics.total_joins
        + metrics.total_leaves + metrics.total_compromises
        + metrics.total_handovers;
    metrics.security_overhead =
        total_events / m_cfg.duration_s;

    NS_LOG_UNCOND(
        "\n[SUMMARY] N=" << actual_n
        << " run=" << run_idx
        << "\n  PDR         = " << metrics.pdr
        << "\n  Tput(kbps)  = " << metrics.throughput_kbps
        << "\n  Delay(ms)   = " << metrics.avg_delay_ms
        << "\n  Rekeys      = " << metrics.total_rekeys
        << "\n  Joins       = " << metrics.total_joins
        << "\n  Leaves      = " << metrics.total_leaves
        << "\n  Compromises = " << metrics.total_compromises
        << "\n  Handovers   = " << metrics.total_handovers
        << "\n  RekeyLat(ms)= " << metrics.rekey_latency_ms
        << "\n  SecOvhd/s   = "
        << metrics.security_overhead);

    Simulator::Destroy();
    if (anim) { delete anim; m_anim = nullptr; }
    event_csv.close();
    rekey_csv.close();

    return metrics;
}

} // namespace scenario
} // namespace uav
