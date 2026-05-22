/**
 * metrics/uav-sinr-metrics.cc
 * Module 58 — SINR Metrics
 */

#include "metrics/uav-sinr-metrics.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <limits>

NS_LOG_COMPONENT_DEFINE("UavSinrMetrics");

using namespace ns3;

namespace uav {
namespace metrics {

SinrMetrics::SinrMetrics(
    const routing::TopologyResult* topo,
    apps::JammerManager*           jammer_mgr)
    : m_topo(topo)
    , m_jammer_mgr(jammer_mgr)
{
    m_uav_sinr.fill(0.0);
    m_uav_jammed.fill(false);
    m_uav_drop_prob.fill(0.0);
    m_uav_impact.fill(0.0);
    m_cluster_avg_sinr.fill(0.0);
    m_cluster_jammed.fill(0);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "SinrMetrics: constructed");
}

void SinrMetrics::Compute()
{
    if (!m_jammer_mgr) return;

    m_cluster_avg_sinr.fill(0.0);
    m_cluster_jammed.fill(0);
    m_jammed_count = 0;

    double sum = 0.0;
    double min_v = std::numeric_limits<double>::max();
    double max_v = -std::numeric_limits<double>::max();

    std::array<double, 3>    cluster_sum{};
    cluster_sum.fill(0.0);

    for (uint32_t i = 0; i < 18; ++i) {
        double sinr = m_jammer_mgr->ComputeSinr(i);
        bool   jammed = m_jammer_mgr->IsJammed(i);
        double drop = m_jammer_mgr->GetDropProbability(i);
        double impact = m_jammer_mgr->GetJammerImpact(i);

        m_uav_sinr[i]      = sinr;
        m_uav_jammed[i]    = jammed;
        m_uav_drop_prob[i] = drop;
        m_uav_impact[i]    = impact;

        uint32_t cluster = i / 6;
        cluster_sum[cluster]      += sinr;
        if (jammed) {
            ++m_cluster_jammed[cluster];
            ++m_jammed_count;
        }

        sum += sinr;
        if (sinr < min_v) min_v = sinr;
        if (sinr > max_v) max_v = sinr;

        // Record sample
        SinrSample s;
        s.time_s    = Simulator::Now().GetSeconds();
        s.uav_id    = i;
        s.sinr_db   = sinr;
        s.jammed    = jammed;
        s.drop_prob = drop;
        m_samples.push_back(s);
    }

    for (uint32_t c = 0; c < 3; ++c)
        m_cluster_avg_sinr[c] = cluster_sum[c] / 6.0;

    m_global_avg_sinr = sum / 18.0;
    m_global_min_sinr =
        (min_v == std::numeric_limits<double>::max())
        ? 0.0 : min_v;
    m_global_max_sinr =
        (max_v == -std::numeric_limits<double>::max())
        ? 0.0 : max_v;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "SinrMetrics: computed"
        " avg=" << m_global_avg_sinr << "dB"
        << " min=" << m_global_min_sinr << "dB"
        << " max=" << m_global_max_sinr << "dB"
        << " jammed=" << m_jammed_count);
}

void SinrMetrics::SchedulePeriodicSample(
    double interval_s)
{
    if (interval_s <= 0.0) return;
    m_sample_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &SinrMetrics::PeriodicSampleCallback, this);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "SinrMetrics: periodic sampling every "
        << interval_s << "s");
}

void SinrMetrics::PeriodicSampleCallback()
{
    Compute();
    Simulator::Schedule(
        Seconds(m_sample_interval),
        &SinrMetrics::PeriodicSampleCallback, this);
}

double SinrMetrics::GetUavSinr(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_sinr[uav_id];
}

bool SinrMetrics::IsUavJammed(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return false;
    return m_uav_jammed[uav_id];
}

double SinrMetrics::GetUavDropProb(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_drop_prob[uav_id];
}

double SinrMetrics::GetUavImpact(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return 0.0;
    return m_uav_impact[uav_id];
}

double SinrMetrics::GetClusterAvgSinr(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0.0;
    return m_cluster_avg_sinr[cluster_id];
}

utils::u32 SinrMetrics::GetClusterJammedCount(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0;
    return m_cluster_jammed[cluster_id];
}

void SinrMetrics::PrintSummary() const
{
    std::cout << "\n=== SINR Metrics ===\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Threshold:  "
              << apps::JammerManager::SINR_THRESHOLD_DB
              << " dB\n";
    std::cout << "  Global avg: "
              << m_global_avg_sinr << " dB\n";
    std::cout << "  Global min: "
              << m_global_min_sinr << " dB\n";
    std::cout << "  Global max: "
              << m_global_max_sinr << " dB\n";
    std::cout << "  Jammed UAVs: "
              << m_jammed_count << "/18\n";
    for (uint32_t c = 0; c < 3; ++c) {
        std::cout << "  C" << c
            << " avg=" << m_cluster_avg_sinr[c]
            << "dB jammed="
            << m_cluster_jammed[c] << "\n";
    }
    for (uint32_t i = 0; i < 18; ++i) {
        std::cout << "  UAV" << i
            << " SINR=" << m_uav_sinr[i] << "dB"
            << (m_uav_jammed[i] ? " [JAMMED]" : "")
            << " drop=" << m_uav_drop_prob[i] << "\n";
    }
}

void SinrMetrics::WriteCsv(
    const std::string& filename) const
{
    std::ofstream f(filename);
    if (!f.is_open()) return;
    f << "uav_id,cluster_id,sinr_db,"
         "jammed,drop_prob,impact\n";
    for (uint32_t i = 0; i < 18; ++i) {
        f << i << "," << (i/6) << ","
          << m_uav_sinr[i]      << ","
          << m_uav_jammed[i]    << ","
          << m_uav_drop_prob[i] << ","
          << m_uav_impact[i]    << "\n";
    }
    f.close();
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "SinrMetrics: wrote " << filename);
}

} // namespace metrics
} // namespace uav
