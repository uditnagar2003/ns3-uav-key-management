/**
 * apps/uav-rekey-manager.cc
 * Module 46 - Rekey Event Logic
 */

#include "apps/uav-rekey-manager.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-time-utils.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <chrono>

NS_LOG_COMPONENT_DEFINE("UavRekeyManager");

using namespace ns3;

namespace uav {
namespace apps {

RekeyManager::RekeyManager(
    const routing::TopologyResult*  topo,
    const crypto::CryptoParamsFile* params,
    TekManager*                     tek_mgr,
    MtkDistributionManager*         dist_mgr,
    MulticastManager*               mc_mgr)
    : m_topo(topo)
    , m_params(params)
    , m_tek_mgr(tek_mgr)
    , m_dist_mgr(dist_mgr)
    , m_mc_mgr(mc_mgr)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyManager: initialized");
}

// ===========================================================================
// TEK derivation per spec:
// TEK_new = SHA256(TEK_old || timestamp || nonce)
// ===========================================================================
crypto::AesGcmKey RekeyManager::DeriveTek(
    const crypto::AesGcmKey& old_tek,
    utils::u64               timestamp_us,
    const utils::Nonce128&    nonce) const
{
    // Build input: TEK_old(32) || ts(8) || nonce(16)
    std::vector<uint8_t> input;
    input.reserve(56);

    // Append TEK_old
    input.insert(input.end(),
        old_tek.begin(), old_tek.end());

    // Append timestamp (big-endian 8 bytes)
    for (int i = 7; i >= 0; --i)
        input.push_back(
            static_cast<uint8_t>(
                (timestamp_us >> (i * 8)) & 0xFF));

    // Append nonce (16 bytes)
    input.insert(input.end(),
        nonce.begin(), nonce.end());

    // SHA-256
    crypto::AesGcmKey new_tek{};
    SHA256(input.data(), input.size(),
           new_tek.data());

    return new_tek;
}

// ===========================================================================
// TriggerRekey - core rekey operation
// ===========================================================================
bool RekeyManager::TriggerRekey(
    utils::u32       cluster_id,
    RekeyReason      reason,
    SkdcApplication* skdc)
{
    if (cluster_id >= 3) return false;

    // FIXED: use wall clock for crypto timing
    auto _wc_start = std::chrono::steady_clock::now();

    RekeyEvent ev;
    ev.cluster_id  = cluster_id;
    ev.old_version = m_tek_mgr->GetVersion(cluster_id);
    ev.reason      = reason;
    ev.time_s      = Simulator::Now().GetSeconds();

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyManager: rekey cluster=" << cluster_id
        << " reason=" << RekeyReasonStr(reason)
        << " v=" << ev.old_version);

    // Derive new TEK using spec formula:
    // TEK_new = SHA256(TEK_old || timestamp || nonce)
    auto old_tek = m_tek_mgr->GetTek(cluster_id);
    utils::u64 ts =
        utils::TimeUtils::NowEpochMicros();

    // Generate nonce
    utils::Nonce128 nonce{};
    RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));

    auto new_tek = DeriveTek(old_tek, ts, nonce);

    // Update TEK in manager
    utils::u32 new_ver = ev.old_version + 1;
    m_tek_mgr->UpdateTek(cluster_id, new_tek, new_ver);

    ev.new_version = m_tek_mgr->GetVersion(cluster_id);

    // Broadcast new MT_K to cluster
    if (skdc && m_dist_mgr)
        m_dist_mgr->OnTekRotated(
            cluster_id, new_tek, new_ver, skdc);

    ev.success = true;
    auto _wc_end = std::chrono::steady_clock::now();
    ev.latency_ms = std::chrono::duration<double, std::milli>(_wc_end - _wc_start).count();

    m_history.push_back(ev);
    ++m_total_rekeys;
    if (cluster_id < 3)
        ++m_cluster_rekeys[cluster_id];

    if (m_rekey_cb) m_rekey_cb(ev);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyManager: rekey complete"
        << " cluster=" << cluster_id
        << " v" << ev.old_version
        << "->" << ev.new_version);

    return true;
}

// ===========================================================================
// GlobalRekey - rekey all clusters
// ===========================================================================
void RekeyManager::GlobalRekey(
    std::array<Ptr<SkdcApplication>, 3>& skdc_apps,
    RekeyReason reason)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyManager: global rekey"
        << " reason=" << RekeyReasonStr(reason));

    for (utils::u32 c = 0; c < 3; ++c) {
        if (skdc_apps[c])
            TriggerRekey(c, reason,
                skdc_apps[c].operator->());
    }
}

// ===========================================================================
// SchedulePeriodic
// ===========================================================================
void RekeyManager::SchedulePeriodic(
    utils::u32 cluster_id,
    Ptr<SkdcApplication> skdc,
    double interval_s)
{
    Simulator::Schedule(
        Seconds(interval_s),
        &RekeyManager::PeriodicRekeyCallback,
        this, cluster_id, skdc);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyManager: periodic rekey scheduled"
        << " cluster=" << cluster_id
        << " interval=" << interval_s << "s");
}

void RekeyManager::PeriodicRekeyCallback(
    utils::u32 cluster_id,
    Ptr<SkdcApplication> skdc)
{
    TriggerRekey(cluster_id,
                 RekeyReason::PERIODIC,
                 skdc.operator->());
}

// ===========================================================================
// Stats
// ===========================================================================
utils::u64 RekeyManager::GetRekeyCount(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0;
    return m_cluster_rekeys[cluster_id];
}

double RekeyManager::GetAvgRekeyLatency() const {
    if (m_history.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& e : m_history)
        sum += e.latency_ms;
    return sum / m_history.size();
}

void RekeyManager::PrintRekeyStats() const {
    std::cout << "\n=== Rekey Stats ===\n";
    std::cout << "  Total rekeys: "
              << m_total_rekeys << "\n";
    for (utils::u32 c = 0; c < 3; ++c)
        std::cout << "  C" << c << " rekeys: "
                  << m_cluster_rekeys[c] << "\n";
    std::cout << "  Avg latency: "
              << GetAvgRekeyLatency() << " ms\n";

    for (const auto& ev : m_history) {
        std::cout << "    t=" << ev.time_s
            << "s C" << ev.cluster_id
            << " " << RekeyReasonStr(ev.reason)
            << " v" << ev.old_version
            << "->" << ev.new_version
            << " ok=" << ev.success << "\n";
    }
}

} // namespace apps
} // namespace uav
