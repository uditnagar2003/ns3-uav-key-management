/**
 * apps/uav-tek-manager.cc
 * Module 39 - TEK Manager
 */

#include "apps/uav-tek-manager.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-byte-utils.h"

#include "ns3/log.h"

#include <openssl/rand.h>

#include <iostream>
#include <iomanip>
#include <cstring>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("UavTekManager");

namespace uav {
namespace apps {

TekManager::TekManager(
    const crypto::CryptoParamsFile* params)
    : m_params(params)
{
    m_hmac_key =
        crypto::HmacSha256Util::GenerateKey();
    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "TekManager: constructed");
}

void TekManager::Initialize() {
    if (!m_params) return;
    utils::u64 now =
        utils::TimeUtils::NowEpochMicros();

    for (utils::u32 c = 0; c < 3; ++c) {
        if (c >= m_params->clusters.size()) break;
        const auto& cp = m_params->clusters[c];
        auto& tr = m_teks[c];
        tr.cluster_id = c;
        tr.tek        = cp.tek;
        tr.tek_int    = cp.tek_int;
        tr.version    = 1;
        tr.created_at = now;
        tr.expires_at = now + TekRecord::TEK_LIFETIME_US;
        tr.valid      = true;

        UAV_LOG_INFO(uav::log::channels::CRYPTO,
            "TekManager: cluster " << c
            << " TEK initialized v" << tr.version);
    }
}

const crypto::AesGcmKey& TekManager::GetTek(
    utils::u32 cluster_id) const
{
    static crypto::AesGcmKey empty{};
    if (cluster_id >= 3) return empty;
    return m_teks[cluster_id].tek;
}

const crypto::BigInt& TekManager::GetTekInt(
    utils::u32 cluster_id) const
{
    static crypto::BigInt empty;
    if (cluster_id >= 3) return empty;
    return m_teks[cluster_id].tek_int;
}

utils::u32 TekManager::GetVersion(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0;
    return m_teks[cluster_id].version;
}

bool TekManager::IsValid(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return false;
    return m_teks[cluster_id].valid;
}

bool TekManager::IsExpired(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return true;
    utils::u64 now =
        utils::TimeUtils::NowEpochMicros();
    return now > m_teks[cluster_id].expires_at;
}

void TekManager::RotateOnLeave(
    utils::u32 cluster_id)
{
    DoRotate(cluster_id, "LEAVE");
}

void TekManager::RotateOnTimer(
    utils::u32 cluster_id)
{
    DoRotate(cluster_id, "TIMER");
}

void TekManager::DoRotate(
    utils::u32 cluster_id,
    const std::string& reason)
{
    if (cluster_id >= 3) return;
    auto& tr = m_teks[cluster_id];

    // Build seed: TEK_old || timestamp || nonce
    utils::ByteBuffer seed(
        tr.tek.begin(), tr.tek.end());

    utils::u64 ts =
        utils::TimeUtils::NowEpochMicros();
    utils::ByteUtils::AppendU64BE(seed, ts);

    // Random 16-byte nonce via OpenSSL
    std::array<utils::u8, 16> nonce{};
    RAND_bytes(nonce.data(),
        static_cast<int>(nonce.size()));
    seed.insert(seed.end(),
        nonce.begin(), nonce.end());

    // HMAC-SHA256 as KDF
    auto new_key = crypto::HmacSha256Util::Compute(
        m_hmac_key, seed);

    std::memcpy(tr.tek.data(),
        new_key.data(),
        std::min(new_key.size(),
            tr.tek.size()));

    tr.tek_int = crypto::BigIntOps::FromBytes(
        utils::ByteBuffer(
            tr.tek.begin(), tr.tek.end()));

    ++tr.version;
    tr.created_at =
        utils::TimeUtils::NowEpochMicros();
    tr.expires_at =
        tr.created_at + TekRecord::TEK_LIFETIME_US;
    ++m_rotations;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "TekManager: TEK rotated"
        << " cluster=" << cluster_id
        << " reason=" << reason
        << " version=" << tr.version);

    if (m_rotate_cb) {
        m_rotate_cb(cluster_id, tr.tek,
                    tr.version);
    }
}

void TekManager::UpdateTek(
    utils::u32 cluster_id,
    const crypto::AesGcmKey& new_tek,
    utils::u32 version)
{
    if (cluster_id >= 3) return;
    auto& tr = m_teks[cluster_id];
    tr.tek        = new_tek;
    tr.version    = version;
    tr.valid      = true;
    tr.created_at =
        utils::TimeUtils::NowEpochMicros();
    tr.expires_at =
        tr.created_at + TekRecord::TEK_LIFETIME_US;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "TekManager: TEK updated from KDC"
        << " cluster=" << cluster_id
        << " version=" << version);
}

bool TekManager::VerifyTek(
    utils::u32 cluster_id,
    const crypto::BigInt& expected_int,
    const crypto::BigInt& n_i) const
{
    if (cluster_id >= 3) return false;
    const auto& tr = m_teks[cluster_id];
    crypto::BigInt actual =
        crypto::BigIntOps::Mod(tr.tek_int, n_i);
    crypto::BigInt expected =
        crypto::BigIntOps::Mod(expected_int, n_i);
    bool ok = (actual == expected);
    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "TekManager: VerifyTek cluster="
        << cluster_id << " result="
        << (ok ? "OK" : "FAIL"));
    return ok;
}

void TekManager::PrintTekStatus() const {
    std::cout << "\n=== TEK Manager Status ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        const auto& tr = m_teks[c];
        std::cout << "  Cluster " << c
            << ": valid=" << tr.valid
            << " version=" << tr.version
            << " expired=" << IsExpired(c)
            << "\n";
    }
    std::cout << "  Total rotations: "
              << m_rotations << "\n";
}

} // namespace apps
} // namespace uav
