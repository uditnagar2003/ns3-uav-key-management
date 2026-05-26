/**
 * crypto/uav-crypto-params.cc
 */

#include "uav-crypto-params.h"
#include "uav-openssl-error.h"
#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-file-utils.h"
#include "uav-string-utils.h"

#include <nlohmann/json.hpp>

#include <cstring>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace uav {
namespace crypto {

// ===========================================================================
// SlaveKeyEntry
// ===========================================================================

bool SlaveKeyEntry::Validate() const {
    // xy_i must equal x_i * y_i
    if (xy_i != x_i * y_i) return false;
    // n_i must be > 0
    if (n_i <= 0) return false;
    // e_i must be ≡ 1 mod 4
    if (BigIntOps::Mod(e_i, BigInt(4)) != BigInt(1)) return false;
    return true;
}

bool SlaveKeyEntry::VerifyDecryptionProperty() const {
    // d_i = e_i^(2*(x_i-1)*(y_i-1)-1) mod 4*x_i*y_i
    BigInt mod4xy  = 4 * x_i * y_i;
    BigInt exp_val = 2 * (x_i - 1) * (y_i - 1) - 1;
    BigInt expected = BigIntOps::ModPow(e_i, exp_val, mod4xy);
    return (d_i == expected);
}

// ===========================================================================
// ClusterCryptoEntry
// ===========================================================================

const SlaveKeyEntry* ClusterCryptoEntry::GetSlaveKey(
    utils::u32 uav_index) const
{
    for (const auto& sk : slave_keys) {
        if (sk.uav_index == uav_index) return &sk;
    }
    return nullptr;
}

const SlaveKeyEntry* ClusterCryptoEntry::GetSlaveKeyById(
    utils::u32 uav_id) const
{
    for (const auto& sk : slave_keys) {
        if (sk.uav_id == uav_id) return &sk;
    }
    return nullptr;
}

bool ClusterCryptoEntry::Validate() const {
    if (slave_keys.empty()) return false;
    if (slave_keys.size() != num_uavs) return false;
    if (eM <= 0) return false;
    if (MT_K <= 0) return false;
    for (const auto& sk : slave_keys) {
        if (!sk.Validate()) return false;
    }
    return true;
}

// ===========================================================================
// CryptoParamsFile
// ===========================================================================

const ClusterCryptoEntry* CryptoParamsFile::GetCluster(
    utils::u32 cluster_id) const
{
    for (const auto& c : clusters) {
        if (c.cluster_id == cluster_id) return &c;
    }
    return nullptr;
}

const SlaveKeyEntry* CryptoParamsFile::GetSlaveKeyByUavId(
    utils::u32 uav_id) const
{
    for (const auto& c : clusters) {
        const auto* sk = c.GetSlaveKeyById(uav_id);
        if (sk) return sk;
    }
    return nullptr;
}

bool CryptoParamsFile::Validate() const {
    if (clusters.empty()) return false;
    if (clusters.size() != num_clusters) return false;
    if (total_uavs != num_clusters * uavs_per_cluster) return false;
    for (const auto& c : clusters) {
        if (!c.Validate()) return false;
    }
    return true;
}

// ===========================================================================
// CryptoParamsLoader — helpers
// ===========================================================================

AesGcmKey CryptoParamsLoader::HexToAesKey(const std::string& hex) {
    if (hex.size() != 64) {
        UAV_THROW(utils::CryptoException,
            "HexToAesKey: expected 64 hex chars, got "
            + std::to_string(hex.size()));
    }
    AesGcmKey key;
    for (std::size_t i = 0; i < 32; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        key[i] = static_cast<utils::u8>(
            std::stoul(byte_str, nullptr, 16));
    }
    return key;
}

// ===========================================================================
// CryptoParamsLoader — JSON parsing via nlohmann::json
// ===========================================================================

SlaveKeyEntry CryptoParamsLoader::ParseSlaveKey(
    const std::string& slave_json)
{
    auto j = json::parse(slave_json);
    SlaveKeyEntry sk;

    sk.uav_index = j.at("uav_index").get<utils::u32>();
    sk.uav_id    = j.at("uav_id").get<utils::u32>();

    sk.e_i  = BigIntOps::FromDecString(
        j.at("e_i").get<std::string>());
    sk.d_i  = BigIntOps::FromDecString(
        j.at("d_i").get<std::string>());
    sk.n_i  = BigIntOps::FromDecString(
        j.at("n_i").get<std::string>());
    sk.x_i  = BigIntOps::FromDecString(
        j.at("x_i").get<std::string>());
    sk.y_i  = BigIntOps::FromDecString(
        j.at("y_i").get<std::string>());
    sk.Mi   = BigIntOps::FromDecString(
        j.at("Mi").get<std::string>());
    sk.Ni   = BigIntOps::FromDecString(
        j.at("Ni").get<std::string>());
    sk.xy_i = BigIntOps::FromDecString(
        j.at("xy_i").get<std::string>());
    sk.p_i  = BigIntOps::FromDecString(
        j.at("p_i").get<std::string>());
    sk.q_i  = BigIntOps::FromDecString(
        j.at("q_i").get<std::string>());

    return sk;
}

CryptoParamsFile CryptoParamsLoader::ParseJson(
    const std::string& json_str)
{
    auto j = json::parse(json_str);
    CryptoParamsFile params;

    params.scheme           = j.at("scheme").get<std::string>();
    params.num_clusters     = j.at("num_clusters").get<utils::u32>();
    params.uavs_per_cluster = j.at("uavs_per_cluster").get<utils::u32>();
    params.total_uavs       = j.at("total_uavs").get<utils::u32>();
    params.seed             = j.value("seed", utils::u32(42));

    // Parse clusters array
    for (const auto& cj : j.at("clusters")) {
        ClusterCryptoEntry c;

        c.cluster_id = cj.at("cluster_id").get<utils::u32>();
        c.skdc_id    = cj.at("skdc_id").get<utils::u32>();
        c.num_uavs   = cj.at("num_uavs").get<utils::u32>();

        c.eM      = BigIntOps::FromDecString(
            cj.at("eM").get<std::string>());
        c.n_total = BigIntOps::FromDecString(
            cj.at("n_total").get<std::string>());
        // tek_int replaces T in new gen_crypto.py
        if (cj.contains("tek_int"))
            c.tek_int = BigIntOps::FromDecString(
                cj.at("tek_int").get<std::string>());
        else if (cj.contains("T"))
            c.tek_int = BigIntOps::FromDecString(
                cj.at("T").get<std::string>());
        c.MT_K    = BigIntOps::FromDecString(
            cj.at("MT_K").get<std::string>());
        c.e_MK    = BigIntOps::FromDecString(
            cj.at("e_MK").get<std::string>());

        // N_global and N_group
        if (cj.contains("N_global"))
            c.N_global = BigIntOps::FromDecString(
                cj.at("N_global").get<std::string>());
        if (cj.contains("N_group"))
            c.N_group = BigIntOps::FromDecString(
                cj.at("N_group").get<std::string>());

        // TEK
        c.tek_hex = cj.at("tek_hex").get<std::string>();
        c.tek     = HexToAesKey(c.tek_hex);

        // User indices
        for (auto idx : cj.at("user_indices")) {
            c.user_indices.push_back(idx.get<utils::u32>());
        }

        // Slave keys
        for (const auto& skj : cj.at("slave_keys")) {
            SlaveKeyEntry sk;
            sk.uav_index = skj.at("uav_index").get<utils::u32>();
            sk.uav_id    = skj.at("uav_id").get<utils::u32>();

            sk.e_i  = BigIntOps::FromDecString(
                skj.at("e_i").get<std::string>());
            sk.d_i  = BigIntOps::FromDecString(
                skj.at("d_i").get<std::string>());
            sk.n_i  = BigIntOps::FromDecString(
                skj.at("n_i").get<std::string>());
            sk.x_i  = BigIntOps::FromDecString(
                skj.at("x_i").get<std::string>());
            sk.y_i  = BigIntOps::FromDecString(
                skj.at("y_i").get<std::string>());
            sk.Mi   = BigIntOps::FromDecString(
                skj.at("Mi").get<std::string>());
            sk.Ni   = BigIntOps::FromDecString(
                skj.at("Ni").get<std::string>());
            sk.xy_i = BigIntOps::FromDecString(
                skj.at("xy_i").get<std::string>());
            sk.p_i  = BigIntOps::FromDecString(
                skj.at("p_i").get<std::string>());
            sk.q_i  = BigIntOps::FromDecString(
                skj.at("q_i").get<std::string>());

            c.slave_keys.push_back(std::move(sk));
        }

        params.clusters.push_back(std::move(c));
    }

    return params;
}

// ===========================================================================
// Public interface
// ===========================================================================

CryptoParamsFile CryptoParamsLoader::LoadFromFile(
    const std::string& path)
{
    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CryptoParamsLoader: loading " << path);

    std::string json_str;
    try {
        json_str = utils::FileUtils::ReadTextFile(path);
    } catch (const std::exception& ex) {
        UAV_THROW(utils::ConfigException,
            "CryptoParamsLoader: cannot read file '"
            + path + "': " + ex.what());
    }

    CryptoParamsFile params = ParseJson(json_str);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CryptoParamsLoader: loaded "
        << params.num_clusters << " clusters, "
        << params.total_uavs   << " UAVs");

    ValidateOrThrow(params);
    return params;
}

CryptoParamsFile CryptoParamsLoader::LoadFromString(
    const std::string& json_str)
{
    CryptoParamsFile params = ParseJson(json_str);
    ValidateOrThrow(params);
    return params;
}

void CryptoParamsLoader::ValidateOrThrow(
    const CryptoParamsFile& params)
{
    if (params.scheme.empty()) {
        UAV_THROW(utils::ConfigException,
            "CryptoParamsLoader: missing scheme");
    }
    if (params.num_clusters == 0) {
        UAV_THROW(utils::ConfigException,
            "CryptoParamsLoader: num_clusters == 0");
    }
    if (params.uavs_per_cluster == 0) {
        UAV_THROW(utils::ConfigException,
            "CryptoParamsLoader: uavs_per_cluster == 0");
    }
    if (params.clusters.size() != params.num_clusters) {
        UAV_THROW(utils::ConfigException,
            "CryptoParamsLoader: cluster count mismatch: "
            "expected " + std::to_string(params.num_clusters)
            + " got " + std::to_string(params.clusters.size()));
    }

    for (const auto& c : params.clusters) {
        if (c.slave_keys.size() != c.num_uavs) {
            UAV_THROW(utils::ConfigException,
                "CryptoParamsLoader: cluster "
                + std::to_string(c.cluster_id)
                + " slave key count mismatch");
        }
        if (c.eM  <= 0) {
            UAV_THROW(utils::CryptoException,
                "CryptoParamsLoader: cluster "
                + std::to_string(c.cluster_id)
                + " eM is zero or negative");
        }
        if (c.MT_K <= 0) {
            UAV_THROW(utils::CryptoException,
                "CryptoParamsLoader: cluster "
                + std::to_string(c.cluster_id)
                + " MT_K is zero or negative");
        }
        if (c.tek_hex.size() != 64) {
            UAV_THROW(utils::CryptoException,
                "CryptoParamsLoader: cluster "
                + std::to_string(c.cluster_id)
                + " tek_hex wrong length");
        }
        for (const auto& sk : c.slave_keys) {
            if (sk.n_i <= 0 || sk.d_i <= 0) {
                UAV_THROW(utils::CryptoException,
                    "CryptoParamsLoader: cluster "
                    + std::to_string(c.cluster_id)
                    + " UAV " + std::to_string(sk.uav_id)
                    + " invalid slave key");
            }
        }
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CryptoParamsLoader: validation passed");
}

} // namespace crypto
} // namespace uav