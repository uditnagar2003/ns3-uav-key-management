cat > ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet/crypto/uav-crt-manager.cc << 'EOF'
/**
 * crypto/uav-crt-manager.cc
 */

#include "uav-crt-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-byte-utils.h"
#include "uav-time-utils.h"

#include <cstring>
#include <algorithm>
#include <sstream>

namespace uav {
namespace crypto {

// ===========================================================================
// Constructor
// ===========================================================================
CrtManager::CrtManager()
    : m_initialized(false)
    , m_num_clusters(0)
    , m_num_uavs(0)
    , m_uavs_per_cluster(0)
{}

// ===========================================================================
// LoadFromParams
// ===========================================================================
void CrtManager::LoadFromParams(const CryptoParamsFile& params) {
    std::lock_guard<std::mutex> lk(m_mtx);

    m_num_clusters     = params.num_clusters;
    m_num_uavs         = params.total_uavs;
    m_uavs_per_cluster = params.uavs_per_cluster;
    m_clusters.clear();
    m_clusters.resize(params.num_clusters);

    for (const auto& cp : params.clusters) {
        ClusterState& cs = m_clusters[cp.cluster_id];
        cs.cluster_id    = cp.cluster_id;

        // Populate MKeyGenResult from loaded params
        cs.mkg.eM      = cp.eM;
        cs.mkg.n_total = cp.n_total;
        cs.mkg.slaves  = cp.slave_keys;

        // Populate MTokenResult
        cs.mtoken.MT_K         = cp.MT_K;
        cs.mtoken.e_MK         = cp.e_MK;
        cs.mtoken.T            = cp.T;
        cs.mtoken.user_indices = std::vector<utils::u32>(
            cp.user_indices.begin(),
            cp.user_indices.end());
        cs.mtoken.cluster_id   = cp.cluster_id;
        cs.mtoken.version      = 1;

        // TEK
        cs.tek           = cp.tek;
        cs.rekey_count   = 0;
        cs.initialized   = true;

        UAV_LOG_INFO(uav::log::channels::CRYPTO,
            "CrtManager: loaded cluster " << cp.cluster_id
            << " eM=" << BigIntOps::ToDecString(cp.eM).substr(0,20)
            << "... slaves=" << cp.slave_keys.size());
    }

    m_initialized = true;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "CrtManager: initialized "
        << m_num_clusters << " clusters, "
        << m_num_uavs << " UAVs");
}

// ===========================================================================
// LoadFromFile
// ===========================================================================
void CrtManager::LoadFromFile(const std::string& path) {
    auto params = CryptoParamsLoader::LoadFromFile(path);
    LoadFromParams(params);
}

// ===========================================================================
// Algorithm 1: MKeyGen
// Exact match to Python reference:
//   e_i = 4k+1, gcd(e_i, x*y) == 1
//   d_i = pow(e_i, 2*(x-1)*(y-1)-1, 4*x*y)
//   eM  = sum(e_i*Mi*Ni) % n_total, enforce eM%4==1
// ===========================================================================
MKeyGenResult CrtManager::MKeyGen(
    const std::vector<std::pair<BigInt,BigInt>>& prime_pairs)
{
    MKeyGenResult result;

    std::vector<BigInt> e_list;
    std::vector<BigInt> xy_list;

    // Step 1: Generate slave keys
    for (auto& [p, q] : prime_pairs) {
        BigInt x = BigIntOps::ComputeX(p);
        BigInt y = BigIntOps::ComputeY(q);

        // Generate e_i = 4k+1 with gcd(e_i, x*y) == 1
        BigInt e_i;
        std::mt19937_64 rng(
            static_cast<uint64_t>(
                utils::TimeUtils::NowEpochMicros()));

        do {
            e_i = BigIntOps::GenerateEi(rng);
        } while (BigIntOps::Gcd(e_i, x * y) != BigInt(1));

        // d_i = e_i^(2*(x-1)*(y-1)-1) mod 4*x*y
        BigInt d_i = BigIntOps::ComputeDi(e_i, x, y);

        SlaveKeyEntry sk;
        sk.uav_index = static_cast<utils::u32>(e_list.size());
        sk.uav_id    = static_cast<utils::u32>(e_list.size());
        sk.e_i  = e_i;
        sk.d_i  = d_i;
        sk.n_i  = p * q;
        sk.x_i  = x;
        sk.y_i  = y;
        sk.xy_i = x * y;
        sk.p_i  = p;
        sk.q_i  = q;

        e_list.push_back(e_i);
        xy_list.push_back(x * y);
        result.slaves.push_back(std::move(sk));
    }

    // Step 2: Compute n_total = product of all x_i * y_i
    result.n_total = BigInt(1);
    for (const auto& xy : xy_list) {
        result.n_total *= xy;
    }

    // Step 3: Compute Mi, Ni for each slave
    for (std::size_t i = 0; i < result.slaves.size(); ++i) {
        BigInt Mi = result.n_total / xy_list[i];
        BigInt Ni = BigIntOps::ModInverse(Mi, xy_list[i]);
        result.slaves[i].Mi = Mi;
        result.slaves[i].Ni = Ni;
    }

    // Step 4: eM = sum(e_i * Mi * Ni) % n_total
    result.eM = BigInt(0);
    for (std::size_t i = 0; i < result.slaves.size(); ++i) {
        result.eM += result.slaves[i].e_i
                   * result.slaves[i].Mi
                   * result.slaves[i].Ni;
    }
    result.eM = BigIntOps::Mod(result.eM, result.n_total);

    // Step 5: Enforce eM ≡ 1 mod 4
    while (BigIntOps::Mod(result.eM, BigInt(4)) != BigInt(1)) {
        result.eM += result.n_total;
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "MKeyGen: eM="
        << BigIntOps::ToDecString(result.eM).substr(0,20)
        << "... slaves=" << result.slaves.size());

    return result;
}

// ===========================================================================
// Algorithm 2: MTokenGen
// e_MK = eM - sum(e_i*Mi*Ni for i NOT in group)
// MT_K = e_MK + T
// ===========================================================================
MTokenResult CrtManager::MTokenGen(
    const MKeyGenResult&            mkg,
    const std::vector<utils::u32>&  user_indices,
    const BigInt&                   T,
    utils::u32                      cluster_id)
{
    MTokenResult result;
    result.T           = T;
    result.cluster_id  = cluster_id;
    result.user_indices = user_indices;
    result.version     = 1;

    // Step 1: e_MK = eM (start with full master key)
    BigInt e_MK = mkg.eM;

    // Step 2: subtract contribution of slaves NOT in group
    for (const auto& slave : mkg.slaves) {
        bool in_group = false;
        for (auto idx : user_indices) {
            if (slave.uav_index == idx) {
                in_group = true;
                break;
            }
        }
        if (!in_group) {
            e_MK -= slave.e_i * slave.Mi * slave.Ni;
        }
    }

    // Step 3: reduce mod n_total and enforce ≡ 1 mod 4
    e_MK = BigIntOps::Mod(e_MK, mkg.n_total);
    while (BigIntOps::Mod(e_MK, BigInt(4)) != BigInt(1)) {
        e_MK += mkg.n_total;
    }

    // Step 4: MT_K = e_MK + T
    result.e_MK = e_MK;
    result.MT_K = e_MK + T;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "MTokenGen: cluster=" << cluster_id
        << " users=" << user_indices.size()
        << " MT_K=" << BigIntOps::ToDecString(result.MT_K).substr(0,20)
        << "...");

    return result;
}

// ===========================================================================
// Algorithm 3: JoKeyUpdate
// Add joining slave's contribution to e_MK
// ===========================================================================
MTokenResult CrtManager::JoKeyUpdate(
    const MKeyGenResult&    mkg,
    const MTokenResult&     current,
    utils::u32              join_slave_index)
{
    // Find joining slave
    const SlaveKeyEntry* join_slave = nullptr;
    for (const auto& s : mkg.slaves) {
        if (s.uav_index == join_slave_index) {
            join_slave = &s;
            break;
        }
    }
    if (!join_slave) {
        UAV_THROW(utils::CryptoException,
            "JoKeyUpdate: slave index "
            + std::to_string(join_slave_index)
            + " not found");
    }

    MTokenResult result;
    result.T          = current.T;
    result.cluster_id = current.cluster_id;
    result.version    = current.version + 1;

    // Step 1: e_MK = MT_K - T
    BigInt e_MK = current.MT_K - current.T;

    // Step 2: add joining slave's contribution
    e_MK += join_slave->e_i * join_slave->Mi * join_slave->Ni;

    // Step 3: reduce mod n_total and enforce ≡ 1 mod 4
    e_MK = BigIntOps::Mod(e_MK, mkg.n_total);
    while (BigIntOps::Mod(e_MK, BigInt(4)) != BigInt(1)) {
        e_MK += mkg.n_total;
    }

    // Step 4: MT'_K = e_MK + T
    result.e_MK = e_MK;
    result.MT_K = e_MK + current.T;

    // Update user list
    result.user_indices = current.user_indices;
    result.user_indices.push_back(join_slave_index);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "JoKeyUpdate: cluster=" << current.cluster_id
        << " join_slave=" << join_slave_index
        << " users=" << result.user_indices.size());

    return result;
}

// ===========================================================================
// Algorithm 5: LeKeyUpdate
// Remove leaving slave's contribution from e_MK
// ===========================================================================
MTokenResult CrtManager::LeKeyUpdate(
    const MKeyGenResult&    mkg,
    const MTokenResult&     current,
    utils::u32              leave_slave_index)
{
    // Find leaving slave
    const SlaveKeyEntry* leave_slave = nullptr;
    for (const auto& s : mkg.slaves) {
        if (s.uav_index == leave_slave_index) {
            leave_slave = &s;
            break;
        }
    }
    if (!leave_slave) {
        UAV_THROW(utils::CryptoException,
            "LeKeyUpdate: slave index "
            + std::to_string(leave_slave_index)
            + " not found");
    }

    MTokenResult result;
    result.T          = current.T;
    result.cluster_id = current.cluster_id;
    result.version    = current.version + 1;

    // Step 1: e_MK = MT_K - T
    BigInt e_MK = current.MT_K - current.T;

    // Step 2: subtract leaving slave's contribution
    e_MK -= leave_slave->e_i * leave_slave->Mi * leave_slave->Ni;

    // Step 3: reduce mod n_total and enforce ≡ 1 mod 4
    e_MK = BigIntOps::Mod(e_MK, mkg.n_total);
    while (BigIntOps::Mod(e_MK, BigInt(4)) != BigInt(1)) {
        e_MK += mkg.n_total;
    }

    // Step 4: MT'_K = e_MK + T
    result.e_MK = e_MK;
    result.MT_K = e_MK + current.T;

    // Update user list — remove leaving slave
    result.user_indices.clear();
    for (auto idx : current.user_indices) {
        if (idx != leave_slave_index) {
            result.user_indices.push_back(idx);
        }
    }

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "LeKeyUpdate: cluster=" << current.cluster_id
        << " leave_slave=" << leave_slave_index
        << " users=" << result.user_indices.size());

    return result;
}

// ===========================================================================
// Slave decryption: pow(MT_K, d_i, n_i)
// ===========================================================================
BigInt CrtManager::SlaveDecrypt(
    const SlaveKeyEntry&    slave,
    const BigInt&           MT_K)
{
    return BigIntOps::ModPow(MT_K, slave.d_i, slave.n_i);
}

bool CrtManager::VerifySlaveDecrypt(
    const SlaveKeyEntry&    slave,
    const BigInt&           MT_K,
    const BigInt&           T)
{
    BigInt recovered = SlaveDecrypt(slave, MT_K);
    BigInt T_mod     = BigIntOps::Mod(T, slave.n_i);
    return recovered == T_mod;
}

// ===========================================================================
// TEK <-> BigInt conversion
// ===========================================================================
AesGcmKey CrtManager::TekFromBigInt(const BigInt& T) {
    // Export T as 32-byte big-endian
    auto bytes = BigIntOps::ToBytes(T, 32);
    if (bytes.size() < 32) {
        // Pad to 32 bytes
        utils::ByteBuffer padded(32, 0x00);
        std::size_t offset = 32 - bytes.size();
        std::copy(bytes.begin(), bytes.end(),
                  padded.begin() + static_cast<std::ptrdiff_t>(offset));
        bytes = padded;
    }
    return AesGcm::KeyFromBytes(bytes.data(), 32);
}

BigInt CrtManager::TekToBigInt(const AesGcmKey& tek) {
    utils::ByteBuffer buf(tek.begin(), tek.end());
    return BigIntOps::FromBytes(buf);
}

// ===========================================================================
// TEK encryption/decryption
// ===========================================================================
utils::ByteBuffer CrtManager::EncryptTek(
    const AesGcmKey& kek,
    const AesGcmKey& tek,
    utils::u32       cluster_id)
{
    // AAD = cluster_id as 4 bytes
    utils::ByteBuffer aad(4);
    utils::ByteUtils::WriteU32BE(aad.data(), cluster_id);
    return AesGcm::EncryptTek(kek, tek, aad);
}

AesGcmKey CrtManager::DecryptTek(
    const AesGcmKey&         kek,
    const utils::ByteBuffer& wire,
    utils::u32               cluster_id)
{
    utils::ByteBuffer aad(4);
    utils::ByteUtils::WriteU32BE(aad.data(), cluster_id);
    return AesGcm::DecryptTek(kek, wire, aad);
}

// ===========================================================================
// TEK rotation: SHA256(old_tek || timestamp || nonce)
// ===========================================================================
AesGcmKey CrtManager::RotateTek(
    const AesGcmKey&        old_tek,
    utils::u64              timestamp_us,
    const utils::Nonce128&  nonce)
{
    utils::ByteBuffer context;
    context.reserve(32 + 8 + 16);
    utils::ByteUtils::AppendBytes(context,
        old_tek.data(), old_tek.size());
    utils::ByteUtils::AppendU64BE(context, timestamp_us);
    utils::ByteUtils::AppendBytes(context,
        nonce.data(), nonce.size());

    return AesGcm::DeriveKey(old_tek, context);
}

// ===========================================================================
// Runtime cluster operations
// ===========================================================================

ClusterState& CrtManager::GetClusterState(utils::u32 cluster_id) {
    if (cluster_id >= m_clusters.size()) {
        UAV_THROW(utils::InvalidArgumentException,
            "CrtManager: invalid cluster_id "
            + std::to_string(cluster_id));
    }
    return m_clusters[cluster_id];
}

const ClusterState& CrtManager::GetClusterState(
    utils::u32 cluster_id) const {
    if (cluster_id >= m_clusters.size()) {
        UAV_THROW(utils::InvalidArgumentException,
            "CrtManager: invalid cluster_id "
            + std::to_string(cluster_id));
    }
    return m_clusters[cluster_id];
}

MTokenResult CrtManager::GetMToken(utils::u32 cluster_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return GetClusterState(cluster_id).mtoken;
}

AesGcmKey CrtManager::GetTek(utils::u32 cluster_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return GetClusterState(cluster_id).tek;
}

const SlaveKeyEntry* CrtManager::GetSlaveKey(
    utils::u32 uav_id) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    for (const auto& cs : m_clusters) {
        for (const auto& sk : cs.mkg.slaves) {
            if (sk.uav_id == uav_id) return &sk;
        }
    }
    return nullptr;
}

const SlaveKeyEntry* CrtManager::GetClusterSlaveKey(
    utils::u32 cluster_id,
    utils::u32 uav_index) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    const auto& cs = GetClusterState(cluster_id);
    for (const auto& sk : cs.mkg.slaves) {
        if (sk.uav_index == uav_index) return &sk;
    }
    return nullptr;
}

MTokenResult CrtManager::ProcessJoin(
    utils::u32 cluster_id,
    utils::u32 joining_uav_index)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto& cs = GetClusterState(cluster_id);

    // Algorithm 3: JoKeyUpdate
    cs.mtoken = JoKeyUpdate(cs.mkg, cs.mtoken,
                             joining_uav_index);
    cs.rekey_count++;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "ProcessJoin: cluster=" << cluster_id
        << " uav=" << joining_uav_index
        << " rekey#=" << cs.rekey_count);

    return cs.mtoken;
}

MTokenResult CrtManager::ProcessLeave(
    utils::u32 cluster_id,
    utils::u32 leaving_uav_index)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto& cs = GetClusterState(cluster_id);

    // Algorithm 5: LeKeyUpdate
    cs.mtoken = LeKeyUpdate(cs.mkg, cs.mtoken,
                             leaving_uav_index);

    // TEK rotation after leave
    auto nonce   = OpenSSLRand::RandomNonce128();
    auto now_us  = utils::TimeUtils::NowEpochMicros();
    cs.tek       = RotateTek(cs.tek, now_us, nonce);
    cs.rekey_count++;

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "ProcessLeave: cluster=" << cluster_id
        << " uav=" << leaving_uav_index
        << " rekey#=" << cs.rekey_count);

    return cs.mtoken;
}

utils::u32 CrtManager::GetRekeyCount(utils::u32 cluster_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return GetClusterState(cluster_id).rekey_count;
}

// ===========================================================================
// Verification
// ===========================================================================

bool CrtManager::VerifyCluster(utils::u32 cluster_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    const auto& cs = GetClusterState(cluster_id);

    for (const auto& sk : cs.mkg.slaves) {
        // Only verify slaves in current user group
        bool in_group = false;
        for (auto idx : cs.mtoken.user_indices) {
            if (sk.uav_index == idx) {
                in_group = true;
                break;
            }
        }
        if (!in_group) continue;

        BigInt recovered = BigIntOps::ModPow(
            cs.mtoken.MT_K, sk.d_i, sk.n_i);
        BigInt T_mod = BigIntOps::Mod(cs.mtoken.T, sk.n_i);

        if (recovered != T_mod) {
            UAV_LOG_WARN(uav::log::channels::CRYPTO,
                "VerifyCluster: cluster=" << cluster_id
                << " UAV " << sk.uav_id << " FAILED");
            return false;
        }
    }
    return true;
}

bool CrtManager::VerifyAll() const {
    for (utils::u32 c = 0; c < m_num_clusters; ++c) {
        if (!VerifyCluster(c)) return false;
    }
    return true;
}

} // namespace crypto
} // namespace uav
EOF
echo "uav-crt-manager.cc created"