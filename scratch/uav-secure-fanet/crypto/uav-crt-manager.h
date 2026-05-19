cat > ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet/crypto/uav-crt-manager.h << 'EOF'
/**
 * crypto/uav-crt-manager.h
 *
 * CRT/GCRT Crypto Manager — full MKE-MGKM orchestration.
 *
 * IMPLEMENTS:
 *   Algorithm 1: MKeyGen      — master key generation
 *   Algorithm 2: MTokenGen    — master token generation
 *   Algorithm 3: JoKeyUpdate  — join key update
 *   Algorithm 5: LeKeyUpdate  — leave key update
 *
 * REFERENCE PYTHON (exact match):
 *   compute_d(e,x,y) = pow(e, 2*(x-1)*(y-1)-1, 4*x*y)
 *   Ni = inverse(Mi, xi*yi)
 *   eM = sum(e_i*Mi*Ni) % n_total, enforce eM%4==1
 *   MT_K = e_MK + T
 *   decrypt: pow(MT_K, d_i, n_i)
 *
 * INTEGRATION:
 *   CrtManager loads pre-generated params from CryptoParamsFile
 *   (Module 14) and provides runtime operations:
 *     - TEK rotation (LeKeyUpdate / JoKeyUpdate)
 *     - MT_K distribution
 *     - Slave decryption verification
 *     - TEK encryption/decryption via AES-256-GCM
 */

#ifndef UAV_CRT_MANAGER_H
#define UAV_CRT_MANAGER_H

#include "uav-bigint.h"
#include "uav-bigint-utils.h"
#include "uav-aes.h"
#include "uav-hmac.h"
#include "uav-replay.h"
#include "uav-crypto-params.h"
#include "uav-types.h"
#include "uav-error.h"

#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <functional>

namespace uav {
namespace crypto {

// ===========================================================================
// MKeyGenResult — output of Algorithm 1
// ===========================================================================
struct MKeyGenResult {
    BigInt                      eM;
    BigInt                      n_total;
    std::vector<SlaveKeyEntry>  slaves;
};

// ===========================================================================
// MTokenResult — output of Algorithm 2/3/5
// ===========================================================================
struct MTokenResult {
    BigInt                      MT_K;
    BigInt                      e_MK;
    BigInt                      T;
    std::vector<utils::u32>     user_indices;
    utils::u32                  cluster_id;
    utils::u32                  version;      // increments on every rekey
};

// ===========================================================================
// ClusterState — runtime state per cluster
// ===========================================================================
struct ClusterState {
    utils::u32          cluster_id;
    MKeyGenResult       mkg;
    MTokenResult        mtoken;
    AesGcmKey           tek;          // current TEK (32 bytes)
    utils::u32          rekey_count;  // number of rekey events
    bool                initialized;

    ClusterState() : cluster_id(0), rekey_count(0),
                     initialized(false) {}
};

// ===========================================================================
// CrtManager — main orchestration class
// ===========================================================================
class CrtManager {
public:
    CrtManager();
    ~CrtManager() = default;

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Load pre-generated params from CryptoParamsFile (Module 14).
    /// Call once at simulation start.
    void LoadFromParams(const CryptoParamsFile& params);

    /// Load directly from JSON file path.
    void LoadFromFile(const std::string& path);

    /// Returns true if initialized.
    bool IsInitialized() const { return m_initialized; }

    // -----------------------------------------------------------------------
    // Algorithm 1: MKeyGen
    // Generates master key and slave keys from safe prime pairs.
    // (Used internally during LoadFromParams)
    // -----------------------------------------------------------------------
    static MKeyGenResult MKeyGen(
        const std::vector<std::pair<BigInt,BigInt>>& prime_pairs);

    // -----------------------------------------------------------------------
    // Algorithm 2: MTokenGen
    // Generates MT_K for a subset of UAVs.
    // -----------------------------------------------------------------------
    static MTokenResult MTokenGen(
        const MKeyGenResult&            mkg,
        const std::vector<utils::u32>&  user_indices,
        const BigInt&                   T,
        utils::u32                      cluster_id);

    // -----------------------------------------------------------------------
    // Algorithm 3: JoKeyUpdate
    // Updates MT_K when a UAV joins the cluster.
    // -----------------------------------------------------------------------
    static MTokenResult JoKeyUpdate(
        const MKeyGenResult&    mkg,
        const MTokenResult&     current,
        utils::u32              join_slave_index);

    // -----------------------------------------------------------------------
    // Algorithm 5: LeKeyUpdate
    // Updates MT_K when a UAV leaves the cluster.
    // -----------------------------------------------------------------------
    static MTokenResult LeKeyUpdate(
        const MKeyGenResult&    mkg,
        const MTokenResult&     current,
        utils::u32              leave_slave_index);

    // -----------------------------------------------------------------------
    // Slave decryption
    // Each UAV recovers T from MT_K using its private d_i.
    // -----------------------------------------------------------------------

    /// Decrypt MT_K using slave key → recover T mod n_i.
    static BigInt SlaveDecrypt(
        const SlaveKeyEntry&    slave,
        const BigInt&           MT_K);

    /// Verify slave can decrypt MT_K correctly.
    static bool VerifySlaveDecrypt(
        const SlaveKeyEntry&    slave,
        const BigInt&           MT_K,
        const BigInt&           T);

    // -----------------------------------------------------------------------
    // TEK operations (AES wrapper around T)
    // -----------------------------------------------------------------------

    /// Convert T (BigInt) to 32-byte AES key.
    static AesGcmKey TekFromBigInt(const BigInt& T);

    /// Convert 32-byte AES key to BigInt.
    static BigInt TekToBigInt(const AesGcmKey& tek);

    /// Encrypt TEK using KEK (for SKDC→UAV distribution).
    static utils::ByteBuffer EncryptTek(
        const AesGcmKey& kek,
        const AesGcmKey& tek,
        utils::u32       cluster_id);

    /// Decrypt TEK from wire format.
    static AesGcmKey DecryptTek(
        const AesGcmKey&         kek,
        const utils::ByteBuffer& wire,
        utils::u32               cluster_id);

    // -----------------------------------------------------------------------
    // TEK rotation (per leave event — Algorithm 5 + derivation)
    // new_tek = SHA256(old_tek || timestamp || nonce)
    // -----------------------------------------------------------------------
    static AesGcmKey RotateTek(
        const AesGcmKey&  old_tek,
        utils::u64        timestamp_us,
        const utils::Nonce128& nonce);

    // -----------------------------------------------------------------------
    // Runtime cluster operations
    // -----------------------------------------------------------------------

    /// Get current MT_K for cluster.
    MTokenResult GetMToken(utils::u32 cluster_id) const;

    /// Get current TEK for cluster.
    AesGcmKey GetTek(utils::u32 cluster_id) const;

    /// Get slave key for UAV.
    const SlaveKeyEntry* GetSlaveKey(utils::u32 uav_id) const;

    /// Get slave key within cluster.
    const SlaveKeyEntry* GetClusterSlaveKey(
        utils::u32 cluster_id,
        utils::u32 uav_index) const;

    /// Process join event — update cluster state.
    /// Returns new MTokenResult.
    MTokenResult ProcessJoin(
        utils::u32 cluster_id,
        utils::u32 joining_uav_index);

    /// Process leave event — update cluster state + rotate TEK.
    /// Returns new MTokenResult.
    MTokenResult ProcessLeave(
        utils::u32 cluster_id,
        utils::u32 leaving_uav_index);

    /// Get rekey count for cluster.
    utils::u32 GetRekeyCount(utils::u32 cluster_id) const;

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Verify all slaves in cluster can decrypt current MT_K.
    bool VerifyCluster(utils::u32 cluster_id) const;

    /// Verify all clusters.
    bool VerifyAll() const;

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------
    utils::u32 NumClusters()    const { return m_num_clusters;    }
    utils::u32 NumUavs()        const { return m_num_uavs;        }
    utils::u32 UavsPerCluster() const { return m_uavs_per_cluster;}

private:
    ClusterState& GetClusterState(utils::u32 cluster_id);
    const ClusterState& GetClusterState(utils::u32 cluster_id) const;

    bool                            m_initialized;
    utils::u32                      m_num_clusters;
    utils::u32                      m_num_uavs;
    utils::u32                      m_uavs_per_cluster;
    std::vector<ClusterState>       m_clusters;
    mutable std::mutex              m_mtx;
};

} // namespace crypto
} // namespace uav

#endif // UAV_CRT_MANAGER_H
EOF
echo "uav-crt-manager.h created"