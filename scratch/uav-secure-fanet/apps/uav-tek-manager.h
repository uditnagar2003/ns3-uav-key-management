/**
 * apps/uav-tek-manager.h
 * Module 39 - TEK Manager
 *
 * TEK LIFECYCLE (per project spec):
 *   - KDC generates TEK
 *   - TEK encrypted into MT_K using SKDC domain
 *   - SKDC re-encrypts TEK for UAV cluster
 *   - UAV decrypts MT_K to extract TEK
 *   - TEK used for AES-256-GCM payload encryption
 *
 * TEK ROTATION:
 *   On JOIN:  TEK unchanged, only MT_K updated
 *   On LEAVE: TEK_new = SHA256(TEK_old || ts || nonce)
 *   On TIMER: periodic rotation every 60s
 *
 * STORAGE:
 *   KDC:  stores TEK per cluster
 *   SKDC: stores current TEK for its cluster
 *   UAV:  stores ONLY current TEK (no history)
 */

#ifndef UAV_TEK_MANAGER_H
#define UAV_TEK_MANAGER_H

#include "crypto/uav-aes.h"
#include "crypto/uav-hmac.h"
#include "crypto/uav-crypto-params.h"
#include "utils/uav-types.h"
#include "utils/uav-error.h"
#include "utils/uav-time-utils.h"

#include <array>
#include <vector>
#include <functional>
#include <string>

namespace uav {
namespace apps {

// ===========================================================================
// TekRecord - per-cluster TEK record
// ===========================================================================
struct TekRecord {
    utils::u32        cluster_id  = 0;
    crypto::AesGcmKey tek         = {};
    crypto::BigInt    tek_int;
    utils::u32        version     = 1;
    utils::u64        created_at  = 0;
    utils::u64        expires_at  = 0;
    bool              valid       = false;

    static constexpr utils::u64 TEK_LIFETIME_US =
        60ULL * 1000000ULL;  // 60 seconds
};

// ===========================================================================
// TekManager - Module 39
// ===========================================================================
class TekManager {
public:
    using TekRotateCallback =
        std::function<void(utils::u32 cluster,
                           const crypto::AesGcmKey& new_tek,
                           utils::u32 version)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit TekManager(
        const crypto::CryptoParamsFile* params);

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------
    void Initialize();

    // -----------------------------------------------------------------------
    // TEK access
    // -----------------------------------------------------------------------
    const crypto::AesGcmKey& GetTek(
        utils::u32 cluster_id) const;

    const crypto::BigInt& GetTekInt(
        utils::u32 cluster_id) const;

    utils::u32 GetVersion(
        utils::u32 cluster_id) const;

    bool IsValid(utils::u32 cluster_id) const;

    bool IsExpired(utils::u32 cluster_id) const;

    // -----------------------------------------------------------------------
    // TEK rotation
    // -----------------------------------------------------------------------

    /// Rotate TEK on leave event
    /// TEK_new = HMAC-SHA256(HMAC_key, TEK_old || ts || nonce)
    void RotateOnLeave(utils::u32 cluster_id);

    /// Rotate TEK on periodic timer
    void RotateOnTimer(utils::u32 cluster_id);

    /// Force TEK update from external source (KDC)
    void UpdateTek(utils::u32 cluster_id,
                   const crypto::AesGcmKey& new_tek,
                   utils::u32 version);

    // -----------------------------------------------------------------------
    // TEK verification
    // -----------------------------------------------------------------------

    /// Verify TEK against expected BigInt
    bool VerifyTek(utils::u32 cluster_id,
                   const crypto::BigInt& expected_int,
                   const crypto::BigInt& n_i) const;

    // -----------------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------------
    void SetRotateCallback(TekRotateCallback cb) {
        m_rotate_cb = cb;
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetRotationCount() const {
        return m_rotations;
    }

    void PrintTekStatus() const;

private:
    const crypto::CryptoParamsFile* m_params;
    std::array<TekRecord, 3>        m_teks;
    crypto::HmacKey                 m_hmac_key;
    TekRotateCallback               m_rotate_cb;
    utils::u64                      m_rotations = 0;

    void DoRotate(utils::u32 cluster_id,
                  const std::string& reason);
};

} // namespace apps
} // namespace uav

#endif // UAV_TEK_MANAGER_H
