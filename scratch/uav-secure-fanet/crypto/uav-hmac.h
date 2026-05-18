/**
 * crypto/uav-hmac.h
 *
 * HMAC-SHA256 utility for packet integrity and authentication.
 *
 * USAGE IN PACKET FORMAT:
 *   [HEADER][MT_K][AES_PAYLOAD][HMAC-SHA256]
 *
 *   HMAC is computed over:
 *     HEADER + MT_K + AES_PAYLOAD (everything except the HMAC field)
 *
 *   HMAC key = TEK (Traffic Encryption Key, 32 bytes)
 *
 * WHY HMAC ON TOP OF AES-GCM:
 *   AES-GCM tag authenticates only the payload.
 *   HMAC-SHA256 authenticates the ENTIRE packet including
 *   plaintext headers and MT_K fields.
 *
 * SECURITY PROPERTIES:
 *   - 256-bit output (32 bytes)
 *   - Constant-time verification (timing-safe comparison)
 *   - Keyed — requires TEK knowledge to forge
 *   - Covers full packet wire bytes
 *
 * THREAD SAFETY:
 *   HmacSha256Util is stateless — all methods static.
 *   Each call creates its own EVP_MAC_CTX internally.
 */

#ifndef UAV_HMAC_H
#define UAV_HMAC_H

#include "uav-types.h"
#include "uav-error.h"
#include "uav-openssl-ctx.h"
#include "uav-openssl-rand.h"

#include <array>
#include <string>

namespace uav {
namespace crypto {

// ===========================================================================
// Constants
// ===========================================================================
constexpr std::size_t HMAC_SHA256_OUTPUT_BYTES = 32;  // 256-bit output
constexpr std::size_t HMAC_KEY_BYTES           = 32;  // 256-bit key

// ===========================================================================
// HmacKey — strong type for HMAC-SHA256 key
// ===========================================================================
using HmacKey = std::array<utils::u8, HMAC_KEY_BYTES>;

// ===========================================================================
// HmacSha256Util — static utility class
// ===========================================================================
class HmacSha256Util {
public:
    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate a cryptographically random HMAC key (32 bytes).
    static HmacKey GenerateKey();

    /// Build HmacKey from raw bytes.
    /// Throws CryptoException if len != 32.
    static HmacKey KeyFromBytes(const utils::u8* raw,
                                std::size_t len);
    static HmacKey KeyFromBytes(const utils::ByteBuffer& raw);

    /// Build HmacKey from AesGcmKey (same size — TEK reuse).
    static HmacKey KeyFromAesKey(
        const std::array<utils::u8, 32>& aes_key);

    // -----------------------------------------------------------------------
    // Compute HMAC
    // -----------------------------------------------------------------------

    /// Compute HMAC-SHA256 over a single buffer.
    ///
    /// @param key   32-byte HMAC key (TEK)
    /// @param data  Input data (full packet wire bytes minus HMAC field)
    /// @returns     32-byte HMAC digest
    static utils::HmacSha256 Compute(
        const HmacKey&           key,
        const utils::ByteBuffer& data);

    /// Compute HMAC-SHA256 over a raw pointer buffer.
    static utils::HmacSha256 Compute(
        const HmacKey&    key,
        const utils::u8*  data,
        std::size_t       len);

    /// Compute HMAC-SHA256 over multiple buffers (scatter-gather).
    /// Equivalent to concatenating all buffers then computing HMAC.
    /// More efficient — avoids allocation of concatenated buffer.
    static utils::HmacSha256 ComputeMulti(
        const HmacKey&                           key,
        const std::vector<utils::ByteBuffer>&    parts);

    // -----------------------------------------------------------------------
    // Verify HMAC (constant-time)
    // -----------------------------------------------------------------------

    /// Verify HMAC-SHA256 in constant time.
    /// Returns true if valid, false if invalid.
    /// NEVER throws on mismatch — caller decides action.
    static bool Verify(
        const HmacKey&           key,
        const utils::ByteBuffer& data,
        const utils::HmacSha256& expected);

    /// Verify and throw CryptoException on mismatch.
    static void VerifyOrThrow(
        const HmacKey&           key,
        const utils::ByteBuffer& data,
        const utils::HmacSha256& expected);

    /// Verify over raw pointer.
    static bool Verify(
        const HmacKey&           key,
        const utils::u8*         data,
        std::size_t              len,
        const utils::HmacSha256& expected);

    // -----------------------------------------------------------------------
    // Packet-level helpers
    // -----------------------------------------------------------------------

    /// Append 32-byte HMAC to end of packet buffer.
    /// Input: packet bytes WITHOUT hmac field
    /// Output: same buffer WITH hmac appended (grows by 32 bytes)
    static void AppendHmac(
        const HmacKey&     key,
        utils::ByteBuffer& packet);

    /// Verify and strip HMAC from end of packet buffer.
    /// Input:  packet bytes WITH hmac field (last 32 bytes)
    /// Output: packet bytes WITHOUT hmac field
    /// Throws CryptoException if HMAC invalid or buffer too short.
    static utils::ByteBuffer StripAndVerifyHmac(
        const HmacKey&           key,
        const utils::ByteBuffer& packet_with_hmac);

    // -----------------------------------------------------------------------
    // SHA-256 (no key) — for hashing nonces, sequence numbers, etc.
    // -----------------------------------------------------------------------

    /// Compute SHA-256 digest (no key).
    static utils::Sha256Hash Sha256(
        const utils::ByteBuffer& data);

    static utils::Sha256Hash Sha256(
        const utils::u8* data,
        std::size_t      len);

    /// SHA-256 of string (convenience).
    static utils::Sha256Hash Sha256(const std::string& s);
};

} // namespace crypto
} // namespace uav

#endif // UAV_HMAC_H