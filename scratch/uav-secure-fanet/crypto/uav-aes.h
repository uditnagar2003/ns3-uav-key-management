/**
 * crypto/uav-aes.h
 *
 * AES-256-GCM authenticated encryption/decryption utility.
 *
 * WHY GCM:
 *   AES-256-GCM provides both confidentiality AND authentication
 *   in a single pass. The 16-byte GCM authentication tag replaces
 *   a separate HMAC for encrypted payloads, reducing overhead.
 *
 * PACKET USAGE:
 *   UAV data payload  → AES-256-GCM encrypt (this module)
 *   TEK distribution  → AES-256-GCM encrypt (this module)
 *   Integrity check   → HMAC-SHA256 over full packet (Module 10)
 *
 * KEY SIZES:
 *   Key  : 32 bytes (256-bit)
 *   IV   : 12 bytes (96-bit GCM standard)
 *   Tag  : 16 bytes (128-bit authentication tag)
 *   AAD  : variable (Additional Authenticated Data — e.g. packet header)
 *
 * WIRE FORMAT (encrypted buffer layout):
 *   [12-byte IV][ciphertext][16-byte GCM tag]
 *   Total overhead per message = 28 bytes
 *
 * THREAD SAFETY:
 *   AesGcm is stateless — all methods are static.
 *   Each call creates its own EVP_CIPHER_CTX internally.
 *   Safe to call concurrently from multiple threads.
 */

#ifndef UAV_AES_H
#define UAV_AES_H

#include "uav-types.h"
#include "uav-error.h"
#include "uav-openssl-ctx.h"
#include "uav-openssl-rand.h"

#include <array>
#include <cstddef>
#include <string>

namespace uav {
namespace crypto {

// ===========================================================================
// Constants
// ===========================================================================
constexpr std::size_t AES_GCM_KEY_BYTES = 32;   // 256-bit key
constexpr std::size_t AES_GCM_IV_BYTES  = 12;   // 96-bit IV
constexpr std::size_t AES_GCM_TAG_BYTES = 16;   // 128-bit tag
constexpr std::size_t AES_GCM_OVERHEAD  =        // IV + tag
    AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES;        // = 28 bytes

// ===========================================================================
// AesGcmKey — strong type for AES-256-GCM key
// ===========================================================================
using AesGcmKey = std::array<utils::u8, AES_GCM_KEY_BYTES>;

// ===========================================================================
// AesGcmResult — output of Encrypt()
// ===========================================================================
struct AesGcmResult {
    utils::ByteBuffer ciphertext;               // encrypted payload
    std::array<utils::u8, AES_GCM_IV_BYTES>  iv;   // random IV used
    std::array<utils::u8, AES_GCM_TAG_BYTES> tag;  // authentication tag
};

// ===========================================================================
// AesGcm — static utility class
// ===========================================================================
class AesGcm {
public:
    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate a cryptographically random AES-256-GCM key.
    static AesGcmKey GenerateKey();

    /// Derive a key from raw bytes (e.g. TEK material from CRT).
    /// Input must be exactly 32 bytes. Throws if wrong size.
    static AesGcmKey KeyFromBytes(const utils::ByteBuffer& raw);
    static AesGcmKey KeyFromBytes(const utils::u8* raw, std::size_t len);

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /// Encrypt plaintext with AES-256-GCM.
    ///
    /// @param key        32-byte AES-256 key
    /// @param plaintext  Data to encrypt
    /// @param aad        Additional Authenticated Data (e.g. packet header)
    ///                   Not encrypted but integrity-protected by tag.
    ///                   Pass empty ByteBuffer if no AAD.
    ///
    /// @returns AesGcmResult { ciphertext, iv, tag }
    ///          ciphertext.size() == plaintext.size()
    ///
    /// @throws CryptoException on OpenSSL failure
    static AesGcmResult Encrypt(
        const AesGcmKey&         key,
        const utils::ByteBuffer& plaintext,
        const utils::ByteBuffer& aad = {});

    /// Encrypt with explicit IV (for deterministic testing only).
    /// Production code always uses random IV via Encrypt().
    static AesGcmResult EncryptWithIv(
        const AesGcmKey&                        key,
        const std::array<utils::u8, 12>&        iv,
        const utils::ByteBuffer&                plaintext,
        const utils::ByteBuffer&                aad = {});

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /// Decrypt and verify AES-256-GCM ciphertext.
    ///
    /// @param key        32-byte AES-256 key
    /// @param iv         12-byte IV (from AesGcmResult or wire)
    /// @param ciphertext Encrypted data
    /// @param tag        16-byte authentication tag
    /// @param aad        Must match AAD used during encryption
    ///
    /// @returns Decrypted plaintext ByteBuffer
    ///
    /// @throws CryptoException if tag verification fails or OpenSSL error
    static utils::ByteBuffer Decrypt(
        const AesGcmKey&                        key,
        const std::array<utils::u8, 12>&        iv,
        const utils::ByteBuffer&                ciphertext,
        const std::array<utils::u8, 16>&        tag,
        const utils::ByteBuffer&                aad = {});

    // -----------------------------------------------------------------------
    // Wire format helpers
    // -----------------------------------------------------------------------

    /// Serialize AesGcmResult to wire format: [IV(12)][CT][TAG(16)]
    static utils::ByteBuffer Serialize(const AesGcmResult& result);

    /// Deserialize wire format back to components.
    /// Throws SerializationException if buffer too short.
    static AesGcmResult Deserialize(const utils::ByteBuffer& wire);

    // -----------------------------------------------------------------------
    // Convenience: encrypt plaintext string → wire bytes
    // -----------------------------------------------------------------------
    static utils::ByteBuffer EncryptToWire(
        const AesGcmKey&         key,
        const utils::ByteBuffer& plaintext,
        const utils::ByteBuffer& aad = {});

    /// Decrypt from wire format → plaintext bytes.
    static utils::ByteBuffer DecryptFromWire(
        const AesGcmKey&         key,
        const utils::ByteBuffer& wire,
        const utils::ByteBuffer& aad = {});

    // -----------------------------------------------------------------------
    // TEK-specific helpers
    // TEK is always exactly 32 bytes (AES-256 key material).
    // -----------------------------------------------------------------------

    /// Encrypt a 32-byte TEK using a KEK (key-encryption key).
    /// Returns wire format: [IV(12)][CT(32)][TAG(16)] = 60 bytes
    static utils::ByteBuffer EncryptTek(
        const AesGcmKey& kek,
        const AesGcmKey& tek,
        const utils::ByteBuffer& aad = {});

    /// Decrypt a 32-byte TEK from wire format.
    static AesGcmKey DecryptTek(
        const AesGcmKey& kek,
        const utils::ByteBuffer& wire,
        const utils::ByteBuffer& aad = {});

    // -----------------------------------------------------------------------
    // Key derivation helper
    // Derives a new key from an existing key + context string.
    // Used for TEK rotation: new_tek = KDF(old_tek, "rekey" || nonce)
    // -----------------------------------------------------------------------
    static AesGcmKey DeriveKey(
        const AesGcmKey&         input_key,
        const utils::ByteBuffer& context);
};

} // namespace crypto
} // namespace uav

#endif // UAV_AES_H