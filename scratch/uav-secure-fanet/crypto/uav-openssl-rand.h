/**
 * crypto/uav-openssl-rand.h
 *
 * Cryptographically secure random byte generation using OpenSSL.
 *
 * This is the ONLY source of cryptographic randomness in the project:
 *   - AES keys
 *   - GCM IVs
 *   - HMAC keys
 *   - Nonces
 *   - TEK material
 *
 * DO NOT use SecureRandom (Module 3) for cryptographic purposes.
 * SecureRandom uses mt19937_64 which is NOT cryptographically secure.
 */

#ifndef UAV_OPENSSL_RAND_H
#define UAV_OPENSSL_RAND_H

#include "uav-types.h"
#include "uav-error.h"

#include <openssl/rand.h>

#include <array>
#include <string>

namespace uav {
namespace crypto {

class OpenSSLRand {
public:
    // -----------------------------------------------------------------------
    // Fill a raw buffer with cryptographically secure random bytes.
    // Throws CryptoException if RAND_bytes fails.
    // -----------------------------------------------------------------------
    static void FillBytes(utils::u8* buf, std::size_t len);

    // -----------------------------------------------------------------------
    // Return a ByteBuffer of `len` random bytes.
    // -----------------------------------------------------------------------
    static utils::ByteBuffer RandomBytes(std::size_t len);

    // -----------------------------------------------------------------------
    // Fixed-size array specializations for common crypto sizes
    // -----------------------------------------------------------------------

    /// Generate a 256-bit (32-byte) AES key.
    static utils::Aes256Key RandomAes256Key();

    /// Generate a 128-bit (16-byte) AES IV (for CBC mode).
    static utils::AesIv RandomAesIv();

    /// Generate a 96-bit (12-byte) GCM IV / nonce.
    /// GCM standard recommends 96-bit IV for performance.
    static std::array<utils::u8, 12> RandomGcmIv();

    /// Generate a 128-bit (16-byte) nonce for replay protection.
    static utils::Nonce128 RandomNonce128();

    /// Generate a 256-bit (32-byte) HMAC key.
    static utils::HmacSha256 RandomHmacKey();

    // -----------------------------------------------------------------------
    // Random u64 (used for sequence numbers, timestamps)
    // -----------------------------------------------------------------------
    static utils::u64 RandomU64();

    // -----------------------------------------------------------------------
    // OpenSSL RAND status check.
    // Returns true if the PRNG has been seeded sufficiently.
    // -----------------------------------------------------------------------
    static bool IsSeeded();

    // -----------------------------------------------------------------------
    // Seed the PRNG with additional entropy (optional, usually automatic).
    // -----------------------------------------------------------------------
    static void AddEntropy(const utils::u8* buf, std::size_t len,
                           double entropy_estimate);
};

} // namespace crypto
} // namespace uav

#endif // UAV_OPENSSL_RAND_H