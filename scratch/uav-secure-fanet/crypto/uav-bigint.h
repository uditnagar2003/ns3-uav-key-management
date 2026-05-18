/**
 * crypto/uav-bigint.h
 *
 * Project-wide Boost.Multiprecision wrapper for CRT/GCRT operations.
 *
 * WHY THIS MODULE EXISTS:
 *   The MKE-MGKM scheme (Park et al.) requires arithmetic on integers
 *   that are hundreds to thousands of bits wide:
 *     - Safe primes p, q: 512-bit each
 *     - Per-slave moduli n_i = p_i * q_i: 1024-bit
 *     - Master modulus M = product of all x_i*y_i: potentially 18*512 bits
 *     - GCRT master exponent e_M: same size as M
 *
 *   Standard 64-bit integers cannot represent these. This module provides
 *   a single, consistent BigInt type used by ALL crypto modules.
 *
 * TYPE ALIASES:
 *   BigInt      = boost::multiprecision::cpp_int  (arbitrary precision)
 *   BigIntVec   = std::vector<BigInt>
 *
 * KEY FUNCTIONS (mirror the paper's Algorithm 1 & 2):
 *   BigInt ModPow(base, exp, mod)    — modular exponentiation
 *   BigInt ModInverse(a, m)          — modular inverse (extended Euclidean)
 *   BigInt Gcd(a, b)                 — greatest common divisor
 *   bool   IsSafePrime(p)            — primality + safe prime test
 *   BigInt GenerateSafePrime(bits)   — safe prime generation
 *   BigInt CRT(remainders, moduli)   — Chinese Remainder Theorem
 *
 * SERIALISATION:
 *   BigInt   FromDecString(s)        — parse decimal string
 *   BigInt   FromHexString(s)        — parse hex string
 *   string   ToDecString(n)          — decimal string
 *   string   ToHexString(n)          — hex string
 */

#ifndef UAV_BIGINT_H
#define UAV_BIGINT_H

#include "uav-types.h"
#include "uav-error.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <openssl/bn.h>

#include <random>
#include <string>
#include <vector>

namespace uav {
namespace crypto {

// ===========================================================================
// Core type aliases
// ===========================================================================
using BigInt    = boost::multiprecision::cpp_int;
using BigIntVec = std::vector<BigInt>;

// ===========================================================================
// BigIntOps — static methods for all CRT/GCRT arithmetic
// ===========================================================================
class BigIntOps {
public:
    // -----------------------------------------------------------------------
    // Modular arithmetic
    // -----------------------------------------------------------------------

    /// Modular exponentiation: base^exp mod m
    /// Equivalent to Python pow(base, exp, m)
    static BigInt ModPow(const BigInt& base,
                         const BigInt& exp,
                         const BigInt& mod);

    /// Modular inverse: a^-1 mod m using extended Euclidean algorithm.
    /// Throws CryptoException if inverse does not exist (gcd(a,m) != 1).
    static BigInt ModInverse(const BigInt& a, const BigInt& m);

    /// Greatest common divisor.
    static BigInt Gcd(const BigInt& a, const BigInt& b);

    /// Least common multiple.
    static BigInt Lcm(const BigInt& a, const BigInt& b);

    /// True modulo (always non-negative, unlike C++ % which can be negative).
    static BigInt Mod(const BigInt& a, const BigInt& m);

    // -----------------------------------------------------------------------
    // Primality
    // -----------------------------------------------------------------------

    /// Miller-Rabin primality test with k rounds.
    /// k=25 gives error probability < 4^(-25).
    static bool IsProbablePrime(const BigInt& n, unsigned k = 25);

    /// Returns true if p is a safe prime: p is prime AND (p-1)/2 is prime.
    static bool IsSafePrime(const BigInt& p);

    // -----------------------------------------------------------------------
    // Random big integer generation
    // -----------------------------------------------------------------------

    /// Generate a random BigInt in [0, upper_bound).
    static BigInt RandomBelow(const BigInt& upper_bound, std::mt19937_64& rng);

    /// Generate a random `bits`-bit BigInt (MSB always set).
    static BigInt RandomBits(unsigned bits, std::mt19937_64& rng);

    /// Generate a random safe prime of exactly `bits` bits.
    /// A safe prime p satisfies: p is prime AND q=(p-1)/2 is prime.
    /// Runs until one is found (probabilistic — typically fast for 512-bit).
    static BigInt GenerateSafePrime(unsigned bits, std::mt19937_64& rng);

    /// Generate `count` independent safe primes, each `bits` bits.
    static BigIntVec GenerateSafePrimes(unsigned count,
                                        unsigned bits,
                                        std::mt19937_64& rng);

    // -----------------------------------------------------------------------
    // CRT — Chinese Remainder Theorem
    // Computes x such that x ≡ r[i] (mod m[i]) for all i.
    // Requires moduli to be pairwise coprime.
    // Throws CryptoException if moduli are not pairwise coprime.
    // -----------------------------------------------------------------------
    static BigInt CRT(const BigIntVec& remainders,
                      const BigIntVec& moduli);

    // -----------------------------------------------------------------------
    // MKE-MGKM specific helpers (Algorithm 1 — MKeyGen)
    // These implement the exact formulas from Park et al.
    // -----------------------------------------------------------------------

    /// Compute x_i = (p_i - 1) / 2  (Sophie Germain companion)
    static BigInt ComputeX(const BigInt& p);

    /// Compute y_i = (q_i - 1) / 2
    static BigInt ComputeY(const BigInt& q);

    /// Generate e_i = 4 * R + 1 where R is random.
    /// Ensures e_i ≡ 1 (mod 4) as required by the scheme.
    static BigInt GenerateEi(std::mt19937_64& rng);

    /// Compute d_i = e_i^(2*(x_i-1)*(y_i-1)) - 1  mod (4 * x_i * y_i)
    /// This is the slave decryption exponent from Algorithm 1 Step 2.
    static BigInt ComputeDi(const BigInt& e_i,
                             const BigInt& x_i,
                             const BigInt& y_i);

    /// Compute M[i] = n / (x_i * y_i)   where n = product of all x_j*y_j
    static BigInt ComputeMi(const BigInt& n_product,
                             const BigInt& x_i,
                             const BigInt& y_i);

    /// Compute N[i] = Mi^-1 mod (x_i * y_i) — standard CRT coefficient
    static BigInt ComputeNi(const BigInt& Mi,
                             const BigInt& x_i,
                             const BigInt& y_i);

    // -----------------------------------------------------------------------
    // Serialisation / deserialisation
    // -----------------------------------------------------------------------
    static BigInt       FromDecString(const std::string& s);
    static BigInt       FromHexString(const std::string& s);
    static std::string  ToDecString  (const BigInt& n);
    static std::string  ToHexString  (const BigInt& n);

    /// Encode BigInt as fixed-width big-endian byte buffer.
    /// If n requires more than `bytes` bytes, throws CryptoException.
    static utils::ByteBuffer ToBytes(const BigInt& n, std::size_t bytes);

    /// Decode big-endian byte buffer to BigInt.
    static BigInt FromBytes(const utils::ByteBuffer& buf);
    static BigInt FromBytes(const utils::u8* data, std::size_t len);
};

} // namespace crypto
} // namespace uav

#endif // UAV_BIGINT_H