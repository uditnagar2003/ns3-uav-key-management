/**
 * crypto/uav-bigint.cc
 *
 * Implementation of BigIntOps.
 *
 * Key design notes:
 *   - All functions are pure (no global state).
 *   - Miller-Rabin uses boost's built-in implementation.
 *   - Safe prime generation uses the direct sieve approach:
 *       generate random odd q of (bits-1) bits,
 *       compute p = 2q+1,
 *       test both for primality.
 *   - CRT uses the Garner algorithm for efficiency.
 *   - All MKE-MGKM formulas directly mirror Algorithm 1 of Park et al.
 */

#include "uav-bigint.h"
#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-string-utils.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random.hpp>

#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace uav {
namespace crypto {

// ===========================================================================
// Internal helpers
// ===========================================================================

namespace {

/// Simple Miller-Rabin wrapper using boost's mt19937
boost::random::mt19937 MakeBoostRng(std::mt19937_64& rng) {
    boost::random::mt19937 boost_mt;
    boost_mt.seed(static_cast<uint32_t>(rng()));
    return boost_mt;
}

} // anonymous namespace

// ===========================================================================
// Modular arithmetic
// ===========================================================================

BigInt BigIntOps::ModPow(const BigInt& base,
                          const BigInt& exp,
                          const BigInt& mod) {
    if (mod == 0) {
        UAV_THROW(utils::CryptoException, "ModPow: modulus is zero");
    }
    if (exp < 0) {
        UAV_THROW(utils::CryptoException, "ModPow: negative exponent");
    }
    return boost::multiprecision::powm(base, exp, mod);
}

BigInt BigIntOps::ModInverse(const BigInt& a, const BigInt& m) {
    if (m <= 1) {
        UAV_THROW(utils::CryptoException,
                  "ModInverse: modulus must be > 1");
    }

    // Extended Euclidean algorithm
    BigInt old_r = a, r = m;
    BigInt old_s = 1, s = 0;

    while (r != 0) {
        BigInt q = old_r / r;
        BigInt tmp = r;
        r     = old_r - q * r;
        old_r = tmp;

        tmp   = s;
        s     = old_s - q * s;
        old_s = tmp;
    }

    if (old_r != 1) {
        UAV_THROW(utils::CryptoException,
                  "ModInverse: gcd != 1, inverse does not exist");
    }

    // Ensure result is positive
    return Mod(old_s, m);
}

BigInt BigIntOps::Gcd(const BigInt& a, const BigInt& b) {
    return boost::multiprecision::gcd(
        boost::multiprecision::abs(a),
        boost::multiprecision::abs(b));
}

BigInt BigIntOps::Lcm(const BigInt& a, const BigInt& b) {
    if (a == 0 || b == 0) return BigInt(0);
    return boost::multiprecision::abs(a) /
           Gcd(a, b) *
           boost::multiprecision::abs(b);
}

BigInt BigIntOps::Mod(const BigInt& a, const BigInt& m) {
    BigInt result = a % m;
    if (result < 0) result += m;
    return result;
}

// ===========================================================================
// Primality
// ===========================================================================

bool BigIntOps::IsProbablePrime(const BigInt& n, unsigned k) {
    if (n < 2)  return false;
    if (n == 2) return true;
    if (n == 3) return true;
    if (n % 2 == 0) return false;

    boost::random::mt19937 boost_rng(42);
    return boost::multiprecision::miller_rabin_test(n, k, boost_rng);
}

bool BigIntOps::IsSafePrime(const BigInt& p) {
    if (!IsProbablePrime(p)) return false;
    BigInt q = (p - 1) / 2;
    return IsProbablePrime(q);
}

// ===========================================================================
// Random generation
// ===========================================================================

BigInt BigIntOps::RandomBelow(const BigInt& upper_bound,
                               std::mt19937_64& rng) {
    if (upper_bound <= 0) {
        UAV_THROW(utils::CryptoException,
                  "RandomBelow: upper_bound must be > 0");
    }

    unsigned bits = static_cast<unsigned>(
        boost::multiprecision::msb(upper_bound) + 1);

    BigInt result;
    do {
        result = RandomBits(bits, rng);
    } while (result >= upper_bound);

    return result;
}

BigInt BigIntOps::RandomBits(unsigned bits, std::mt19937_64& rng) {
    if (bits == 0) return BigInt(0);

    BigInt result = 0;
    unsigned full_words = bits / 64;
    unsigned rem_bits   = bits % 64;

    for (unsigned i = 0; i < full_words; ++i) {
        result <<= 64;
        result  |= BigInt(rng());
    }
    if (rem_bits > 0) {
        result <<= rem_bits;
        result  |= BigInt(rng() >> (64 - rem_bits));
    }

    // Ensure MSB is set (so it's exactly `bits` bits)
    if (bits > 0) {
        result |= (BigInt(1) << (bits - 1));
    }

    return result;
}

BigInt BigIntOps::GenerateSafePrime(unsigned bits, std::mt19937_64& rng) {
    if (bits < 8) {
        UAV_THROW(utils::CryptoException,
                  "GenerateSafePrime: bits must be >= 8");
    }

    // Use OpenSSL BN_generate_prime_ex with safe=1 flag.
    // BN_generate_prime_ex generates p such that (p-1)/2 is also prime.
    // This is exactly the safe prime definition required by MKE-MGKM.
    BIGNUM* bn = BN_new();
    if (!bn) {
        UAV_THROW(utils::CryptoException,
                  "GenerateSafePrime: BN_new() failed");
    }

    // safe=1 means generate safe prime p where q=(p-1)/2 is also prime
    int rc = BN_generate_prime_ex(
        bn,                  // output BIGNUM
        static_cast<int>(bits), // bit length
        1,                   // safe = 1 (safe prime)
        nullptr,             // add = NULL
        nullptr,             // rem = NULL
        nullptr              // callback = NULL
    );

    if (rc != 1) {
        BN_free(bn);
        UAV_THROW(utils::CryptoException,
                  "GenerateSafePrime: BN_generate_prime_ex() failed");
    }

    // Convert OpenSSL BIGNUM to Boost cpp_int via hex string
    char* hex = BN_bn2hex(bn);
    if (!hex) {
        BN_free(bn);
        UAV_THROW(utils::CryptoException,
                  "GenerateSafePrime: BN_bn2hex() failed");
    }

    std::string hex_str(hex);
    OPENSSL_free(hex);
    BN_free(bn);

    BigInt p = FromHexString(hex_str);

    UAV_LOG_DEBUG(log::channels::CRYPTO,
        "GenerateSafePrime: OpenSSL generated "
        << bits << "-bit safe prime");

    return p;
}

BigIntVec BigIntOps::GenerateSafePrimes(unsigned count,
                                         unsigned bits,
                                         std::mt19937_64& rng) {
    BigIntVec primes;
    primes.reserve(count);
    for (unsigned i = 0; i < count; ++i) {
        primes.push_back(GenerateSafePrime(bits, rng));
        UAV_LOG_INFO(log::channels::CRYPTO,
                     "OpenSSL generated safe prime "
                     << (i + 1) << "/" << count);
    }
    return primes;
}

// ===========================================================================
// CRT — Chinese Remainder Theorem (Garner's algorithm)
// ===========================================================================

BigInt BigIntOps::CRT(const BigIntVec& remainders,
                       const BigIntVec& moduli) {
    if (remainders.size() != moduli.size()) {
        UAV_THROW(utils::CryptoException,
                  "CRT: remainders and moduli must have same size");
    }
    if (remainders.empty()) {
        UAV_THROW(utils::CryptoException, "CRT: empty input");
    }

    std::size_t n = moduli.size();

    // Verify pairwise coprime
    for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t j = i + 1; j < n; ++j) {
            if (Gcd(moduli[i], moduli[j]) != 1) {
                UAV_THROW(utils::CryptoException,
                          "CRT: moduli are not pairwise coprime");
            }
        }
    }

    // Compute product of all moduli
    BigInt M = 1;
    for (const auto& m : moduli) M *= m;

    // Standard CRT formula: x = sum( r_i * M_i * y_i ) mod M
    // where M_i = M / m_i, y_i = M_i^-1 mod m_i
    BigInt result = 0;
    for (std::size_t i = 0; i < n; ++i) {
        BigInt Mi = M / moduli[i];
        BigInt yi = ModInverse(Mi, moduli[i]);
        result += remainders[i] * Mi * yi;
    }

    return Mod(result, M);
}

// ===========================================================================
// MKE-MGKM specific helpers (Algorithm 1 — MKeyGen, Park et al.)
// ===========================================================================

BigInt BigIntOps::ComputeX(const BigInt& p) {
    // x_i = (p_i - 1) / 2
    return (p - 1) / 2;
}

BigInt BigIntOps::ComputeY(const BigInt& q) {
    // y_i = (q_i - 1) / 2
    return (q - 1) / 2;
}

BigInt BigIntOps::GenerateEi(std::mt19937_64& rng) {
    // e_i = 4 * R + 1  where R is a random positive integer
    // This guarantees e_i ≡ 1 (mod 4)
    BigInt R = BigInt(rng()) + 1;   // R >= 1
    return 4 * R + 1;
}

BigInt BigIntOps::ComputeDi(const BigInt& e_i,
                              const BigInt& x_i,
                              const BigInt& y_i) {
    // d_i = e_i^(2*(x_i-1)*(y_i-1) - 1)  mod (4 * x_i * y_i)
    //
    // Reference Python: exp = 2*(x-1)*(y-1) - 1
    // The -1 is INSIDE the exponent, not subtracted after.
    BigInt modulus = 4 * x_i * y_i;
    BigInt exp_val = 2 * (x_i - 1) * (y_i - 1) - 1;
    return ModPow(e_i, exp_val, modulus);
}

BigInt BigIntOps::ComputeMi(const BigInt& n_product,
                              const BigInt& x_i,
                              const BigInt& y_i) {
    // M[i] = n / (x_i * y_i)
    // where n = product of all x_j * y_j
    BigInt denom = x_i * y_i;
    if (n_product % denom != 0) {
        UAV_THROW(utils::CryptoException,
                  "ComputeMi: n_product is not divisible by x_i*y_i");
    }
    return n_product / denom;
}

BigInt BigIntOps::ComputeNi(const BigInt& Mi,
                              const BigInt& x_i,
                              const BigInt& y_i) {
    // N[i] = Mi^-1 mod (x_i * y_i)
    // Reference Python: Ni = inverse(Mi, xi_yi)
    // Standard CRT coefficient — modular inverse of Mi mod xi*yi
    BigInt modulus = x_i * y_i;
    return ModInverse(Mi, modulus);
}

// ===========================================================================
// Serialisation
// ===========================================================================

BigInt BigIntOps::FromDecString(const std::string& s) {
    if (s.empty()) {
        UAV_THROW(utils::CryptoException,
                  "FromDecString: empty string");
    }
    try {
        return BigInt(s);
    } catch (const std::exception& ex) {
        UAV_THROW(utils::CryptoException,
                  std::string("FromDecString: parse error: ") + ex.what());
    }
}

BigInt BigIntOps::FromHexString(const std::string& s) {
    if (s.empty()) {
        UAV_THROW(utils::CryptoException,
                  "FromHexString: empty string");
    }
    std::string hex = s;
    // Strip optional 0x prefix
    if (hex.size() >= 2 &&
        hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex = hex.substr(2);
    }
    try {
        return BigInt("0x" + hex);
    } catch (const std::exception& ex) {
        UAV_THROW(utils::CryptoException,
                  std::string("FromHexString: parse error: ") + ex.what());
    }
}

std::string BigIntOps::ToDecString(const BigInt& n) {
    return n.str();
}

std::string BigIntOps::ToHexString(const BigInt& n) {
    if (n == 0) return "00";
    std::ostringstream oss;
    oss << std::hex << n;
    return oss.str();
}

utils::ByteBuffer BigIntOps::ToBytes(const BigInt& n, std::size_t bytes) {
    if (n < 0) {
        UAV_THROW(utils::CryptoException,
                  "ToBytes: negative BigInt cannot be serialised");
    }

    utils::ByteBuffer buf(bytes, 0);
    BigInt tmp = n;

    for (std::size_t i = bytes; i > 0; --i) {
        buf[i - 1] = static_cast<utils::u8>(
            static_cast<unsigned>(tmp & 0xFF));
        tmp >>= 8;
    }

    if (tmp != 0) {
        UAV_THROW(utils::CryptoException,
                  "ToBytes: BigInt does not fit in " +
                  std::to_string(bytes) + " bytes");
    }

    return buf;
}

BigInt BigIntOps::FromBytes(const utils::ByteBuffer& buf) {
    return FromBytes(buf.data(), buf.size());
}

BigInt BigIntOps::FromBytes(const utils::u8* data, std::size_t len) {
    BigInt result = 0;
    for (std::size_t i = 0; i < len; ++i) {
        result = (result << 8) | BigInt(data[i]);
    }
    return result;
}

} // namespace crypto
} // namespace uav