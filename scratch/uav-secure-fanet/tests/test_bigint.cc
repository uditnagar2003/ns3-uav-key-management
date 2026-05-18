/**
 * tests/test_bigint.cc
 * Unit test for Phase 2 Module 7: Boost Multiprecision Integration
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I/usr/include \
 *       tests/test_bigint.cc \
 *       utils/uav-error.cc \
 *       utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc \
 *       utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc \
 *       utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc \
 *       utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc \
 *       utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-bigint.cc \
 *       -o tests/test_bigint
 *
 * RUN:
 *   ./tests/test_bigint
 */

#include "crypto/uav-bigint.h"
#include "crypto/uav-bigint-utils.h"
#include "utils/uav-logger.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>

using namespace uav::crypto;
using namespace uav;

namespace {

int g_pass = 0;
int g_fail = 0;

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { \
        std::cerr << "  ASSERT_TRUE failed: " #expr \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_EQ(a, b) \
    do { if (!((a) == (b))) { \
        std::cerr << "  ASSERT_EQ failed: " #a " != " #b \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_THROWS(expr) \
    do { bool threw = false; \
        try { expr; } catch (...) { threw = true; } \
        if (!threw) { \
            std::cerr << "  ASSERT_THROWS failed: " #expr \
                      << " @ line " << __LINE__ << "\n"; \
            return false; } } while (0)

void RunTest(const std::string& name, bool (*fn)()) {
    std::cout << "[ RUN  ] " << name << "\n";
    bool ok = false;
    try { ok = fn(); }
    catch (const std::exception& ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        ok = false;
    }
    if (ok) { std::cout << "[ PASS ] " << name << "\n\n"; ++g_pass; }
    else    { std::cout << "[ FAIL ] " << name << "\n\n"; ++g_fail; }
}

std::mt19937_64 g_rng(42);

// ===========================================================================
// Test 1: Basic BigInt construction and arithmetic
// ===========================================================================
bool test_basic_arithmetic() {
    BigInt a = B("123456789012345678901234567890");
    BigInt b = B("987654321098765432109876543210");

    BigInt sum  = a + b;
    BigInt diff = b - a;
    BigInt prod = a * b;

    ASSERT_TRUE(sum  > a);
    ASSERT_TRUE(diff > 0);
    ASSERT_TRUE(prod > b);

    // Verify against known results
    ASSERT_EQ(BigIntOps::ToDecString(a + b),
              std::string("1111111110111111111011111111100"));

    // Integer literals
    BigInt x = B(42LL);
    BigInt y = B(100ULL);
    ASSERT_EQ(x + y, BigInt(142));

    // Utility helpers
    ASSERT_TRUE(IsZero(BigInt(0)));
    ASSERT_TRUE(IsOne(BigInt(1)));
    ASSERT_TRUE(!IsZero(BigInt(1)));
    ASSERT_TRUE(FitsU64(BigInt(12345678901234567ULL)));
    ASSERT_TRUE(!FitsU32(BigInt("99999999999")));

    return true;
}

// ===========================================================================
// Test 2: Modular arithmetic
// ===========================================================================
bool test_modular_arithmetic() {
    // ModPow — Python: pow(2, 100, 1000000007) = ?
    BigInt base(2), exp_v(100), mod(1000000007);
    BigInt result = BigIntOps::ModPow(base, exp_v, mod);
    // Known result: 2^100 mod 1000000007 = 976371285
    ASSERT_EQ(result, BigInt(976371285));

    // ModInverse — 3^-1 mod 7 = 5  (since 3*5 = 15 ≡ 1 mod 7)
    BigInt inv = BigIntOps::ModInverse(BigInt(3), BigInt(7));
    ASSERT_EQ(inv, BigInt(5));
    ASSERT_EQ((BigInt(3) * inv) % BigInt(7), BigInt(1));

    // ModInverse with large numbers
    BigInt p = B("1000000007");   // prime
    BigInt a = B("123456789");
    BigInt a_inv = BigIntOps::ModInverse(a, p);
    ASSERT_EQ(BigIntOps::Mod(a * a_inv, p), BigInt(1));

    // ModInverse fails when gcd != 1
    ASSERT_THROWS(BigIntOps::ModInverse(BigInt(6), BigInt(9)));

    // Gcd
    ASSERT_EQ(BigIntOps::Gcd(BigInt(12), BigInt(8)), BigInt(4));
    ASSERT_EQ(BigIntOps::Gcd(BigInt(17), BigInt(13)), BigInt(1));

    // Lcm
    ASSERT_EQ(BigIntOps::Lcm(BigInt(4), BigInt(6)), BigInt(12));

    // Mod — always non-negative
    ASSERT_EQ(BigIntOps::Mod(BigInt(-7), BigInt(5)), BigInt(3));
    ASSERT_EQ(BigIntOps::Mod(BigInt(7),  BigInt(5)), BigInt(2));

    // ModPow with zero exponent
    ASSERT_EQ(BigIntOps::ModPow(BigInt(100), BigInt(0), BigInt(7)),
              BigInt(1));

    return true;
}

// ===========================================================================
// Test 3: CRT — Chinese Remainder Theorem
// ===========================================================================
bool test_crt() {
    // x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) → x = 23
    BigIntVec r = { BigInt(2), BigInt(3), BigInt(2) };
    BigIntVec m = { BigInt(3), BigInt(5), BigInt(7) };
    BigInt x = BigIntOps::CRT(r, m);
    ASSERT_EQ(x % BigInt(3), BigInt(2));
    ASSERT_EQ(x % BigInt(5), BigInt(3));
    ASSERT_EQ(x % BigInt(7), BigInt(2));
    ASSERT_EQ(x, BigInt(23));

    // CRT with two large coprime moduli
    BigInt p1 = B("1000000007");
    BigInt p2 = B("998244353");
    BigIntVec r2 = { BigInt(42), BigInt(100) };
    BigIntVec m2 = { p1, p2 };
    BigInt x2 = BigIntOps::CRT(r2, m2);
    ASSERT_EQ(BigIntOps::Mod(x2, p1), BigInt(42));
    ASSERT_EQ(BigIntOps::Mod(x2, p2), BigInt(100));

    // Non-coprime moduli should throw
    BigIntVec bad_m = { BigInt(6), BigInt(10) }; // gcd=2
    BigIntVec bad_r = { BigInt(1), BigInt(1)  };
    ASSERT_THROWS(BigIntOps::CRT(bad_r, bad_m));

    return true;
}

// ===========================================================================
// Test 4: Primality tests
// ===========================================================================
bool test_primality() {
    // Known primes
    ASSERT_TRUE(BigIntOps::IsProbablePrime(BigInt(2)));
    ASSERT_TRUE(BigIntOps::IsProbablePrime(BigInt(3)));
    ASSERT_TRUE(BigIntOps::IsProbablePrime(BigInt(17)));
    ASSERT_TRUE(BigIntOps::IsProbablePrime(BigInt(1000000007)));

    // Known composites
    ASSERT_TRUE(!BigIntOps::IsProbablePrime(BigInt(1)));
    ASSERT_TRUE(!BigIntOps::IsProbablePrime(BigInt(4)));
    ASSERT_TRUE(!BigIntOps::IsProbablePrime(BigInt(1000000006)));

    // Known safe primes: 11 (q=5), 23 (q=11), 47 (q=23), 59 (q=29)
    ASSERT_TRUE(BigIntOps::IsSafePrime(BigInt(11)));
    ASSERT_TRUE(BigIntOps::IsSafePrime(BigInt(23)));
    ASSERT_TRUE(BigIntOps::IsSafePrime(BigInt(47)));
    ASSERT_TRUE(!BigIntOps::IsSafePrime(BigInt(13))); // 13 prime but 6 not

    // Large known safe prime:
    // p = 2 * 1000000007 + 1 = 2000000015 — check if 1000000007 is prime
    // 1000000007 IS prime, so 2000000015 = 2*1000000007+1 should be safe
    // (verify: IsProbablePrime(2000000015) and IsProbablePrime(1000000007))
    BigInt q_big = BigInt(1000000007);
    BigInt p_big = 2 * q_big + 1;
    if (BigIntOps::IsProbablePrime(p_big)) {
        ASSERT_TRUE(BigIntOps::IsSafePrime(p_big));
    }

    return true;
}

// ===========================================================================
// Test 5: Safe prime generation (small bits for speed)
// ===========================================================================
bool test_safe_prime_generation() {
    // Generate a small safe prime (32-bit range is fast)
    BigInt p = BigIntOps::GenerateSafePrime(8, g_rng);

    ASSERT_TRUE(p > 0);
    ASSERT_TRUE(BigIntOps::IsProbablePrime(p));
    BigInt q = (p - 1) / 2;
    ASSERT_TRUE(BigIntOps::IsProbablePrime(q));

    std::cout << "  Generated 32-bit safe prime: " << p << "\n";
    std::cout << "  Sophie Germain q = " << q << "\n";

    // Generate 3 safe primes
    BigIntVec primes = BigIntOps::GenerateSafePrimes(3, 8, g_rng);
    ASSERT_EQ(primes.size(), 3u);
    for (const auto& pp : primes) {
        ASSERT_TRUE(BigIntOps::IsSafePrime(pp));
    }

    return true;
}

// ===========================================================================
// Test 6: MKE-MGKM helpers (Algorithm 1 formulas)
// ===========================================================================
bool test_mkemgkm_helpers() {
    // Use small safe prime for speed
    BigInt p = BigIntOps::GenerateSafePrime(8, g_rng);
    BigInt q = BigIntOps::GenerateSafePrime(8, g_rng);

    BigInt x = BigIntOps::ComputeX(p);
    BigInt y = BigIntOps::ComputeY(q);

    // Verify x = (p-1)/2 and y = (q-1)/2
    ASSERT_EQ(x, (p - 1) / 2);
    ASSERT_EQ(y, (q - 1) / 2);
    ASSERT_TRUE(BigIntOps::IsProbablePrime(x));  // x is Sophie Germain
    ASSERT_TRUE(BigIntOps::IsProbablePrime(y));

    // e_i = 4*R+1 → must be ≡ 1 (mod 4)
    BigInt e_i = BigIntOps::GenerateEi(g_rng);
    ASSERT_EQ(e_i % 4, BigInt(1));
    ASSERT_TRUE(e_i > 0);

    // d_i computation
    BigInt d_i = BigIntOps::ComputeDi(e_i, x, y);
    ASSERT_TRUE(d_i >= 0);

    // Verify slave decryption property:
    // e_i * (d_i + 1) ≡ e_i^(2*(x-1)*(y-1))  (mod 4*x*y)
    BigInt mod4xy  = 4 * x * y;
    BigInt lhs     = BigIntOps::Mod(e_i * (d_i + 1), mod4xy);
    BigInt exp_val = 2 * (x - 1) * (y - 1);
    BigInt rhs     = BigIntOps::ModPow(e_i, exp_val, mod4xy);
    ASSERT_EQ(lhs, rhs);

    std::cout << "  e_i = " << e_i << "\n";
    std::cout << "  d_i = " << d_i << "\n";
    std::cout << "  Slave decryption property VERIFIED\n";

    // M[i] and N[i] — use two slaves
    BigInt p2 = BigIntOps::GenerateSafePrime(8, g_rng);
    BigInt q2 = BigIntOps::GenerateSafePrime(8, g_rng);
    BigInt x2 = BigIntOps::ComputeX(p2);
    BigInt y2 = BigIntOps::ComputeY(q2);

    BigInt n_product = x * y * x2 * y2;

    BigInt M1 = BigIntOps::ComputeMi(n_product, x,  y );
    BigInt M2 = BigIntOps::ComputeMi(n_product, x2, y2);

    ASSERT_EQ(M1 * x  * y,  n_product);
    ASSERT_EQ(M2 * x2 * y2, n_product);

    BigInt N1 = BigIntOps::ComputeNi(M1, x,  y );
    BigInt N2 = BigIntOps::ComputeNi(M2, x2, y2);

    ASSERT_TRUE(N1 >= 0);
    ASSERT_TRUE(N2 >= 0);

    std::cout << "  M1 = " << M1 << "\n";
    std::cout << "  N1 = " << N1 << "\n";

    return true;
}

// ===========================================================================
// Test 7: Serialisation round-trips
// ===========================================================================
bool test_serialisation() {
    BigInt n = B("123456789012345678901234567890987654321");

    // Dec string round-trip
    std::string dec = BigIntOps::ToDecString(n);
    ASSERT_EQ(dec, std::string("123456789012345678901234567890987654321"));
    ASSERT_EQ(BigIntOps::FromDecString(dec), n);

    // Hex string round-trip
    std::string hex = BigIntOps::ToHexString(n);
    ASSERT_TRUE(!hex.empty());
    BigInt n2 = BigIntOps::FromHexString(hex);
    ASSERT_EQ(n, n2);

    // Hex with 0x prefix
    BigInt n3 = BigIntOps::FromHexString("0xDEADBEEF");
    ASSERT_EQ(n3, BigInt(0xDEADBEEFUL));

    // Byte buffer round-trip (32-byte AES key sized)
    BigInt key_val = B("0xCAFEBABEDEADBEEF0011223344556677"
                       "8899AABBCCDDEEFF0102030405060708");
    utils::ByteBuffer buf = BigIntOps::ToBytes(key_val, 32);
    ASSERT_EQ(buf.size(), 32u);
    BigInt key_back = BigIntOps::FromBytes(buf);
    ASSERT_EQ(key_val, key_back);

    // ToBytes overflow detection
    BigInt huge = BigInt(1) << 300;  // 300-bit number
    ASSERT_THROWS(BigIntOps::ToBytes(huge, 32));

    // FromDecString error
    ASSERT_THROWS(BigIntOps::FromDecString(""));
    ASSERT_THROWS(BigIntOps::FromDecString("not_a_number_xyz"));

    std::cout << "  Dec: " << dec.substr(0, 20) << "...\n";
    std::cout << "  Hex: " << hex.substr(0, 20) << "...\n";

    return true;
}

// ===========================================================================
// Test 8: Full MKeyGen skeleton (Algorithm 1, N=2 slaves)
// ===========================================================================
bool test_mkeyge_skeleton() {
    // Algorithm 1 with N=2 for speed
    // Inputs: safe primes p_1,q_1,p_2,q_2
    // Output: master key e_M and 2 slave key pairs

    const int N = 2;
    BigIntVec p_primes = BigIntOps::GenerateSafePrimes(N, 8, g_rng);
    BigIntVec q_primes = BigIntOps::GenerateSafePrimes(N, 8, g_rng);

    // Step 1: compute x_i, y_i, e_i, d_i for each slave
    BigIntVec x_vec, y_vec, e_vec, d_vec;
    for (int i = 0; i < N; ++i) {
        BigInt xi = BigIntOps::ComputeX(p_primes[i]);
        BigInt yi = BigIntOps::ComputeY(q_primes[i]);
        BigInt ei = BigIntOps::GenerateEi(g_rng);
        BigInt di = BigIntOps::ComputeDi(ei, xi, yi);
        x_vec.push_back(xi);
        y_vec.push_back(yi);
        e_vec.push_back(ei);
        d_vec.push_back(di);
    }

    // Step 3-4: compute product n = ∏(x_i * y_i)
    BigInt n_product = 1;
    for (int i = 0; i < N; ++i) {
        n_product *= (x_vec[i] * y_vec[i]);
    }

    // Step 5: compute M[i] and N[i]
    BigIntVec M_vec, Nv_vec;
    for (int i = 0; i < N; ++i) {
        BigInt Mi = BigIntOps::ComputeMi(n_product, x_vec[i], y_vec[i]);
        BigInt Ni = BigIntOps::ComputeNi(Mi, x_vec[i], y_vec[i]);
        M_vec.push_back(Mi);
        Nv_vec.push_back(Ni);
    }

    // Step 6-7: compute e_M = sum(e_i * M[i] * N[i])
    BigInt e_M = 0;
    for (int i = 0; i < N; ++i) {
        e_M += e_vec[i] * M_vec[i] * Nv_vec[i];
    }

    ASSERT_TRUE(e_M > 0);
    std::cout << "  N=" << N << " slave MKeyGen completed\n";
    std::cout << "  e_M (first 40 digits): "
              << BigIntOps::ToDecString(e_M).substr(0, 40) << "...\n";

    // Verify each slave can "decrypt": e_M ≡ e_i (mod x_i*y_i)
    for (int i = 0; i < N; ++i) {
        BigInt xi_yi  = x_vec[i] * y_vec[i];
        BigInt e_M_mod = BigIntOps::Mod(e_M, xi_yi);
        ASSERT_EQ(e_M_mod, BigIntOps::Mod(e_vec[i], xi_yi));
    }
    std::cout << "  CRT selective decryption property VERIFIED\n";

    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 7 — Boost Multiprecision Integration\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_bigint_test_logs",
        log::LogLevel::WARN,
        false);

    RunTest("basic_arithmetic",      test_basic_arithmetic);
    RunTest("modular_arithmetic",    test_modular_arithmetic);
    RunTest("crt",                   test_crt);
    RunTest("primality",             test_primality);
    RunTest("safe_prime_generation", test_safe_prime_generation);
    RunTest("mkemgkm_helpers",       test_mkemgkm_helpers);
    RunTest("serialisation",         test_serialisation);
    RunTest("mkeygen_skeleton",      test_mkeyge_skeleton);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}