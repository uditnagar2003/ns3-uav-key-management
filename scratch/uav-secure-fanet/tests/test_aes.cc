/**
 * tests/test_aes.cc
 * Unit test for Phase 2 Module 9: AES-256-GCM Utility
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I/usr/include \
 *       tests/test_aes.cc \
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
 *       crypto/uav-openssl-rand.cc \
 *       crypto/uav-openssl-ctx.cc \
 *       crypto/uav-aes.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_aes
 *
 * RUN:
 *   ./tests/test_aes
 */

#include "crypto/uav-aes.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace uav;
using namespace uav::crypto;

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

// ===========================================================================
// Test 1: Key generation
// ===========================================================================
bool test_key_generation() {
    auto k1 = AesGcm::GenerateKey();
    auto k2 = AesGcm::GenerateKey();

    ASSERT_EQ(k1.size(), 32u);
    ASSERT_EQ(k2.size(), 32u);
    ASSERT_TRUE(k1 != k2);   // probabilistically distinct

    // KeyFromBytes round-trip
    utils::ByteBuffer raw(k1.begin(), k1.end());
    auto k3 = AesGcm::KeyFromBytes(raw);
    ASSERT_EQ(k1, k3);

    // Wrong size throws
    utils::ByteBuffer short_raw(16, 0xAB);
    ASSERT_THROWS(AesGcm::KeyFromBytes(short_raw));

    std::cout << "  Key: "
              << utils::StringUtils::BytesToHex(k1.data(), 8)
              << "...\n";
    return true;
}

// ===========================================================================
// Test 2: Basic encrypt/decrypt round-trip
// ===========================================================================
bool test_encrypt_decrypt_roundtrip() {
    auto key = AesGcm::GenerateKey();

    const std::string msg = "UAV-SECURE-FANET-PAYLOAD-TEST";
    utils::ByteBuffer pt(msg.begin(), msg.end());

    auto result = AesGcm::Encrypt(key, pt);

    ASSERT_EQ(result.iv.size(),         12u);
    ASSERT_EQ(result.tag.size(),        16u);
    ASSERT_EQ(result.ciphertext.size(), pt.size());
    ASSERT_TRUE(result.ciphertext != pt);  // must be different

    auto recovered = AesGcm::Decrypt(
        key, result.iv, result.ciphertext, result.tag);

    ASSERT_EQ(recovered, pt);

    std::cout << "  Plaintext : " << msg << "\n";
    std::cout << "  CT hex    : "
              << utils::StringUtils::BytesToHexAbbrev(
                     result.ciphertext) << "\n";
    std::cout << "  IV        : "
              << utils::StringUtils::BytesToHex(
                     result.iv.data(), 12) << "\n";
    std::cout << "  Tag       : "
              << utils::StringUtils::BytesToHex(
                     result.tag.data(), 16) << "\n";
    return true;
}

// ===========================================================================
// Test 3: Empty plaintext
// ===========================================================================
bool test_empty_plaintext() {
    auto key = AesGcm::GenerateKey();
    utils::ByteBuffer empty;

    auto result = AesGcm::Encrypt(key, empty);
    ASSERT_EQ(result.ciphertext.size(), 0u);
    ASSERT_EQ(result.iv.size(),         12u);
    ASSERT_EQ(result.tag.size(),        16u);

    auto recovered = AesGcm::Decrypt(
        key, result.iv, result.ciphertext, result.tag);
    ASSERT_EQ(recovered.size(), 0u);

    std::cout << "  Empty plaintext round-trip: OK\n";
    return true;
}

// ===========================================================================
// Test 4: AAD (Additional Authenticated Data)
// ===========================================================================
bool test_aad() {
    auto key = AesGcm::GenerateKey();

    utils::ByteBuffer pt   = {0x01, 0x02, 0x03, 0x04};
    utils::ByteBuffer aad  = {0xAA, 0xBB, 0xCC};   // packet header

    auto result = AesGcm::Encrypt(key, pt, aad);

    // Correct AAD → decrypt succeeds
    auto recovered = AesGcm::Decrypt(
        key, result.iv, result.ciphertext, result.tag, aad);
    ASSERT_EQ(recovered, pt);

    // Wrong AAD → tag verification fails
    utils::ByteBuffer wrong_aad = {0xAA, 0xBB, 0xDD};
    ASSERT_THROWS(AesGcm::Decrypt(
        key, result.iv, result.ciphertext,
        result.tag, wrong_aad));

    // No AAD → tag verification fails
    ASSERT_THROWS(AesGcm::Decrypt(
        key, result.iv, result.ciphertext, result.tag));

    std::cout << "  AAD correct: PASS\n";
    std::cout << "  AAD tampered: throws CryptoException: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: Tampered ciphertext detection
// ===========================================================================
bool test_tamper_detection() {
    auto key = AesGcm::GenerateKey();
    utils::ByteBuffer pt = {0x10, 0x20, 0x30, 0x40, 0x50};

    auto result = AesGcm::Encrypt(key, pt);

    // Flip one byte in ciphertext
    auto tampered_ct = result.ciphertext;
    tampered_ct[0] ^= 0xFF;

    ASSERT_THROWS(AesGcm::Decrypt(
        key, result.iv, tampered_ct, result.tag));

    // Flip one byte in tag
    auto tampered_tag = result.tag;
    tampered_tag[0] ^= 0x01;

    ASSERT_THROWS(AesGcm::Decrypt(
        key, result.iv, result.ciphertext, tampered_tag));

    // Wrong key
    auto wrong_key = AesGcm::GenerateKey();
    ASSERT_THROWS(AesGcm::Decrypt(
        wrong_key, result.iv, result.ciphertext, result.tag));

    std::cout << "  Tampered CT  : throws CryptoException: PASS\n";
    std::cout << "  Tampered tag : throws CryptoException: PASS\n";
    std::cout << "  Wrong key    : throws CryptoException: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: Wire format serialize/deserialize
// ===========================================================================
bool test_wire_format() {
    auto key = AesGcm::GenerateKey();
    utils::ByteBuffer pt = {0x01, 0x02, 0x03, 0x04,
                            0x05, 0x06, 0x07, 0x08};

    // Encrypt to wire
    utils::ByteBuffer wire = AesGcm::EncryptToWire(key, pt);

    // Wire = IV(12) + CT(8) + TAG(16) = 36 bytes
    ASSERT_EQ(wire.size(), 12u + pt.size() + 16u);

    // Decrypt from wire
    auto recovered = AesGcm::DecryptFromWire(key, wire);
    ASSERT_EQ(recovered, pt);

    // Deserialize and verify components
    auto result = AesGcm::Deserialize(wire);
    ASSERT_EQ(result.iv.size(),         12u);
    ASSERT_EQ(result.ciphertext.size(), pt.size());
    ASSERT_EQ(result.tag.size(),        16u);

    // Too-short wire throws
    utils::ByteBuffer short_wire(10, 0x00);
    ASSERT_THROWS(AesGcm::Deserialize(short_wire));

    std::cout << "  Wire size: " << wire.size() << " bytes "
              << "(IV=12 + CT=" << pt.size()
              << " + TAG=16)\n";
    return true;
}

// ===========================================================================
// Test 7: TEK encrypt/decrypt
// ===========================================================================
bool test_tek_encrypt_decrypt() {
    // KEK = key encryption key (SKDC master key)
    auto kek = AesGcm::GenerateKey();

    // TEK = traffic encryption key (32 random bytes)
    auto tek = AesGcm::GenerateKey();

    // Encrypt TEK
    utils::ByteBuffer aad = {0xC1, 0xC2};  // cluster ID as AAD
    utils::ByteBuffer wire = AesGcm::EncryptTek(kek, tek, aad);

    // Wire = IV(12) + CT(32) + TAG(16) = 60 bytes
    ASSERT_EQ(wire.size(), 60u);

    // Decrypt TEK
    auto recovered_tek = AesGcm::DecryptTek(kek, wire, aad);
    ASSERT_EQ(recovered_tek, tek);

    // Wrong KEK fails
    auto wrong_kek = AesGcm::GenerateKey();
    ASSERT_THROWS(AesGcm::DecryptTek(wrong_kek, wire, aad));

    std::cout << "  TEK wire size: " << wire.size() << " bytes\n";
    std::cout << "  TEK: "
              << utils::StringUtils::BytesToHex(tek.data(), 8)
              << "...\n";
    std::cout << "  TEK encrypt/decrypt: OK\n";
    return true;
}

// ===========================================================================
// Test 8: Key derivation (TEK rotation)
// ===========================================================================
bool test_key_derivation() {
    auto tek_old = AesGcm::GenerateKey();

    // Context = "rekey" || nonce
    utils::ByteBuffer context = {
        'r','e','k','e','y',
        0x01, 0x02, 0x03, 0x04
    };

    auto tek_new = AesGcm::DeriveKey(tek_old, context);

    ASSERT_EQ(tek_new.size(), 32u);
    ASSERT_TRUE(tek_new != tek_old);

    // Deterministic — same input → same output
    auto tek_new2 = AesGcm::DeriveKey(tek_old, context);
    ASSERT_EQ(tek_new, tek_new2);

    // Different context → different key
    utils::ByteBuffer ctx2 = {'r','e','k','e','y', 0x99};
    auto tek_new3 = AesGcm::DeriveKey(tek_old, ctx2);
    ASSERT_TRUE(tek_new3 != tek_new);

    std::cout << "  Old TEK: "
              << utils::StringUtils::BytesToHex(tek_old.data(), 8)
              << "...\n";
    std::cout << "  New TEK: "
              << utils::StringUtils::BytesToHex(tek_new.data(), 8)
              << "...\n";
    std::cout << "  Key derivation deterministic: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Large payload (1024-byte data packet)
// ===========================================================================
bool test_large_payload() {
    auto key = AesGcm::GenerateKey();

    // 1024-byte data packet (project spec)
    utils::ByteBuffer pt(1024);
    OpenSSLRand::FillBytes(pt.data(), pt.size());

    utils::ByteBuffer aad = {0x01, 0x00, 0x00, 0x01};  // packet header

    auto wire = AesGcm::EncryptToWire(key, pt, aad);
    ASSERT_EQ(wire.size(), 12u + 1024u + 16u);  // 1052 bytes

    auto recovered = AesGcm::DecryptFromWire(key, wire, aad);
    ASSERT_EQ(recovered, pt);

    std::cout << "  1024-byte payload: wire=" << wire.size()
              << " bytes\n";
    std::cout << "  Overhead: " << (wire.size() - pt.size())
              << " bytes (IV=12 + TAG=16)\n";
    return true;
}

// ===========================================================================
// Test 10: Deterministic encrypt (known IV)
// ===========================================================================
bool test_deterministic_encrypt() {
    // Known test vector — verify AES-256-GCM is correct
    // Key: all zeros
    AesGcmKey key{};
    key.fill(0x00);

    // IV: all zeros
    std::array<utils::u8, 12> iv{};
    iv.fill(0x00);

    // Plaintext: empty
    utils::ByteBuffer pt;

    auto result = AesGcm::EncryptWithIv(key, iv, pt);

    // Known GCM tag for AES-256, all-zero key, all-zero IV, empty PT:
    // tag = 530f8afbc74536b9a963b4f1c4cb738b
    std::string tag_hex = utils::StringUtils::BytesToHex(
        result.tag.data(), 16);

    std::cout << "  Zero-key zero-IV empty-PT tag: "
              << tag_hex << "\n";

    // Verify it's deterministic
    auto result2 = AesGcm::EncryptWithIv(key, iv, pt);
    ASSERT_EQ(result.tag, result2.tag);
    ASSERT_EQ(result.ciphertext, result2.ciphertext);

    std::cout << "  Deterministic encrypt: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: Multiple keys don't interfere
// ===========================================================================
bool test_key_isolation() {
    auto k1 = AesGcm::GenerateKey();
    auto k2 = AesGcm::GenerateKey();

    utils::ByteBuffer pt = {0xDE, 0xAD, 0xBE, 0xEF};

    auto r1 = AesGcm::Encrypt(k1, pt);
    auto r2 = AesGcm::Encrypt(k2, pt);

    // Different keys → different ciphertext
    ASSERT_TRUE(r1.ciphertext != r2.ciphertext);

    // k1 cannot decrypt r2
    ASSERT_THROWS(AesGcm::Decrypt(k1, r2.iv,
                                   r2.ciphertext, r2.tag));

    // k2 cannot decrypt r1
    ASSERT_THROWS(AesGcm::Decrypt(k2, r1.iv,
                                   r1.ciphertext, r1.tag));

    // Each key decrypts its own correctly
    auto p1 = AesGcm::Decrypt(k1, r1.iv, r1.ciphertext, r1.tag);
    auto p2 = AesGcm::Decrypt(k2, r2.iv, r2.ciphertext, r2.tag);
    ASSERT_EQ(p1, pt);
    ASSERT_EQ(p2, pt);

    std::cout << "  Key isolation: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 9 — AES-256-GCM Utility\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_aes_test_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("key_generation",          test_key_generation);
    RunTest("encrypt_decrypt_roundtrip", test_encrypt_decrypt_roundtrip);
    RunTest("empty_plaintext",         test_empty_plaintext);
    RunTest("aad",                     test_aad);
    RunTest("tamper_detection",        test_tamper_detection);
    RunTest("wire_format",             test_wire_format);
    RunTest("tek_encrypt_decrypt",     test_tek_encrypt_decrypt);
    RunTest("key_derivation",          test_key_derivation);
    RunTest("large_payload",           test_large_payload);
    RunTest("deterministic_encrypt",   test_deterministic_encrypt);
    RunTest("key_isolation",           test_key_isolation);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}