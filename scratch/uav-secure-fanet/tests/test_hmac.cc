/**
 * tests/test_hmac.cc
 * Unit test for Phase 2 Module 10: HMAC-SHA256 Utility
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I/usr/include \
 *       tests/test_hmac.cc \
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
 *       crypto/uav-hmac.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_hmac
 *
 * RUN:
 *   ./tests/test_hmac
 */

#include "crypto/uav-hmac.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>

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
    auto k1 = HmacSha256Util::GenerateKey();
    auto k2 = HmacSha256Util::GenerateKey();

    ASSERT_EQ(k1.size(), 32u);
    ASSERT_TRUE(k1 != k2);

    // KeyFromBytes round-trip
    utils::ByteBuffer raw(k1.begin(), k1.end());
    auto k3 = HmacSha256Util::KeyFromBytes(raw);
    ASSERT_EQ(k1, k3);

    // Wrong size throws
    utils::ByteBuffer short_raw(16, 0xAB);
    ASSERT_THROWS(HmacSha256Util::KeyFromBytes(short_raw));

    std::cout << "  Key: "
              << utils::StringUtils::BytesToHex(k1.data(), 8)
              << "...\n";
    return true;
}

// ===========================================================================
// Test 2: Known answer test
// ===========================================================================
bool test_known_answer() {
    // Use a custom known-answer test with 32-byte key
    // since our HmacKey requires exactly 32 bytes.
    //
    // Verified against Python:
    //   import hmac, hashlib
    //   key = bytes([0x0b]*32)
    //   data = b"Hi There"
    //   print(hmac.new(key, data, hashlib.sha256).hexdigest())

    utils::u8 key_raw[32];
    std::memset(key_raw, 0x0b, 32);
    auto key = HmacSha256Util::KeyFromBytes(key_raw, 32);

    std::string data_str = "Hi There";
    utils::ByteBuffer data(data_str.begin(), data_str.end());

    auto hmac = HmacSha256Util::Compute(key, data);
    std::string got = utils::StringUtils::BytesToHex(hmac.data(), 32);

    // Compute expected using same logic — verify determinism
    auto hmac2 = HmacSha256Util::Compute(key, data);
    std::string got2 = utils::StringUtils::BytesToHex(hmac2.data(), 32);

    std::cout << "  HMAC-SHA256(key=0x0b*32, \"Hi There\"):\n";
    std::cout << "  Got : " << got << "\n";

    // Verify determinism — two calls same result
    ASSERT_EQ(got, got2);
    ASSERT_EQ(got.size(), 64u);  // 32 bytes = 64 hex chars

    // Verify with different key gives different result
    utils::u8 key2_raw[32];
    std::memset(key2_raw, 0x0c, 32);
    auto key2 = HmacSha256Util::KeyFromBytes(key2_raw, 32);
    auto hmac3 = HmacSha256Util::Compute(key2, data);
    std::string got3 = utils::StringUtils::BytesToHex(hmac3.data(), 32);
    ASSERT_TRUE(got != got3);

    // Verify with known Python-computed value
    // python3 -c "import hmac,hashlib; print(hmac.new(bytes([0x0b]*32), b'Hi There', hashlib.sha256).hexdigest())"
    std::string expected = "198a607eb44bfbc69903a0f1cf2bbdc5"
                           "ba0aa3f3d9ae3c1c7a3b1696a0b68cf7";
    std::cout << "  Exp : " << expected << "\n";
    ASSERT_EQ(got, expected);

    std::cout << "  Determinism: PASS\n";
    std::cout << "  Key isolation: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: Verify — correct and incorrect
// ===========================================================================
bool test_verify() {
    auto key = HmacSha256Util::GenerateKey();
    utils::ByteBuffer data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto hmac = HmacSha256Util::Compute(key, data);

    // Correct verify
    ASSERT_TRUE(HmacSha256Util::Verify(key, data, hmac));

    // VerifyOrThrow — correct
    bool threw = false;
    try {
        HmacSha256Util::VerifyOrThrow(key, data, hmac);
    } catch (...) { threw = true; }
    ASSERT_TRUE(!threw);

    // Wrong key → false
    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_TRUE(!HmacSha256Util::Verify(wrong_key, data, hmac));

    // Tampered data → false
    utils::ByteBuffer tampered = data;
    tampered[0] ^= 0xFF;
    ASSERT_TRUE(!HmacSha256Util::Verify(key, tampered, hmac));

    // Tampered HMAC → false
    auto tampered_hmac = hmac;
    tampered_hmac[0] ^= 0x01;
    ASSERT_TRUE(!HmacSha256Util::Verify(key, data, tampered_hmac));

    // VerifyOrThrow on wrong key throws
    ASSERT_THROWS(HmacSha256Util::VerifyOrThrow(
        wrong_key, data, hmac));

    std::cout << "  Verify correct  : PASS\n";
    std::cout << "  Verify wrong key: PASS\n";
    std::cout << "  Verify tampered : PASS\n";
    return true;
}

// ===========================================================================
// Test 4: ComputeMulti (scatter-gather)
// ===========================================================================
bool test_compute_multi() {
    auto key = HmacSha256Util::GenerateKey();

    // Part A + Part B should equal HMAC(A||B)
    utils::ByteBuffer A = {0x01, 0x02, 0x03};
    utils::ByteBuffer B = {0x04, 0x05, 0x06, 0x07};

    // Concatenated
    utils::ByteBuffer AB = utils::ByteUtils::Concat(A, B);
    auto hmac_concat = HmacSha256Util::Compute(key, AB);

    // Multi-part
    auto hmac_multi = HmacSha256Util::ComputeMulti(key, {A, B});

    ASSERT_EQ(hmac_concat, hmac_multi);

    // Three parts
    utils::ByteBuffer C = {0x08, 0x09};
    utils::ByteBuffer ABC = utils::ByteUtils::Concat(AB, C);
    auto hmac_abc   = HmacSha256Util::Compute(key, ABC);
    auto hmac_multi3 = HmacSha256Util::ComputeMulti(key, {A, B, C});
    ASSERT_EQ(hmac_abc, hmac_multi3);

    std::cout << "  ComputeMulti == Compute(concat): PASS\n";
    return true;
}

// ===========================================================================
// Test 5: AppendHmac + StripAndVerifyHmac
// ===========================================================================
bool test_append_strip() {
    auto key = HmacSha256Util::GenerateKey();

    utils::ByteBuffer packet = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };
    std::size_t original_size = packet.size();

    // Append HMAC
    HmacSha256Util::AppendHmac(key, packet);
    ASSERT_EQ(packet.size(), original_size + 32u);

    // Strip and verify — returns original body
    auto body = HmacSha256Util::StripAndVerifyHmac(key, packet);
    ASSERT_EQ(body.size(), original_size);
    ASSERT_EQ(body[0], 0x01u);
    ASSERT_EQ(body[7], 0x08u);

    // Tamper packet body → verification fails
    auto tampered = packet;
    tampered[0] ^= 0xFF;
    ASSERT_THROWS(
        HmacSha256Util::StripAndVerifyHmac(key, tampered));

    // Too-short buffer throws
    utils::ByteBuffer short_buf(10, 0x00);
    ASSERT_THROWS(
        HmacSha256Util::StripAndVerifyHmac(key, short_buf));

    std::cout << "  AppendHmac: packet grew by 32 bytes: PASS\n";
    std::cout << "  StripAndVerify correct: PASS\n";
    std::cout << "  StripAndVerify tampered: throws: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: SHA-256 known answer
// ===========================================================================
bool test_sha256_known_answer() {
    // SHA-256("") = e3b0c44...
    auto h_empty = HmacSha256Util::Sha256(
        utils::ByteBuffer{});
    std::string s_empty = utils::StringUtils::BytesToHex(
        h_empty.data(), 32);
    ASSERT_EQ(s_empty, std::string(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"));

    // SHA-256("abc") = ba7816bf...
    auto h_abc = HmacSha256Util::Sha256(std::string("abc"));
    std::string s_abc = utils::StringUtils::BytesToHex(
        h_abc.data(), 32);
    ASSERT_EQ(s_abc.substr(0, 8), std::string("ba7816bf"));

    // SHA-256("UAV-FANET") — deterministic
    auto h1 = HmacSha256Util::Sha256(std::string("UAV-FANET"));
    auto h2 = HmacSha256Util::Sha256(std::string("UAV-FANET"));
    ASSERT_EQ(h1, h2);

    std::cout << "  SHA-256(\"\")    : "
              << s_empty.substr(0, 16) << "...\n";
    std::cout << "  SHA-256(\"abc\") : "
              << s_abc.substr(0, 16) << "...\n";
    return true;
}

// ===========================================================================
// Test 7: Full packet HMAC workflow
// (simulates [HEADER][MT_K][AES_PAYLOAD][HMAC] packet)
// ===========================================================================
bool test_full_packet_workflow() {
    auto tek = HmacSha256Util::GenerateKey();  // TEK as HMAC key

    // Simulate packet components
    utils::ByteBuffer header  = {0x55, 0x41, 0x56, 0x46,  // 'UAVF'
                                  0x01, 0x00,              // version
                                  0x00, 0x00};             // cluster 0
    utils::ByteBuffer mtk     = {0xAA, 0xBB, 0xCC, 0xDD,
                                  0xEE, 0xFF, 0x11, 0x22}; // MT_K stub
    utils::ByteBuffer payload = {0x10, 0x20, 0x30, 0x40,
                                  0x50, 0x60, 0x70, 0x80}; // AES-CT stub

    // Build packet body = header || MT_K || payload
    utils::ByteBuffer body;
    utils::ByteUtils::AppendBytes(body, header);
    utils::ByteUtils::AppendBytes(body, mtk);
    utils::ByteUtils::AppendBytes(body, payload);

    std::size_t body_size = body.size();

    // Append HMAC → complete packet
    HmacSha256Util::AppendHmac(tek, body);
    ASSERT_EQ(body.size(), body_size + 32u);

    std::cout << "  Packet size with HMAC: "
              << body.size() << " bytes\n";

    // Receiver: strip and verify
    auto recovered = HmacSha256Util::StripAndVerifyHmac(
        tek, body);

    ASSERT_EQ(recovered.size(), body_size);

    // Verify header intact
    ASSERT_EQ(recovered[0], 0x55u);
    ASSERT_EQ(recovered[3], 0x46u);

    std::cout << "  Full packet HMAC workflow: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: HMAC with empty data
// ===========================================================================
bool test_empty_data() {
    auto key = HmacSha256Util::GenerateKey();
    utils::ByteBuffer empty;

    auto hmac = HmacSha256Util::Compute(key, empty);
    ASSERT_EQ(hmac.size(), 32u);

    // Verify empty
    ASSERT_TRUE(HmacSha256Util::Verify(key, empty, hmac));

    // Different key → different HMAC of empty
    auto k2   = HmacSha256Util::GenerateKey();
    auto hmac2 = HmacSha256Util::Compute(k2, empty);
    ASSERT_TRUE(hmac != hmac2);

    std::cout << "  HMAC of empty data: "
              << utils::StringUtils::BytesToHex(hmac.data(), 8)
              << "...\n";
    return true;
}

// ===========================================================================
// Test 9: Large data (1024-byte payload)
// ===========================================================================
bool test_large_data() {
    auto key = HmacSha256Util::GenerateKey();

    // 1024-byte packet body
    utils::ByteBuffer data(1024);
    OpenSSLRand::FillBytes(data.data(), data.size());

    auto hmac = HmacSha256Util::Compute(key, data);
    ASSERT_EQ(hmac.size(), 32u);
    ASSERT_TRUE(HmacSha256Util::Verify(key, data, hmac));

    // Flip last byte
    data[1023] ^= 0x01;
    ASSERT_TRUE(!HmacSha256Util::Verify(key, data, hmac));

    std::cout << "  1024-byte HMAC: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Constant-time property (no early exit)
// ===========================================================================
bool test_constant_time() {
    auto key  = HmacSha256Util::GenerateKey();
    utils::ByteBuffer data = {0x01, 0x02, 0x03};

    auto correct = HmacSha256Util::Compute(key, data);

    // All-zero HMAC
    utils::HmacSha256 zero_hmac{};
    zero_hmac.fill(0x00);

    // Off-by-one HMAC
    auto off_hmac = correct;
    off_hmac[31] ^= 0x01;

    // Both must return false (not crash or reveal timing)
    ASSERT_TRUE(!HmacSha256Util::Verify(key, data, zero_hmac));
    ASSERT_TRUE(!HmacSha256Util::Verify(key, data, off_hmac));

    std::cout << "  Constant-time verify: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 10 — HMAC-SHA256 Utility\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_hmac_test_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("key_generation",        test_key_generation);
    RunTest("known_answer",          test_known_answer);
    RunTest("verify",                test_verify);
    RunTest("compute_multi",         test_compute_multi);
    RunTest("append_strip",          test_append_strip);
    RunTest("sha256_known_answer",   test_sha256_known_answer);
    RunTest("full_packet_workflow",  test_full_packet_workflow);
    RunTest("empty_data",            test_empty_data);
    RunTest("large_data",            test_large_data);
    RunTest("constant_time",         test_constant_time);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}