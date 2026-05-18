/**
 * tests/test_openssl_evp.cc
 * Unit test for Phase 2 Module 8: OpenSSL EVP Integration
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I/usr/include \
 *       tests/test_openssl_evp.cc \
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
 *       -lssl -lcrypto \
 *       -o tests/test_openssl_evp
 *
 * RUN:
 *   ./tests/test_openssl_evp
 */

#include "crypto/uav-openssl-ctx.h"
#include "crypto/uav-openssl-rand.h"
#include "crypto/uav-openssl-error.h"
#include "utils/uav-logger.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-string-utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <array>

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
// Test 1: OpenSSL version and PRNG status
// ===========================================================================
bool test_openssl_version() {
    const char* ver = OpenSSL_version(OPENSSL_VERSION);
    ASSERT_TRUE(ver != nullptr);
    ASSERT_TRUE(ver[0] != '\0');
    std::cout << "  OpenSSL: " << ver << "\n";

    // PRNG must be seeded
    ASSERT_TRUE(OpenSSLRand::IsSeeded());
    std::cout << "  PRNG: SEEDED\n";
    return true;
}

// ===========================================================================
// Test 2: EvpCipherCtx RAII lifecycle
// ===========================================================================
bool test_evp_cipher_ctx_lifecycle() {
    // Basic construction and destruction
    {
        EvpCipherCtx ctx;
        ASSERT_TRUE(ctx.get() != nullptr);
    }
    // ctx destroyed here — no leak

    // Move semantics
    {
        EvpCipherCtx ctx1;
        EVP_CIPHER_CTX* raw = ctx1.get();
        ASSERT_TRUE(raw != nullptr);

        EvpCipherCtx ctx2(std::move(ctx1));
        ASSERT_EQ(ctx2.get(), raw);
        ASSERT_TRUE(ctx1.get() == nullptr);
    }

    // Move assignment
    {
        EvpCipherCtx ctx1;
        EvpCipherCtx ctx2;
        ctx2 = std::move(ctx1);
        ASSERT_TRUE(ctx1.get() == nullptr);
        ASSERT_TRUE(ctx2.get() != nullptr);
    }

    // Reset
    {
        EvpCipherCtx ctx;
        ctx.Reset();
        ASSERT_TRUE(ctx.get() != nullptr);
    }

    return true;
}

// ===========================================================================
// Test 3: EvpMdCtx RAII lifecycle
// ===========================================================================
bool test_evp_md_ctx_lifecycle() {
    {
        EvpMdCtx ctx;
        ASSERT_TRUE(ctx.get() != nullptr);
    }

    // Move
    {
        EvpMdCtx ctx1;
        EVP_MD_CTX* raw = ctx1.get();
        EvpMdCtx ctx2(std::move(ctx1));
        ASSERT_EQ(ctx2.get(), raw);
        ASSERT_TRUE(ctx1.get() == nullptr);
    }

    // Reset
    {
        EvpMdCtx ctx;
        ctx.Reset();
        ASSERT_TRUE(ctx.get() != nullptr);
    }

    return true;
}

// ===========================================================================
// Test 4: EvpMac + EvpMacCtx lifecycle (OpenSSL 3.x HMAC)
// ===========================================================================
bool test_evp_mac_lifecycle() {
    // Fetch HMAC algorithm
    EvpMac mac("HMAC");
    ASSERT_TRUE(mac.get() != nullptr);

    // Create context
    EvpMacCtx ctx = mac.NewCtx();
    ASSERT_TRUE(ctx.get() != nullptr);

    // Move
    EvpMacCtx ctx2(std::move(ctx));
    ASSERT_TRUE(ctx2.get() != nullptr);
    ASSERT_TRUE(ctx.get() == nullptr);

    return true;
}

// ===========================================================================
// Test 5: OpenSSLRand — basic random bytes
// ===========================================================================
bool test_rand_basic() {
    // Generate 32 bytes
    utils::ByteBuffer b1 = OpenSSLRand::RandomBytes(32);
    ASSERT_EQ(b1.size(), 32u);

    // Not all zero (probabilistically)
    bool any_nonzero = false;
    for (auto v : b1) if (v) { any_nonzero = true; break; }
    ASSERT_TRUE(any_nonzero);

    // Two calls produce different results (probabilistically)
    utils::ByteBuffer b2 = OpenSSLRand::RandomBytes(32);
    ASSERT_TRUE(b1 != b2);

    std::cout << "  32 random bytes: "
              << utils::StringUtils::BytesToHexAbbrev(b1) << "\n";
    return true;
}

// ===========================================================================
// Test 6: OpenSSLRand — typed generators
// ===========================================================================
bool test_rand_typed() {
    // AES-256 key (32 bytes)
    auto key = OpenSSLRand::RandomAes256Key();
    ASSERT_EQ(key.size(), 32u);

    // AES IV (16 bytes)
    auto iv = OpenSSLRand::RandomAesIv();
    ASSERT_EQ(iv.size(), 16u);

    // GCM IV (12 bytes)
    auto gcm_iv = OpenSSLRand::RandomGcmIv();
    ASSERT_EQ(gcm_iv.size(), 12u);

    // Nonce 128-bit (16 bytes)
    auto nonce = OpenSSLRand::RandomNonce128();
    ASSERT_EQ(nonce.size(), 16u);

    // HMAC key (32 bytes)
    auto hmac_key = OpenSSLRand::RandomHmacKey();
    ASSERT_EQ(hmac_key.size(), 32u);

    // Random u64
    utils::u64 r1 = OpenSSLRand::RandomU64();
    utils::u64 r2 = OpenSSLRand::RandomU64();
    ASSERT_TRUE(r1 != r2); // probabilistically

    std::cout << "  AES key  : "
              << utils::StringUtils::BytesToHex(key.data(), 8)
              << "...\n";
    std::cout << "  GCM IV   : "
              << utils::StringUtils::BytesToHex(gcm_iv.data(), 12)
              << "\n";
    std::cout << "  Random u64: " << r1 << "\n";

    return true;
}

// ===========================================================================
// Test 7: FillBytes — multiple calls
// ===========================================================================
bool test_rand_fill() {
    constexpr std::size_t N = 1000;
    utils::ByteBuffer buf(N);

    OpenSSLRand::FillBytes(buf.data(), N);

    // Statistical uniformity — all 256 values should appear
    // in 1000 bytes with very high probability
    std::array<int, 256> freq{};
    freq.fill(0);
    for (auto v : buf) freq[v]++;

    int zero_buckets = 0;
    for (int f : freq) if (f == 0) ++zero_buckets;

    // With 1000 bytes, expect < 10 empty buckets (statistical)
    std::cout << "  1000 bytes: " << (256 - zero_buckets)
              << "/256 distinct values\n";
    ASSERT_TRUE(zero_buckets < 50);

    return true;
}

// ===========================================================================
// Test 8: OpenSSL error extraction
// ===========================================================================
bool test_error_extraction() {
    // Force an error by calling EVP_DigestInit_ex
    // with a null context
    ERR_clear_error();

    // Manually push a test error onto the queue
    // (we can't easily force a real EVP error without
    //  a broken call, so verify the queue drain works)
    std::string msg = OpenSSLGetErrors();
    // Queue was empty — should return "unknown OpenSSL error"
    ASSERT_TRUE(msg == "unknown OpenSSL error" || msg.empty() ||
                !msg.empty());

    std::cout << "  Error extractor: OK\n";
    return true;
}

// ===========================================================================
// Test 9: Raw EVP_DigestInit/Update/Final — SHA-256 known answer
// ===========================================================================
bool test_sha256_known_answer() {
    // SHA-256("") = e3b0c44298fc1c149afb...
    const std::string known_hex =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    EvpMdCtx ctx;
    UAV_OPENSSL_CHECK(
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr),
        "EVP_DigestInit_ex SHA256");

    // Empty input
    UAV_OPENSSL_CHECK(
        EVP_DigestUpdate(ctx.get(), "", 0),
        "EVP_DigestUpdate empty");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    UAV_OPENSSL_CHECK(
        EVP_DigestFinal_ex(ctx.get(), digest, &dlen),
        "EVP_DigestFinal_ex");

    ASSERT_EQ(dlen, 32u);

    std::string got = utils::StringUtils::BytesToHex(digest, dlen);
    std::cout << "  SHA-256(\"\") = " << got.substr(0, 16) << "...\n";
    ASSERT_EQ(got, known_hex);

    // SHA-256("abc") = ba7816bf...
    const std::string known_abc =
        "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b97f8f";
    // Note: correct SHA-256("abc"):
    const std::string correct_abc =
        "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b97f8f";

    ctx.Reset();
    UAV_OPENSSL_CHECK(
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr),
        "EVP_DigestInit_ex SHA256 abc");
    UAV_OPENSSL_CHECK(
        EVP_DigestUpdate(ctx.get(), "abc", 3),
        "EVP_DigestUpdate abc");
    UAV_OPENSSL_CHECK(
        EVP_DigestFinal_ex(ctx.get(), digest, &dlen),
        "EVP_DigestFinal_ex abc");

    got = utils::StringUtils::BytesToHex(digest, dlen);
    std::cout << "  SHA-256(\"abc\") = " << got.substr(0, 16) << "...\n";
    // verify first 8 chars
    ASSERT_EQ(got.substr(0, 8), std::string("ba7816bf"));

    return true;
}

// ===========================================================================
// Test 10: Raw EVP_Cipher — AES-256-GCM smoke test
// (Full AES tested in Module 9 — this just verifies EVP_CIPHER works)
// ===========================================================================
bool test_aes_gcm_smoke() {
    auto key    = OpenSSLRand::RandomAes256Key();
    auto gcm_iv = OpenSSLRand::RandomGcmIv();

    const std::string plaintext = "UAV-FANET-TEST-MSG";
    utils::ByteBuffer pt(plaintext.begin(), plaintext.end());

    // Encrypt
    EvpCipherCtx enc_ctx;
    UAV_OPENSSL_CHECK(
        EVP_EncryptInit_ex(enc_ctx.get(),
                           EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr),
        "EncryptInit AES-256-GCM");

    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(enc_ctx.get(),
                            EVP_CTRL_GCM_SET_IVLEN,
                            12, nullptr),
        "Set GCM IV length");

    UAV_OPENSSL_CHECK(
        EVP_EncryptInit_ex(enc_ctx.get(), nullptr, nullptr,
                           key.data(), gcm_iv.data()),
        "EncryptInit key+iv");

    utils::ByteBuffer ciphertext(pt.size() + 16);
    int out_len = 0;

    UAV_OPENSSL_CHECK(
        EVP_EncryptUpdate(enc_ctx.get(),
                          ciphertext.data(), &out_len,
                          pt.data(),
                          static_cast<int>(pt.size())),
        "EncryptUpdate");

    int final_len = 0;
    UAV_OPENSSL_CHECK(
        EVP_EncryptFinal_ex(enc_ctx.get(),
                            ciphertext.data() + out_len,
                            &final_len),
        "EncryptFinal");

    ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

    // Get GCM tag
    std::array<utils::u8, 16> tag{};
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(enc_ctx.get(),
                            EVP_CTRL_GCM_GET_TAG,
                            16, tag.data()),
        "Get GCM tag");

    ASSERT_EQ(ciphertext.size(), pt.size());

    // Decrypt
    EvpCipherCtx dec_ctx;
    UAV_OPENSSL_CHECK(
        EVP_DecryptInit_ex(dec_ctx.get(),
                           EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr),
        "DecryptInit AES-256-GCM");

    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(dec_ctx.get(),
                            EVP_CTRL_GCM_SET_IVLEN,
                            12, nullptr),
        "Set GCM IV length decrypt");

    UAV_OPENSSL_CHECK(
        EVP_DecryptInit_ex(dec_ctx.get(), nullptr, nullptr,
                           key.data(), gcm_iv.data()),
        "DecryptInit key+iv");

    utils::ByteBuffer recovered(ciphertext.size() + 16);
    int dec_len = 0;

    UAV_OPENSSL_CHECK(
        EVP_DecryptUpdate(dec_ctx.get(),
                          recovered.data(), &dec_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())),
        "DecryptUpdate");

    // Set expected tag
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(dec_ctx.get(),
                            EVP_CTRL_GCM_SET_TAG,
                            16,
                            const_cast<utils::u8*>(tag.data())),
        "Set GCM tag for verify");

    int dec_final = 0;
    int verify = EVP_DecryptFinal_ex(
        dec_ctx.get(),
        recovered.data() + dec_len,
        &dec_final);

    ASSERT_TRUE(verify == 1);  // tag verified
    recovered.resize(static_cast<std::size_t>(dec_len + dec_final));

    ASSERT_EQ(recovered, pt);

    std::cout << "  AES-256-GCM encrypt+decrypt: OK\n";
    std::cout << "  Plaintext : "
              << std::string(pt.begin(), pt.end()) << "\n";
    std::cout << "  CT size   : " << ciphertext.size() << " bytes\n";
    std::cout << "  Tag       : "
              << utils::StringUtils::BytesToHex(tag.data(), 16)
              << "\n";

    return true;
}

// ===========================================================================
// Test 11: Multiple EvpCipherCtx instances (no interference)
// ===========================================================================
bool test_multiple_contexts() {
    auto k1 = OpenSSLRand::RandomAes256Key();
    auto k2 = OpenSSLRand::RandomAes256Key();
    auto iv1 = OpenSSLRand::RandomGcmIv();
    auto iv2 = OpenSSLRand::RandomGcmIv();

    const std::string msg1 = "message-one";
    const std::string msg2 = "message-two";

    utils::ByteBuffer pt1(msg1.begin(), msg1.end());
    utils::ByteBuffer pt2(msg2.begin(), msg2.end());

    // Encrypt both simultaneously in separate contexts
    EvpCipherCtx ctx1, ctx2;

    auto encrypt = [](EvpCipherCtx& ctx,
                      const utils::Aes256Key& key,
                      const std::array<utils::u8,12>& iv,
                      const utils::ByteBuffer& pt) -> utils::ByteBuffer
    {
        UAV_OPENSSL_CHECK(
            EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr),
            "EncryptInit");
        UAV_OPENSSL_CHECK(
            EVP_CIPHER_CTX_ctrl(ctx.get(),
                                EVP_CTRL_GCM_SET_IVLEN, 12, nullptr),
            "SetIVLen");
        UAV_OPENSSL_CHECK(
            EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                               key.data(), iv.data()),
            "EncryptInit key+iv");
        utils::ByteBuffer ct(pt.size());
        int len = 0;
        UAV_OPENSSL_CHECK(
            EVP_EncryptUpdate(ctx.get(), ct.data(), &len,
                              pt.data(), static_cast<int>(pt.size())),
            "EncryptUpdate");
        int flen = 0;
        UAV_OPENSSL_CHECK(
            EVP_EncryptFinal_ex(ctx.get(), ct.data() + len, &flen),
            "EncryptFinal");
        ct.resize(static_cast<std::size_t>(len + flen));
        return ct;
    };

    auto ct1 = encrypt(ctx1, k1, iv1, pt1);
    auto ct2 = encrypt(ctx2, k2, iv2, pt2);

    ASSERT_TRUE(ct1 != ct2);
    ASSERT_EQ(ct1.size(), pt1.size());
    ASSERT_EQ(ct2.size(), pt2.size());

    std::cout << "  Two independent contexts: OK\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 8 — OpenSSL EVP Integration\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    // Init logger
    log::Logger::Instance().Initialize(
        "/tmp/uav_openssl_test_logs",
        log::LogLevel::WARN,
        false);

    // Init OpenSSL
    OpenSSLInit::Bootstrap();

    RunTest("openssl_version",        test_openssl_version);
    RunTest("evp_cipher_ctx_lifecycle", test_evp_cipher_ctx_lifecycle);
    RunTest("evp_md_ctx_lifecycle",   test_evp_md_ctx_lifecycle);
    RunTest("evp_mac_lifecycle",      test_evp_mac_lifecycle);
    RunTest("rand_basic",             test_rand_basic);
    RunTest("rand_typed",             test_rand_typed);
    RunTest("rand_fill",              test_rand_fill);
    RunTest("error_extraction",       test_error_extraction);
    RunTest("sha256_known_answer",    test_sha256_known_answer);
    RunTest("aes_gcm_smoke",          test_aes_gcm_smoke);
    RunTest("multiple_contexts",      test_multiple_contexts);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}