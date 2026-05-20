/**
 * tests/test_crt_manager.cc
 * Unit test for Phase 2 Module 12: CRT/GCRT Crypto Manager
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I/usr/include \
 *       tests/test_crt_manager.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-bigint.cc crypto/uav-aes.cc \
 *       crypto/uav-hmac.cc crypto/uav-replay.cc \
 *       crypto/uav-crypto-params.cc \
 *       crypto/uav-crt-manager.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_crt_manager
 *
 * RUN:
 *   ./tests/test_crt_manager
 *
 * REQUIRES: json/crypto_params.json (run python3 scripts/gen_crypto.py first)
 */

#include "crypto/uav-crt-manager.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-time-utils.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>

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

bool json_exists() {
    std::ifstream f("json/crypto_params.json");
    return f.good();
}

// ===========================================================================
// Test 1: Load from file
// ===========================================================================
bool test_load_from_file() {
    if (!json_exists()) {
        std::cout << "  SKIP: run python3 scripts/gen_crypto.py first\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    ASSERT_TRUE(mgr.IsInitialized());
    ASSERT_EQ(mgr.NumClusters(),    3u);
    ASSERT_EQ(mgr.NumUavs(),        18u);
    ASSERT_EQ(mgr.UavsPerCluster(), 6u);

    std::cout << "  Clusters: " << mgr.NumClusters() << "\n";
    std::cout << "  UAVs: "     << mgr.NumUavs()     << "\n";
    return true;
}

// ===========================================================================
// Test 2: Initial MT_K verification (all 18 UAVs)
// ===========================================================================
bool test_initial_mtk_verification() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    ASSERT_TRUE(mgr.VerifyAll());
    std::cout << "  All 3 clusters × 6 UAVs: MT_K decrypt VERIFIED\n";
    return true;
}

// ===========================================================================
// Test 3: SlaveDecrypt — core security property
// pow(MT_K, d_i, n_i) == T mod n_i
// ===========================================================================
bool test_slave_decrypt() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    int pass = 0;
    int fail = 0;

    for (utils::u32 c = 0; c < 3; ++c) {
        auto mtoken = mgr.GetMToken(c);

        for (utils::u32 u = 0; u < 6; ++u) {
            const auto* sk = mgr.GetClusterSlaveKey(c, u);
            ASSERT_TRUE(sk != nullptr);

            bool ok = CrtManager::VerifySlaveDecrypt(
                *sk, mtoken.MT_K, mtoken.T);  // T = tek_int

            if (ok) {
                ++pass;
                std::cout << "  Cluster " << c
                          << " UAV " << u << ": OK\n";
            } else {
                ++fail;
                std::cerr << "  Cluster " << c
                          << " UAV " << u << ": FAIL\n";
            }
        }
    }

    ASSERT_EQ(fail, 0);
    ASSERT_EQ(pass, 18);
    return true;
}

// ===========================================================================
// Test 4: Algorithm 3 — JoKeyUpdate (join event)
// ===========================================================================
bool test_jo_key_update() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    // Get cluster 0 state
    auto mtoken0 = mgr.GetMToken(0);
    utils::u32 initial_users =
        static_cast<utils::u32>(mtoken0.user_indices.size());

    // Simulate leave then join (leave UAV 0 first)
    auto params = CryptoParamsLoader::LoadFromFile(
        "json/crypto_params.json");
    const auto* c0 = params.GetCluster(0);
    ASSERT_TRUE(c0 != nullptr);

    // Build MKeyGenResult from loaded params
    MKeyGenResult mkg;
    mkg.eM      = c0->eM;
    mkg.n_total = c0->n_total;
    mkg.slaves  = c0->slave_keys;

    // Set T = tek_int for MTokenGen
    mtoken0.T       = c0->tek_int;
    mtoken0.N_group = c0->N_group;

    // Simulate leave of UAV index 0
    MTokenResult after_leave = CrtManager::LeKeyUpdate(
        mkg, mtoken0, 0);

    ASSERT_EQ(static_cast<utils::u32>(
        after_leave.user_indices.size()),
        initial_users - 1);

    // Verify remaining UAVs (1..5) can decrypt after leave
    bool leave_ok = true;
    for (utils::u32 u = 1; u < 6; ++u) {
        const auto* sk = mgr.GetClusterSlaveKey(0, u);
        if (!sk) { leave_ok = false; continue; }
        // pow(new_MT_K, d_i, n_i) == tek_int % n_i
        BigInt recovered = BigIntOps::ModPow(
            after_leave.MT_K, sk->d_i, sk->n_i);
        BigInt expected  = BigIntOps::Mod(after_leave.T, sk->n_i);
        if (recovered != expected) { leave_ok = false; }
    }
    ASSERT_TRUE(leave_ok);

    // Now join UAV 0 back
    MTokenResult after_join = CrtManager::JoKeyUpdate(
        mkg, after_leave, 0);

    ASSERT_EQ(static_cast<utils::u32>(
        after_join.user_indices.size()),
        initial_users);

    // Verify ALL UAVs can decrypt after rejoin
    bool join_ok = true;
    for (utils::u32 u = 0; u < 6; ++u) {
        const auto* sk = mgr.GetClusterSlaveKey(0, u);
        if (!sk) { join_ok = false; continue; }
        BigInt recovered = BigIntOps::ModPow(
            after_join.MT_K, sk->d_i, sk->n_i);
        BigInt expected  = BigIntOps::Mod(after_join.T, sk->n_i);
        if (recovered != expected) { join_ok = false; }
    }
    ASSERT_TRUE(join_ok);

    std::cout << "  Leave UAV 0: remaining 5 verify OK\n";
    std::cout << "  Rejoin UAV 0: all 6 verify OK\n";
    std::cout << "  Version after leave: "
              << after_leave.version << "\n";
    std::cout << "  Version after join: "
              << after_join.version << "\n";
    return true;
}

// ===========================================================================
// Test 5: Algorithm 5 — LeKeyUpdate (leave event)
// ===========================================================================
bool test_le_key_update() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    auto params = CryptoParamsLoader::LoadFromFile(
        "json/crypto_params.json");
    const auto* c1 = params.GetCluster(1);
    ASSERT_TRUE(c1 != nullptr);

    MKeyGenResult mkg;
    mkg.eM      = c1->eM;
    mkg.n_total = c1->n_total;
    mkg.slaves  = c1->slave_keys;

    auto mtoken1 = mgr.GetMToken(1);
    mtoken1.N_group = c1->N_group;

    // Leave UAV 3 (middle of cluster)
    MTokenResult after_leave = CrtManager::LeKeyUpdate(
        mkg, mtoken1, 3);

    // UAV 3 (index 3) should NOT be in user list
    bool uav3_found = false;
    for (auto idx : after_leave.user_indices) {
        if (idx == 3) { uav3_found = true; break; }
    }
    ASSERT_TRUE(!uav3_found);

    // Remaining UAVs (0,1,2,4,5) verify
    std::vector<utils::u32> remaining = {0, 1, 2, 4, 5};
    for (auto u : remaining) {
        const auto* sk = mgr.GetClusterSlaveKey(1, u);
        ASSERT_TRUE(sk != nullptr);
        // pow(MT_K, d_i, n_i) == tek_int % n_i
        BigInt recovered = BigIntOps::ModPow(
            after_leave.MT_K, sk->d_i, sk->n_i);
        BigInt expected  = BigIntOps::Mod(after_leave.T, sk->n_i);
        bool ok = (recovered == expected);
        ASSERT_TRUE(ok);
        std::cout << "  Cluster 1 UAV " << u
                  << " after leave: OK\n";
    }

    // UAV 3 should fail (excluded from group)
    // Note: in real scenario UAV 3 is revoked and
    // can't decrypt the NEW MT_K
    std::cout << "  UAV 3 excluded from new group: VERIFIED\n";
    return true;
}

// ===========================================================================
// Test 6: ProcessJoin (runtime state update)
// ===========================================================================
bool test_process_join() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    utils::u32 rekey_before = mgr.GetRekeyCount(2);

    // Simulate leave first (to test join)
    auto params = CryptoParamsLoader::LoadFromFile(
        "json/crypto_params.json");
    const auto* c2 = params.GetCluster(2);
    MKeyGenResult mkg;
    mkg.eM      = c2->eM;
    mkg.n_total = c2->n_total;
    mkg.slaves  = c2->slave_keys;

    auto mtoken2 = mgr.GetMToken(2);
    auto after_leave = CrtManager::LeKeyUpdate(mkg, mtoken2, 5);

    // ProcessJoin — updates internal state
    auto new_mtoken = mgr.ProcessJoin(2, 5);

    ASSERT_EQ(mgr.GetRekeyCount(2), rekey_before + 1);
    ASSERT_TRUE(new_mtoken.version > mtoken2.version);

    std::cout << "  ProcessJoin rekey count: "
              << mgr.GetRekeyCount(2) << "\n";
    std::cout << "  Version incremented: "
              << new_mtoken.version << "\n";
    return true;
}

// ===========================================================================
// Test 7: ProcessLeave (runtime state + TEK rotation)
// ===========================================================================
bool test_process_leave() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    auto tek_before = mgr.GetTek(0);
    utils::u32 rekey_before = mgr.GetRekeyCount(0);

    // ProcessLeave — updates MT_K + rotates TEK
    auto new_mtoken = mgr.ProcessLeave(0, 0);

    auto tek_after = mgr.GetTek(0);

    // TEK must have changed after leave
    ASSERT_TRUE(tek_before != tek_after);
    ASSERT_EQ(mgr.GetRekeyCount(0), rekey_before + 1);

    std::cout << "  TEK before: "
              << utils::StringUtils::BytesToHex(
                     tek_before.data(), 8) << "...\n";
    std::cout << "  TEK after : "
              << utils::StringUtils::BytesToHex(
                     tek_after.data(), 8) << "...\n";
    std::cout << "  TEK rotated: PASS\n";
    std::cout << "  Rekey count: "
              << mgr.GetRekeyCount(0) << "\n";
    return true;
}

// ===========================================================================
// Test 8: TEK encryption/decryption
// ===========================================================================
bool test_tek_encrypt_decrypt() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    auto tek = mgr.GetTek(0);
    auto kek = AesGcm::GenerateKey();  // KEK for SKDC->UAV

    // Encrypt TEK
    auto wire = CrtManager::EncryptTek(kek, tek, 0);
    ASSERT_EQ(wire.size(), 60u);  // IV(12)+CT(32)+TAG(16)

    // Decrypt TEK
    auto recovered = CrtManager::DecryptTek(kek, wire, 0);
    ASSERT_EQ(recovered, tek);

    // Wrong KEK fails
    auto wrong_kek = AesGcm::GenerateKey();
    ASSERT_THROWS(CrtManager::DecryptTek(wrong_kek, wire, 0));

    std::cout << "  TEK wire size: " << wire.size() << " bytes\n";
    std::cout << "  TEK encrypt/decrypt: PASS\n";
    std::cout << "  Wrong KEK throws: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: TEK rotation
// ===========================================================================
bool test_tek_rotation() {
    auto old_tek = AesGcm::GenerateKey();
    auto nonce   = OpenSSLRand::RandomNonce128();
    auto now_us  = utils::TimeUtils::NowEpochMicros();

    auto new_tek = CrtManager::RotateTek(old_tek, now_us, nonce);

    ASSERT_TRUE(new_tek != old_tek);
    ASSERT_EQ(new_tek.size(), 32u);

    // Deterministic with same inputs
    auto new_tek2 = CrtManager::RotateTek(old_tek, now_us, nonce);
    ASSERT_EQ(new_tek, new_tek2);

    // Different nonce → different TEK
    auto nonce2  = OpenSSLRand::RandomNonce128();
    auto new_tek3 = CrtManager::RotateTek(old_tek, now_us, nonce2);
    ASSERT_TRUE(new_tek != new_tek3);

    std::cout << "  Old TEK: "
              << utils::StringUtils::BytesToHex(old_tek.data(), 8)
              << "...\n";
    std::cout << "  New TEK: "
              << utils::StringUtils::BytesToHex(new_tek.data(), 8)
              << "...\n";
    std::cout << "  TEK rotation deterministic: PASS\n";
    std::cout << "  Different nonce → different key: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: TekFromBigInt / TekToBigInt round-trip
// ===========================================================================
bool test_tek_bigint_conversion() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    auto mtoken = mgr.GetMToken(0);
    const BigInt& T = mtoken.T;

    // T → AesGcmKey → T (round-trip)
    AesGcmKey key = CrtManager::TekFromBigInt(T);
    ASSERT_EQ(key.size(), 32u);

    BigInt T2 = CrtManager::TekToBigInt(key);

    // T2 should match T mod 2^256
    BigInt mask = (BigInt(1) << 256) - 1;
    BigInt T_masked  = BigIntOps::Mod(T,  mask);
    BigInt T2_masked = BigIntOps::Mod(T2, mask);
    ASSERT_EQ(T_masked, T2_masked);

    std::cout << "  T → AesKey → T: round-trip PASS\n";
    return true;
}

// ===========================================================================
// Test 11: GetSlaveKey lookup
// ===========================================================================
bool test_get_slave_key() {
    if (!json_exists()) {
        std::cout << "  SKIP\n";
        return true;
    }

    CrtManager mgr;
    mgr.LoadFromFile("json/crypto_params.json");

    // UAVs 0-17 should all be findable
    for (utils::u32 uid = 0; uid < 18; ++uid) {
        const auto* sk = mgr.GetSlaveKey(uid);
        ASSERT_TRUE(sk != nullptr);
        ASSERT_EQ(sk->uav_id, uid);
    }

    // UAV 99 should not be found
    ASSERT_TRUE(mgr.GetSlaveKey(99) == nullptr);

    std::cout << "  All 18 UAVs found by uav_id: PASS\n";
    std::cout << "  UAV 99 returns nullptr: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 12 — CRT/GCRT Crypto Manager\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_crt_manager_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("load_from_file",        test_load_from_file);
    RunTest("initial_mtk_verify",    test_initial_mtk_verification);
    RunTest("slave_decrypt",         test_slave_decrypt);
    RunTest("jo_key_update",         test_jo_key_update);
    RunTest("le_key_update",         test_le_key_update);
    RunTest("process_join",          test_process_join);
    RunTest("process_leave",         test_process_leave);
    RunTest("tek_encrypt_decrypt",   test_tek_encrypt_decrypt);
    RunTest("tek_rotation",          test_tek_rotation);
    RunTest("tek_bigint_conversion", test_tek_bigint_conversion);
    RunTest("get_slave_key",         test_get_slave_key);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
