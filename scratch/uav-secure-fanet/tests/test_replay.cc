/**
 * tests/test_replay.cc
 * Unit test for Phase 2 Module 11: Replay Protection
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I/usr/include \
 *       tests/test_replay.cc \
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
 *       crypto/uav-replay.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_replay
 *
 * RUN:
 *   ./tests/test_replay
 */

#include "crypto/uav-replay.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-time-utils.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

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

// Current time helper
utils::u64 Now() {
    return utils::TimeUtils::NowEpochMicros();
}

// ===========================================================================
// Test 1: ReplayToken generation and serialization
// ===========================================================================
bool test_token_serialization() {
    // Generate token
    SequenceCounter seq;
    auto token = ReplayToken::Generate(seq.Next());

    ASSERT_TRUE(token.timestamp_us > 0);
    ASSERT_TRUE(token.sequence_num == 1);
    ASSERT_EQ(token.nonce.size(), 16u);

    // Serialize
    auto buf = token.Serialize();
    ASSERT_EQ(buf.size(), ReplayToken::WIRE_SIZE);  // 32 bytes

    // Deserialize round-trip
    auto token2 = ReplayToken::Deserialize(buf);
    ASSERT_EQ(token2.timestamp_us, token.timestamp_us);
    ASSERT_EQ(token2.sequence_num, token.sequence_num);
    ASSERT_EQ(token2.nonce,        token.nonce);

    // Too-short buffer throws
    utils::ByteBuffer short_buf(10, 0x00);
    ASSERT_THROWS(ReplayToken::Deserialize(short_buf));

    std::cout << "  Token wire size: " << buf.size() << " bytes\n";
    std::cout << "  Sequence num: " << token.sequence_num << "\n";
    std::cout << "  Timestamp: " << token.timestamp_us << " µs\n";
    return true;
}

// ===========================================================================
// Test 2: Fresh packet accepted
// ===========================================================================
bool test_fresh_packet_accepted() {
    ReplayCache cache;
    SequenceCounter seq;

    utils::u32 sender = 42;
    utils::u64 now    = Now();

    auto token = ReplayToken::Generate(seq.Next());

    auto result = cache.CheckAndRecord(sender, token, now);
    ASSERT_EQ(result, ReplayCheckResult::ACCEPTED);

    std::cout << "  Fresh packet: "
              << ReplayCheckResultToString(result) << "\n";
    return true;
}

// ===========================================================================
// Test 3: Timestamp — outside skew window rejected
// ===========================================================================
bool test_timestamp_rejection() {
    // 2-second skew window
    ReplayCache cache(2'000'000ULL);
    SequenceCounter seq;

    utils::u32 sender = 1;
    utils::u64 now    = Now();

    // Old timestamp (10 seconds ago) → rejected
    ReplayToken old_token;
    old_token.timestamp_us = now - 10'000'000ULL;
    old_token.nonce        = OpenSSLRand::RandomNonce128();
    old_token.sequence_num = seq.Next();

    auto r1 = cache.CheckAndRecord(sender, old_token, now);
    ASSERT_EQ(r1, ReplayCheckResult::REPLAY_TIMESTAMP);

    // Future timestamp (10 seconds ahead) → rejected
    ReplayToken future_token;
    future_token.timestamp_us = now + 10'000'000ULL;
    future_token.nonce        = OpenSSLRand::RandomNonce128();
    future_token.sequence_num = seq.Next();

    auto r2 = cache.CheckAndRecord(sender, future_token, now);
    ASSERT_EQ(r2, ReplayCheckResult::REPLAY_TIMESTAMP);

    // Fresh timestamp (within 1 second) → accepted
    ReplayToken fresh_token;
    fresh_token.timestamp_us = now - 500'000ULL;  // 0.5s ago
    fresh_token.nonce        = OpenSSLRand::RandomNonce128();
    fresh_token.sequence_num = seq.Next();

    auto r3 = cache.CheckAndRecord(sender, fresh_token, now);
    ASSERT_EQ(r3, ReplayCheckResult::ACCEPTED);

    std::cout << "  Old timestamp  : "
              << ReplayCheckResultToString(r1) << "\n";
    std::cout << "  Future timestamp: "
              << ReplayCheckResultToString(r2) << "\n";
    std::cout << "  Fresh timestamp : "
              << ReplayCheckResultToString(r3) << "\n";
    return true;
}

// ===========================================================================
// Test 4: Nonce — duplicate rejected
// ===========================================================================
bool test_nonce_rejection() {
    ReplayCache cache;
    SequenceCounter seq;

    utils::u32 sender = 2;
    utils::u64 now    = Now();

    // First occurrence — accepted
    auto nonce = OpenSSLRand::RandomNonce128();

    ReplayToken t1;
    t1.timestamp_us = now;
    t1.nonce        = nonce;
    t1.sequence_num = seq.Next();

    auto r1 = cache.CheckAndRecord(sender, t1, now);
    ASSERT_EQ(r1, ReplayCheckResult::ACCEPTED);

    // Same nonce, different sequence → REPLAY_NONCE
    ReplayToken t2;
    t2.timestamp_us = now;
    t2.nonce        = nonce;   // same nonce!
    t2.sequence_num = seq.Next();

    auto r2 = cache.CheckAndRecord(sender, t2, now);
    ASSERT_EQ(r2, ReplayCheckResult::REPLAY_NONCE);

    // Different nonce, next sequence → accepted
    ReplayToken t3;
    t3.timestamp_us = now;
    t3.nonce        = OpenSSLRand::RandomNonce128();
    t3.sequence_num = seq.Next();

    auto r3 = cache.CheckAndRecord(sender, t3, now);
    ASSERT_EQ(r3, ReplayCheckResult::ACCEPTED);

    std::cout << "  First packet    : "
              << ReplayCheckResultToString(r1) << "\n";
    std::cout << "  Duplicate nonce : "
              << ReplayCheckResultToString(r2) << "\n";
    std::cout << "  Fresh nonce     : "
              << ReplayCheckResultToString(r3) << "\n";
    return true;
}

// ===========================================================================
// Test 5: Sequence number — replay and old sequence rejected
// ===========================================================================
bool test_sequence_rejection() {
    ReplayCache cache;
    utils::u32 sender = 3;
    utils::u64 now    = Now();

    // Send packets 1..10 in order
    for (utils::u64 s = 1; s <= 10; ++s) {
        ReplayToken t;
        t.timestamp_us = now;
        t.nonce        = OpenSSLRand::RandomNonce128();
        t.sequence_num = s;
        auto r = cache.CheckAndRecord(sender, t, now);
        ASSERT_EQ(r, ReplayCheckResult::ACCEPTED);
    }

    // Replay packet 5 (within window but already seen)
    ReplayToken replay5;
    replay5.timestamp_us = now;
    replay5.nonce        = OpenSSLRand::RandomNonce128();
    replay5.sequence_num = 5;
    auto r_replay = cache.CheckAndRecord(sender, replay5, now);
    ASSERT_EQ(r_replay, ReplayCheckResult::REPLAY_SEQUENCE);

    // Sequence 0 (too old — outside 64-packet window from seq 10)
    // With window=64, seq 10-64 = negative → outside window
    // Let's advance to seq 80 first
    for (utils::u64 s = 11; s <= 80; ++s) {
        ReplayToken t;
        t.timestamp_us = now;
        t.nonce        = OpenSSLRand::RandomNonce128();
        t.sequence_num = s;
        cache.CheckAndRecord(sender, t, now);
    }

    // Now seq 1 is outside the window
    ReplayToken old_seq;
    old_seq.timestamp_us = now;
    old_seq.nonce        = OpenSSLRand::RandomNonce128();
    old_seq.sequence_num = 1;
    auto r_old = cache.CheckAndRecord(sender, old_seq, now);
    ASSERT_EQ(r_old, ReplayCheckResult::REPLAY_OLD_SEQ);

    // Next fresh sequence accepted
    ReplayToken fresh;
    fresh.timestamp_us = now;
    fresh.nonce        = OpenSSLRand::RandomNonce128();
    fresh.sequence_num = 81;
    auto r_fresh = cache.CheckAndRecord(sender, fresh, now);
    ASSERT_EQ(r_fresh, ReplayCheckResult::ACCEPTED);

    std::cout << "  Replay seq 5    : "
              << ReplayCheckResultToString(r_replay) << "\n";
    std::cout << "  Old seq (1)     : "
              << ReplayCheckResultToString(r_old) << "\n";
    std::cout << "  Fresh seq (81)  : "
              << ReplayCheckResultToString(r_fresh) << "\n";
    return true;
}

// ===========================================================================
// Test 6: CheckOrThrow — throws on replay
// ===========================================================================
bool test_check_or_throw() {
    ReplayCache cache;
    utils::u32 sender = 4;
    utils::u64 now    = Now();

    // Fresh packet — no throw
    ReplayToken t1;
    t1.timestamp_us = now;
    t1.nonce        = OpenSSLRand::RandomNonce128();
    t1.sequence_num = 1;

    bool threw = false;
    try {
        cache.CheckOrThrow(sender, t1, now);
    } catch (...) { threw = true; }
    ASSERT_TRUE(!threw);

    // Replay same token — throws
    ASSERT_THROWS(cache.CheckOrThrow(sender, t1, now));

    std::cout << "  CheckOrThrow fresh: no throw PASS\n";
    std::cout << "  CheckOrThrow replay: throws PASS\n";
    return true;
}

// ===========================================================================
// Test 7: Multiple senders isolated
// ===========================================================================
bool test_multiple_senders() {
    ReplayCache cache;
    utils::u64 now = Now();

    // Sender A uses seq 1
    ReplayToken tA;
    tA.timestamp_us = now;
    tA.nonce        = OpenSSLRand::RandomNonce128();
    tA.sequence_num = 1;
    auto rA = cache.CheckAndRecord(1, tA, now);
    ASSERT_EQ(rA, ReplayCheckResult::ACCEPTED);

    // Sender B uses seq 1 — different sender, should be accepted
    ReplayToken tB;
    tB.timestamp_us = now;
    tB.nonce        = OpenSSLRand::RandomNonce128();
    tB.sequence_num = 1;
    auto rB = cache.CheckAndRecord(2, tB, now);
    ASSERT_EQ(rB, ReplayCheckResult::ACCEPTED);

    // Sender A replay seq 1 → rejected
    ReplayToken tA2;
    tA2.timestamp_us = now;
    tA2.nonce        = OpenSSLRand::RandomNonce128();
    tA2.sequence_num = 1;
    auto rA2 = cache.CheckAndRecord(1, tA2, now);
    ASSERT_EQ(rA2, ReplayCheckResult::REPLAY_SEQUENCE);

    ASSERT_EQ(cache.SenderCount(), 2u);

    std::cout << "  Sender 1 seq 1: " << ReplayCheckResultToString(rA) << "\n";
    std::cout << "  Sender 2 seq 1: " << ReplayCheckResultToString(rB) << "\n";
    std::cout << "  Sender 1 replay: " << ReplayCheckResultToString(rA2) << "\n";
    std::cout << "  Sender count: " << cache.SenderCount() << "\n";
    return true;
}

// ===========================================================================
// Test 8: Reset sender (handover scenario)
// ===========================================================================
bool test_reset_sender() {
    ReplayCache cache;
    utils::u32 sender = 5;
    utils::u64 now    = Now();

    // Send seq 1-5
    for (utils::u64 s = 1; s <= 5; ++s) {
        ReplayToken t;
        t.timestamp_us = now;
        t.nonce        = OpenSSLRand::RandomNonce128();
        t.sequence_num = s;
        cache.CheckAndRecord(sender, t, now);
    }

    // Seq 3 replay → rejected
    ReplayToken t3;
    t3.timestamp_us = now;
    t3.nonce        = OpenSSLRand::RandomNonce128();
    t3.sequence_num = 3;
    auto r1 = cache.CheckAndRecord(sender, t3, now);
    ASSERT_EQ(r1, ReplayCheckResult::REPLAY_SEQUENCE);

    // Reset sender state (simulates handover)
    cache.ResetSender(sender);
    ASSERT_TRUE(!cache.HasSender(sender));

    // After reset seq 3 is accepted again
    ReplayToken t3b;
    t3b.timestamp_us = now;
    t3b.nonce        = OpenSSLRand::RandomNonce128();
    t3b.sequence_num = 3;
    auto r2 = cache.CheckAndRecord(sender, t3b, now);
    ASSERT_EQ(r2, ReplayCheckResult::ACCEPTED);

    std::cout << "  Before reset seq 3: "
              << ReplayCheckResultToString(r1) << "\n";
    std::cout << "  After reset seq 3 : "
              << ReplayCheckResultToString(r2) << "\n";
    return true;
}

// ===========================================================================
// Test 9: SequenceCounter
// ===========================================================================
bool test_sequence_counter() {
    SequenceCounter sc(1);

    // Sequential increments
    ASSERT_EQ(sc.Next(), 1ULL);
    ASSERT_EQ(sc.Next(), 2ULL);
    ASSERT_EQ(sc.Next(), 3ULL);
    ASSERT_EQ(sc.Current(), 4ULL);

    // Reset
    sc.Reset(100);
    ASSERT_EQ(sc.Next(), 100ULL);
    ASSERT_EQ(sc.Next(), 101ULL);

    // Thread-safe increment test
    sc.Reset(1);
    std::atomic<int> errors{0};
    std::vector<std::thread> threads;
    std::vector<utils::u64> results(100);

    for (int i = 0; i < 100; ++i) {
        threads.emplace_back([&sc, &results, &errors, i]() {
            try {
                results[static_cast<std::size_t>(i)] = sc.Next();
            } catch (...) { ++errors; }
        });
    }
    for (auto& t : threads) t.join();

    ASSERT_EQ(errors.load(), 0);

    // All 100 values must be unique
    std::sort(results.begin(), results.end());
    for (std::size_t i = 0; i + 1 < results.size(); ++i) {
        ASSERT_TRUE(results[i] != results[i+1]);
    }

    std::cout << "  Sequential: 1,2,3 PASS\n";
    std::cout << "  Thread-safe: 100 unique values PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Eviction of stale senders
// ===========================================================================
bool test_eviction() {
    ReplayCache cache;
    utils::u64 now = Now();

    // Add sender with old last_seen
    ReplayToken t;
    t.timestamp_us = now;
    t.nonce        = OpenSSLRand::RandomNonce128();
    t.sequence_num = 1;

    cache.CheckAndRecord(10, t, now);
    cache.CheckAndRecord(11, t, now);
    ASSERT_EQ(cache.SenderCount(), 2u);

    // Evict senders older than 0 µs (evicts all)
    cache.Evict(0);
    ASSERT_EQ(cache.SenderCount(), 0u);

    std::cout << "  Before evict: 2 senders\n";
    std::cout << "  After evict : 0 senders\n";
    return true;
}

// ===========================================================================
// Test 11: Full packet workflow simulation
// (simulates 18 UAVs sending packets to SKDC)
// ===========================================================================
bool test_full_workflow() {
    ReplayCache skdc_cache;
    utils::u64 now = Now();

    constexpr int NUM_UAVS = 18;
    std::vector<SequenceCounter> seq_counters(NUM_UAVS);

    int accepted = 0;
    int rejected = 0;

    // Each UAV sends 5 valid packets
    for (int uav = 0; uav < NUM_UAVS; ++uav) {
        for (int pkt = 0; pkt < 5; ++pkt) {
            ReplayToken t = ReplayToken::Generate(
                seq_counters[static_cast<std::size_t>(uav)].Next());
            t.timestamp_us = now;  // fix timestamp for test

            auto r = skdc_cache.CheckAndRecord(
                static_cast<utils::u32>(uav), t, now);

            if (r == ReplayCheckResult::ACCEPTED) ++accepted;
            else ++rejected;
        }
    }

    ASSERT_EQ(accepted, NUM_UAVS * 5);
    ASSERT_EQ(rejected, 0);
    ASSERT_EQ(skdc_cache.SenderCount(),
              static_cast<std::size_t>(NUM_UAVS));

    std::cout << "  " << NUM_UAVS << " UAVs × 5 packets = "
              << accepted << " accepted, "
              << rejected << " rejected\n";
    std::cout << "  Sender cache size: "
              << skdc_cache.SenderCount() << "\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 2 Module 11 — Replay Protection\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_replay_test_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("token_serialization",   test_token_serialization);
    RunTest("fresh_packet_accepted", test_fresh_packet_accepted);
    RunTest("timestamp_rejection",   test_timestamp_rejection);
    RunTest("nonce_rejection",       test_nonce_rejection);
    RunTest("sequence_rejection",    test_sequence_rejection);
    RunTest("check_or_throw",        test_check_or_throw);
    RunTest("multiple_senders",      test_multiple_senders);
    RunTest("reset_sender",          test_reset_sender);
    RunTest("sequence_counter",      test_sequence_counter);
    RunTest("eviction",              test_eviction);
    RunTest("full_workflow",         test_full_workflow);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}