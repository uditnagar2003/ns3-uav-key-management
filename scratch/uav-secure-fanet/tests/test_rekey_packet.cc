/**
 * tests/test_rekey_packet.cc
 * Unit test for Phase 3 Module 20: REKEY Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_rekey_packet.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-bigint.cc crypto/uav-hmac.cc \
 *       crypto/uav-replay.cc \
 *       headers/uav-packet-enums.cc \
 *       headers/uav-base-header.cc \
 *       headers/uav-rekey-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_rekey_packet
 */

#include "headers/uav-rekey-packet.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace uav;
using namespace uav::packet;
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

BigInt MakeMtk() {
    return BigInt("123456789012345678901234567890");
}

// ===========================================================================
// Test 1: RekeyBody serialize/deserialize round-trip
// ===========================================================================
bool test_rekey_body_roundtrip() {
    RekeyBody body;
    body.cluster_id   = 1;
    body.version      = 5;
    body.reason       = RekeyReason::LEAVE;
    body.mtk          = MakeMtk();
    body.timestamp_us = 9876543210ULL;
    for (std::size_t i = 0; i < 16; ++i)
        body.rekey_nonce[i] = static_cast<utils::u8>(i + 0xA0);

    auto wire  = body.Serialize();
    ASSERT_TRUE(wire.size() >= RekeyBody::FIXED_SIZE);

    auto body2 = RekeyBody::Deserialize(wire);
    ASSERT_EQ(body2.cluster_id,   body.cluster_id);
    ASSERT_EQ(body2.version,      body.version);
    ASSERT_EQ(body2.reason,       body.reason);
    ASSERT_EQ(body2.mtk,          body.mtk);
    ASSERT_EQ(body2.timestamp_us, body.timestamp_us);
    ASSERT_EQ(body2.rekey_nonce,  body.rekey_nonce);

    std::cout << "  Body wire size: " << wire.size() << " bytes\n";
    std::cout << "  RekeyBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 2: WireSize consistency
// ===========================================================================
bool test_wiresize_consistency() {
    RekeyBody body;
    body.cluster_id = 0;
    body.version    = 1;
    body.mtk        = MakeMtk();

    ASSERT_EQ(body.WireSize(), body.Serialize().size());
    std::cout << "  WireSize: " << body.WireSize() << " bytes\n";
    return true;
}

// ===========================================================================
// Test 3: Build packet
// ===========================================================================
bool test_build() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = RekeyPacket::Build(
        0, 100, 3, RekeyReason::LEAVE,
        MakeMtk(), hmac_key, seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_EQ(pkt.GetHeader().packet_type,
              PacketType::REKEY_PACKET);
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(100));
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(0xFFFF));
    ASSERT_EQ(pkt.GetBody().cluster_id,    utils::u32(0));
    ASSERT_EQ(pkt.GetBody().version,       utils::u32(3));
    ASSERT_EQ(pkt.GetBody().reason,        RekeyReason::LEAVE);
    ASSERT_TRUE(pkt.GetHeader().HasMtk());
    ASSERT_TRUE(pkt.GetHeader().IsReplayProtected());

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 4: Full serialize/deserialize round-trip
// ===========================================================================
bool test_serialize_roundtrip() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = RekeyPacket::Build(
        1, 101, 7, RekeyReason::JOIN,
        MakeMtk(), hmac_key, seq);

    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  Wire size: " << wire.size() << " bytes\n";

    auto pkt2 = RekeyPacket::Deserialize(wire, hmac_key);
    ASSERT_EQ(pkt2.GetBody().cluster_id, pkt.GetBody().cluster_id);
    ASSERT_EQ(pkt2.GetBody().version,    pkt.GetBody().version);
    ASSERT_EQ(pkt2.GetBody().reason,     pkt.GetBody().reason);
    ASSERT_EQ(pkt2.GetBody().mtk,        pkt.GetBody().mtk);
    ASSERT_EQ(pkt2.GetBody().rekey_nonce,pkt.GetBody().rekey_nonce);

    std::cout << "  Serialize/Deserialize: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: HMAC tamper detection
// ===========================================================================
bool test_tamper_detection() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = RekeyPacket::Build(
        0, 100, 1, RekeyReason::PERIODIC,
        MakeMtk(), hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    auto tampered = wire;
    tampered[50] ^= 0xFF;
    ASSERT_THROWS(RekeyPacket::Deserialize(tampered, hmac_key));

    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(RekeyPacket::Deserialize(wire, wrong_key));

    std::cout << "  Tamper detection: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: All RekeyReason values
// ===========================================================================
bool test_all_rekey_reasons() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    const RekeyReason reasons[] = {
        RekeyReason::JOIN,
        RekeyReason::LEAVE,
        RekeyReason::HANDOVER,
        RekeyReason::COMPROMISE,
        RekeyReason::PERIODIC,
        RekeyReason::JAMMER,
        RekeyReason::FORCED,
    };

    for (auto r : reasons) {
        auto pkt  = RekeyPacket::Build(
            0, 100, 1, r, MakeMtk(), hmac_key, seq);
        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);

        auto pkt2 = RekeyPacket::Deserialize(wire, hmac_key);
        ASSERT_EQ(pkt2.GetBody().reason, r);

        std::cout << "  Reason "
                  << RekeyReasonToString(r) << ": PASS\n";
    }
    return true;
}

// ===========================================================================
// Test 7: Fits within REKEY_PACKET_SIZE (512 bytes)
// ===========================================================================
bool test_fits_in_rekey_size() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Production-size MTK
    BigInt big_mtk(
        "99735465717733929368765165680915278925332715030"
        "70969212031309649187264663034");

    auto pkt  = RekeyPacket::Build(
        0, 100, 1, RekeyReason::LEAVE,
        big_mtk, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  REKEY packet size: "
              << wire.size() << " bytes\n";
    ASSERT_TRUE(wire.size() <= 512u);
    std::cout << "  Fits within 512 bytes: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: Version increments on each rekey
// ===========================================================================
bool test_version_increments() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    for (utils::u32 v = 1; v <= 5; ++v) {
        auto pkt  = RekeyPacket::Build(
            0, 100, v, RekeyReason::PERIODIC,
            MakeMtk(), hmac_key, seq);
        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);

        auto pkt2 = RekeyPacket::Deserialize(wire, hmac_key);
        ASSERT_EQ(pkt2.GetBody().version, v);
    }

    std::cout << "  Versions 1-5: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Three clusters have independent rekey packets
// ===========================================================================
bool test_three_clusters() {
    SequenceCounter seq;

    auto k0 = HmacSha256Util::GenerateKey();
    auto k1 = HmacSha256Util::GenerateKey();
    auto k2 = HmacSha256Util::GenerateKey();

    BigInt mtk0("111111111111111111111111111111");
    BigInt mtk1("222222222222222222222222222222");
    BigInt mtk2("333333333333333333333333333333");

    auto p0 = RekeyPacket::Build(0,100,1,RekeyReason::LEAVE,mtk0,k0,seq);
    auto p1 = RekeyPacket::Build(1,101,1,RekeyReason::LEAVE,mtk1,k1,seq);
    auto p2 = RekeyPacket::Build(2,102,1,RekeyReason::LEAVE,mtk2,k2,seq);

    // Different clusters
    ASSERT_EQ(p0.GetBody().cluster_id, utils::u32(0));
    ASSERT_EQ(p1.GetBody().cluster_id, utils::u32(1));
    ASSERT_EQ(p2.GetBody().cluster_id, utils::u32(2));

    // Different MTKs
    ASSERT_TRUE(p0.GetBody().mtk != p1.GetBody().mtk);

    // Cross-cluster key rejection
    auto w0 = p0.Serialize();
    HmacSha256Util::AppendHmac(k0, w0);
    ASSERT_THROWS(RekeyPacket::Deserialize(w0, k1));

    std::cout << "  3 clusters independent: PASS\n";
    std::cout << "  Cross-cluster rejection: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Unique nonce per rekey
// ===========================================================================
bool test_unique_nonce() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto p1 = RekeyPacket::Build(0,100,1,RekeyReason::JOIN,
        MakeMtk(), hmac_key, seq);
    auto p2 = RekeyPacket::Build(0,100,2,RekeyReason::JOIN,
        MakeMtk(), hmac_key, seq);

    ASSERT_TRUE(
        p1.GetBody().rekey_nonce != p2.GetBody().rekey_nonce);
    ASSERT_TRUE(
        p1.GetHeader().sequence_num !=
        p2.GetHeader().sequence_num);

    std::cout << "  Unique nonces per rekey: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: Rekey after leave simulation
// (cluster 0 loses UAV 2, SKDC broadcasts rekey)
// ===========================================================================
bool test_leave_rekey_simulation() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Before leave: version 2
    BigInt old_mtk("111111111111111111111111");
    auto before = RekeyPacket::Build(
        0, 100, 2, RekeyReason::NONE,
        old_mtk, hmac_key, seq);

    // After leave: new MTK, version 3, reason=LEAVE
    BigInt new_mtk("999999999999999999999999");
    auto after = RekeyPacket::Build(
        0, 100, 3, RekeyReason::LEAVE,
        new_mtk, hmac_key, seq);

    ASSERT_TRUE(after.GetBody().version >
                before.GetBody().version);
    ASSERT_TRUE(after.GetBody().mtk != before.GetBody().mtk);
    ASSERT_EQ(after.GetBody().reason, RekeyReason::LEAVE);

    // Serialize and verify
    auto wire = after.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);
    auto received = RekeyPacket::Deserialize(wire, hmac_key);

    ASSERT_EQ(received.GetBody().mtk, new_mtk);
    ASSERT_EQ(received.GetBody().version, utils::u32(3));

    std::cout << "  Before: v" << before.GetBody().version << "\n";
    std::cout << "  After : v" << after.GetBody().version << "\n";
    std::cout << "  Leave rekey simulation: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 20 — REKEY Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_rekey_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("rekey_body_roundtrip",    test_rekey_body_roundtrip);
    RunTest("wiresize_consistency",    test_wiresize_consistency);
    RunTest("build",                   test_build);
    RunTest("serialize_roundtrip",     test_serialize_roundtrip);
    RunTest("tamper_detection",        test_tamper_detection);
    RunTest("all_rekey_reasons",       test_all_rekey_reasons);
    RunTest("fits_in_rekey_size",      test_fits_in_rekey_size);
    RunTest("version_increments",      test_version_increments);
    RunTest("three_clusters",          test_three_clusters);
    RunTest("unique_nonce",            test_unique_nonce);
    RunTest("leave_rekey_simulation",  test_leave_rekey_simulation);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
