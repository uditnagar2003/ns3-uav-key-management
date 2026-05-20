/**
 * tests/test_mtk_packet.cc
 * Unit test for Phase 3 Module 17: MT_K Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_mtk_packet.cc \
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
 *       headers/uav-mtk-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_mtk_packet
 *
 * RUN:
 *   ./tests/test_mtk_packet
 */

#include "headers/uav-mtk-packet.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-time-utils.h"

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

// Helper: make small test BigInts
BigInt MakeMtk()     { return BigInt("123456789012345678901234567890"); }
BigInt MakeNGroup()  { return BigInt("987654321098765432109876543210"); }

// ===========================================================================
// Test 1: MtkBody serialize/deserialize round-trip
// ===========================================================================
bool test_mtk_body_roundtrip() {
    MtkBody body;
    body.cluster_id   = 1;
    body.version      = 3;
    body.timestamp_us = 1234567890ULL;
    body.mtk          = MakeMtk();
    body.n_group      = MakeNGroup();
    for (std::size_t i = 0; i < 16; ++i)
        body.body_nonce[i] = static_cast<utils::u8>(i + 0xA0);

    auto wire = body.Serialize();
    ASSERT_TRUE(wire.size() >= MtkBody::MIN_SIZE);

    auto body2 = MtkBody::Deserialize(wire);
    ASSERT_EQ(body2.cluster_id,   body.cluster_id);
    ASSERT_EQ(body2.version,      body.version);
    ASSERT_EQ(body2.timestamp_us, body.timestamp_us);
    ASSERT_EQ(body2.mtk,          body.mtk);
    ASSERT_EQ(body2.n_group,      body.n_group);
    ASSERT_EQ(body2.body_nonce,   body.body_nonce);

    std::cout << "  Body wire size: " << wire.size() << " bytes\n";
    std::cout << "  MTK: "
              << BigIntOps::ToDecString(body.mtk).substr(0,20)
              << "...\n";
    std::cout << "  MtkBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 2: MtkBody WireSize consistency
// ===========================================================================
bool test_mtk_body_wiresize() {
    MtkBody body;
    body.cluster_id = 0;
    body.version    = 1;
    body.mtk        = MakeMtk();
    body.n_group    = MakeNGroup();

    std::size_t computed = body.WireSize();
    auto wire            = body.Serialize();

    ASSERT_EQ(computed, wire.size());
    std::cout << "  WireSize matches Serialize: "
              << computed << " bytes\n";
    return true;
}

// ===========================================================================
// Test 3: MtkPacket Build
// ===========================================================================
bool test_mtk_packet_build() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = MtkPacket::Build(
        0,          // cluster_id
        100,        // src_skdc
        1,          // version
        MakeMtk(),
        MakeNGroup(),
        hmac_key,
        seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_EQ(pkt.GetHeader().packet_type,
              PacketType::MTK_PACKET);
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(100));
    ASSERT_EQ(pkt.GetHeader().cluster_id,  utils::u16(0));
    ASSERT_TRUE(pkt.GetHeader().HasMtk());
    ASSERT_TRUE(pkt.GetHeader().IsReplayProtected());
    ASSERT_TRUE(pkt.GetHeader().HasHmac());
    ASSERT_EQ(pkt.GetBody().version, utils::u32(1));
    ASSERT_EQ(pkt.GetBody().cluster_id, utils::u32(0));

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 4: Full serialize/deserialize with HMAC
// ===========================================================================
bool test_mtk_packet_serialization() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = MtkPacket::Build(
        1,      // cluster
        101,    // skdc
        5,      // version
        MakeMtk(),
        MakeNGroup(),
        hmac_key,
        seq);

    // Serialize (without HMAC — add it manually)
    auto wire = pkt.Serialize();

    // Append HMAC
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  Wire size with HMAC: "
              << wire.size() << " bytes\n";

    // Deserialize + verify HMAC
    auto pkt2 = MtkPacket::Deserialize(wire, hmac_key);

    ASSERT_EQ(pkt2.GetHeader().packet_type,
              PacketType::MTK_PACKET);
    ASSERT_EQ(pkt2.GetBody().cluster_id,
              pkt.GetBody().cluster_id);
    ASSERT_EQ(pkt2.GetBody().version,
              pkt.GetBody().version);
    ASSERT_EQ(pkt2.GetBody().mtk,
              pkt.GetBody().mtk);
    ASSERT_EQ(pkt2.GetBody().n_group,
              pkt.GetBody().n_group);

    std::cout << "  Serialize/Deserialize round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: HMAC tamper detection
// ===========================================================================
bool test_hmac_tamper_detection() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = MtkPacket::Build(0, 100, 1,
        MakeMtk(), MakeNGroup(), hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    // Tamper with wire
    auto tampered = wire;
    tampered[32] ^= 0xFF;

    ASSERT_THROWS(MtkPacket::Deserialize(tampered, hmac_key));

    // Wrong key
    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(MtkPacket::Deserialize(wire, wrong_key));

    std::cout << "  Tampered body rejected: PASS\n";
    std::cout << "  Wrong HMAC key rejected: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: Replay token in MT_K packet
// ===========================================================================
bool test_replay_token_in_mtk() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt1 = MtkPacket::Build(0, 100, 1,
        MakeMtk(), MakeNGroup(), hmac_key, seq);
    auto pkt2 = MtkPacket::Build(0, 100, 2,
        MakeMtk(), MakeNGroup(), hmac_key, seq);

    // Different sequence numbers
    ASSERT_TRUE(
        pkt1.GetHeader().sequence_num !=
        pkt2.GetHeader().sequence_num);

    // Different nonces
    ASSERT_TRUE(
        pkt1.GetHeader().nonce !=
        pkt2.GetHeader().nonce);

    std::cout << "  Seq 1: " << pkt1.GetHeader().sequence_num
              << "\n";
    std::cout << "  Seq 2: " << pkt2.GetHeader().sequence_num
              << "\n";
    std::cout << "  Unique nonces: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: Version increment
// ===========================================================================
bool test_version_increment() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt1 = MtkPacket::Build(0, 100, 1,
        MakeMtk(), MakeNGroup(), hmac_key, seq);
    auto pkt2 = MtkPacket::Build(0, 100, 2,
        MakeMtk(), MakeNGroup(), hmac_key, seq);
    auto pkt3 = MtkPacket::Build(0, 100, 3,
        MakeMtk(), MakeNGroup(), hmac_key, seq);

    ASSERT_EQ(pkt1.GetBody().version, utils::u32(1));
    ASSERT_EQ(pkt2.GetBody().version, utils::u32(2));
    ASSERT_EQ(pkt3.GetBody().version, utils::u32(3));

    std::cout << "  Versions 1,2,3: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: Large BigInt MT_K (production-size)
// ===========================================================================
bool test_large_bigint_mtk() {
    // Simulate production-size MT_K (256-bit safe prime product)
    BigInt large_mtk = BigInt(
        "99735465717733929368765165680915278925332715030"
        "70969212031309649187264663034387285183222085408"
        "525579745082375439950251841403562559420299371208"
        "873259773303");

    BigInt large_n = BigInt(
        "10374488968351774802161445350729323917712782132"
        "29877900770674219022610007093399863323352865559"
        "336114080891915576421128703741639110104234431468"
        "327039399781");

    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = MtkPacket::Build(2, 102, 7,
        large_mtk, large_n, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    auto pkt2 = MtkPacket::Deserialize(wire, hmac_key);
    ASSERT_EQ(pkt2.GetBody().mtk,     large_mtk);
    ASSERT_EQ(pkt2.GetBody().n_group, large_n);

    std::cout << "  Large MTK size: "
              << wire.size() << " bytes\n";
    std::cout << "  Large BigInt round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Three clusters produce independent packets
// ===========================================================================
bool test_three_clusters() {
    auto key0 = HmacSha256Util::GenerateKey();
    auto key1 = HmacSha256Util::GenerateKey();
    auto key2 = HmacSha256Util::GenerateKey();

    SequenceCounter seq;

    BigInt mtk0("111111111111111111111111111111");
    BigInt mtk1("222222222222222222222222222222");
    BigInt mtk2("333333333333333333333333333333");
    BigInt ng("999999999999999999999999999999");

    auto p0 = MtkPacket::Build(0, 100, 1, mtk0, ng, key0, seq);
    auto p1 = MtkPacket::Build(1, 101, 1, mtk1, ng, key1, seq);
    auto p2 = MtkPacket::Build(2, 102, 1, mtk2, ng, key2, seq);

    // Each cluster has different SKDC src
    ASSERT_EQ(p0.GetHeader().src_node_id, utils::u16(100));
    ASSERT_EQ(p1.GetHeader().src_node_id, utils::u16(101));
    ASSERT_EQ(p2.GetHeader().src_node_id, utils::u16(102));

    // Each cluster has correct ID
    ASSERT_EQ(p0.GetBody().cluster_id, utils::u32(0));
    ASSERT_EQ(p1.GetBody().cluster_id, utils::u32(1));
    ASSERT_EQ(p2.GetBody().cluster_id, utils::u32(2));

    // MTK values are different
    ASSERT_TRUE(p0.GetBody().mtk != p1.GetBody().mtk);
    ASSERT_TRUE(p1.GetBody().mtk != p2.GetBody().mtk);

    // Each cluster's key cannot decrypt another's packet
    auto w0 = p0.Serialize();
    HmacSha256Util::AppendHmac(key0, w0);
    ASSERT_THROWS(MtkPacket::Deserialize(w0, key1));
    ASSERT_THROWS(MtkPacket::Deserialize(w0, key2));

    std::cout << "  3 clusters independent: PASS\n";
    std::cout << "  Cross-cluster HMAC rejection: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Packet fits within REKEY_PACKET_SIZE (512 bytes)
// ===========================================================================
bool test_fits_in_rekey_size() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Production-size MT_K (~256 bytes BigInt)
    BigInt big_mtk = BigInt(
        "99735465717733929368765165680915278925332715030"
        "70969212031309649187264663034387285183222085408"
        "525579745082375439950251841403562559420299371208"
        "873259773303");
    BigInt big_ng = big_mtk + BigInt(1);

    auto pkt  = MtkPacket::Build(0, 100, 1,
        big_mtk, big_ng, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  MT_K packet wire size: "
              << wire.size() << " bytes\n";
    std::cout << "  REKEY_PACKET_SIZE limit: 512 bytes\n";

    ASSERT_TRUE(wire.size() <= 512u);
    std::cout << "  Fits within 512 bytes: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: Describe output
// ===========================================================================
bool test_describe() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = MtkPacket::Build(0, 100, 3,
        MakeMtk(), MakeNGroup(), hmac_key, seq);

    std::string desc = pkt.Describe();
    ASSERT_TRUE(!desc.empty());
    ASSERT_TRUE(desc.find("MTK") != std::string::npos);
    ASSERT_TRUE(desc.find("cluster=0") != std::string::npos);
    ASSERT_TRUE(desc.find("version=3") != std::string::npos);

    std::cout << "  " << desc << "\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 17 — MT_K Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_mtk_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("mtk_body_roundtrip",       test_mtk_body_roundtrip);
    RunTest("mtk_body_wiresize",        test_mtk_body_wiresize);
    RunTest("mtk_packet_build",         test_mtk_packet_build);
    RunTest("mtk_packet_serialization", test_mtk_packet_serialization);
    RunTest("hmac_tamper_detection",    test_hmac_tamper_detection);
    RunTest("replay_token_in_mtk",      test_replay_token_in_mtk);
    RunTest("version_increment",        test_version_increment);
    RunTest("large_bigint_mtk",         test_large_bigint_mtk);
    RunTest("three_clusters",           test_three_clusters);
    RunTest("fits_in_rekey_size",       test_fits_in_rekey_size);
    RunTest("describe",                 test_describe);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
