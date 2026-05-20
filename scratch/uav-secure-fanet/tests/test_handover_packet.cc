/**
 * tests/test_handover_packet.cc
 * Unit test for Phase 3 Module 21: HANDOVER Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_handover_packet.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-hmac.cc crypto/uav-replay.cc \
 *       headers/uav-packet-enums.cc \
 *       headers/uav-base-header.cc \
 *       headers/uav-handover-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_handover_packet
 */

#include "headers/uav-handover-packet.h"
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

// ===========================================================================
// Test 1: HandoverBody wire size
// ===========================================================================
bool test_body_wire_size() {
    ASSERT_EQ(HandoverBody::WIRE_SIZE, 64u);

    HandoverBody body;
    body.phase = HandoverPhase::INITIATED;
    ASSERT_EQ(body.Serialize().size(), 64u);

    std::cout << "  HandoverBody size: 64 bytes\n";
    return true;
}

// ===========================================================================
// Test 2: HandoverBody serialize/deserialize
// ===========================================================================
bool test_body_roundtrip() {
    HandoverBody body;
    body.phase          = HandoverPhase::NEW_JOIN;
    body.uav_id         = 7;
    body.old_cluster_id = 0;
    body.new_cluster_id = 1;
    body.old_skdc_id    = 100;
    body.new_skdc_id    = 101;
    body.old_version    = 3;
    body.new_version    = 4;
    body.timestamp_us   = 1234567890ULL;
    body.uav_index_old  = 1;
    body.uav_index_new  = 2;
    for (std::size_t i = 0; i < 16; ++i)
        body.ho_nonce[i] = static_cast<utils::u8>(i + 0xB0);

    auto wire  = body.Serialize();
    auto body2 = HandoverBody::Deserialize(wire);

    ASSERT_EQ(body2.phase,          body.phase);
    ASSERT_EQ(body2.uav_id,         body.uav_id);
    ASSERT_EQ(body2.old_cluster_id, body.old_cluster_id);
    ASSERT_EQ(body2.new_cluster_id, body.new_cluster_id);
    ASSERT_EQ(body2.old_skdc_id,    body.old_skdc_id);
    ASSERT_EQ(body2.new_skdc_id,    body.new_skdc_id);
    ASSERT_EQ(body2.old_version,    body.old_version);
    ASSERT_EQ(body2.new_version,    body.new_version);
    ASSERT_EQ(body2.timestamp_us,   body.timestamp_us);
    ASSERT_EQ(body2.uav_index_old,  body.uav_index_old);
    ASSERT_EQ(body2.uav_index_new,  body.uav_index_new);
    ASSERT_EQ(body2.ho_nonce,       body.ho_nonce);

    std::cout << "  HandoverBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: BuildInit (Phase 1)
// ===========================================================================
bool test_build_init() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = HandoverPacket::BuildInit(
        7,    // uav_id
        100,  // old_skdc
        0,    // old_cluster
        1,    // new_cluster
        101,  // new_skdc
        1,    // uav_index_old
        hmac_key, seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_EQ(pkt.GetPhase(), HandoverPhase::INITIATED);
    ASSERT_EQ(pkt.GetBody().uav_id,         utils::u16(7));
    ASSERT_EQ(pkt.GetBody().old_cluster_id, utils::u16(0));
    ASSERT_EQ(pkt.GetBody().new_cluster_id, utils::u16(1));
    ASSERT_EQ(pkt.GetHeader().src_type, NodeTypeCode::UAV);
    ASSERT_EQ(pkt.GetHeader().dst_type, NodeTypeCode::SKDC);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 4: BuildTransfer (Phase 2)
// ===========================================================================
bool test_build_transfer() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = HandoverPacket::BuildTransfer(
        7, 100, 101, 0, 1, 1, 2, hmac_key, seq);

    ASSERT_EQ(pkt.GetPhase(), HandoverPhase::OLD_LEAVE);
    ASSERT_EQ(pkt.GetHeader().src_type, NodeTypeCode::SKDC);
    ASSERT_EQ(pkt.GetHeader().dst_type, NodeTypeCode::SKDC);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 5: BuildAccept (Phase 3)
// ===========================================================================
bool test_build_accept() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = HandoverPacket::BuildAccept(
        7, 101, 0, 1, 2, 4, hmac_key, seq);

    ASSERT_EQ(pkt.GetPhase(), HandoverPhase::NEW_JOIN);
    ASSERT_EQ(pkt.GetBody().new_version, utils::u32(4));
    ASSERT_EQ(pkt.GetHeader().src_type,  NodeTypeCode::SKDC);
    ASSERT_EQ(pkt.GetHeader().dst_type,  NodeTypeCode::UAV);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 6: BuildRekey (Phase 4+5)
// ===========================================================================
bool test_build_rekey() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto old_rekey = HandoverPacket::BuildRekey(
        100, 0, 4, HandoverPhase::OLD_REKEY, hmac_key, seq);
    auto new_rekey = HandoverPacket::BuildRekey(
        101, 1, 5, HandoverPhase::NEW_REKEY, hmac_key, seq);

    ASSERT_EQ(old_rekey.GetPhase(), HandoverPhase::OLD_REKEY);
    ASSERT_EQ(new_rekey.GetPhase(), HandoverPhase::NEW_REKEY);
    ASSERT_EQ(old_rekey.GetHeader().dst_node_id,
              utils::u16(0xFFFF));

    std::cout << "  OLD_REKEY: " << old_rekey.Describe() << "\n";
    std::cout << "  NEW_REKEY: " << new_rekey.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 7: BuildComplete (Phase 6)
// ===========================================================================
bool test_build_complete() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = HandoverPacket::BuildComplete(
        7, 101, 0, 1, 2, hmac_key, seq);

    ASSERT_EQ(pkt.GetPhase(), HandoverPhase::COMPLETE);
    ASSERT_EQ(pkt.GetHeader().src_type, NodeTypeCode::UAV);
    ASSERT_EQ(pkt.GetHeader().dst_type, NodeTypeCode::SKDC);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 8: Full serialize/deserialize round-trip
// ===========================================================================
bool test_serialize_roundtrip() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = HandoverPacket::BuildInit(
        5, 100, 0, 2, 102, 2, hmac_key, seq);
    auto wire = pkt.Serialize();

    // 32+16+64 = 112 before HMAC
    ASSERT_EQ(wire.size(),
              BaseHeader::WIRE_SIZE +
              BaseHeader::NONCE_SIZE +
              HandoverBody::WIRE_SIZE);

    HmacSha256Util::AppendHmac(hmac_key, wire);
    // 112+32 = 144
    ASSERT_EQ(wire.size(), 144u);

    std::cout << "  Wire size: " << wire.size() << " bytes\n";

    auto pkt2 = HandoverPacket::Deserialize(wire, hmac_key);
    ASSERT_EQ(pkt2.GetPhase(),
              pkt.GetPhase());
    ASSERT_EQ(pkt2.GetBody().uav_id,
              pkt.GetBody().uav_id);
    ASSERT_EQ(pkt2.GetBody().old_cluster_id,
              pkt.GetBody().old_cluster_id);
    ASSERT_EQ(pkt2.GetBody().new_cluster_id,
              pkt.GetBody().new_cluster_id);
    ASSERT_EQ(pkt2.GetBody().ho_nonce,
              pkt.GetBody().ho_nonce);

    std::cout << "  Serialize/Deserialize: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: HMAC tamper detection
// ===========================================================================
bool test_tamper_detection() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = HandoverPacket::BuildInit(
        3, 100, 0, 1, 101, 0, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    auto tampered = wire;
    tampered[50] ^= 0xFF;
    ASSERT_THROWS(HandoverPacket::Deserialize(
        tampered, hmac_key));

    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(HandoverPacket::Deserialize(
        wire, wrong_key));

    std::cout << "  Tamper detection: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Fits within CONTROL_PACKET_SIZE (256 bytes)
// ===========================================================================
bool test_fits_in_control_size() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = HandoverPacket::BuildInit(
        7, 100, 0, 1, 101, 1, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  HANDOVER packet size: "
              << wire.size() << " bytes\n";
    ASSERT_TRUE(wire.size() <= 256u);
    std::cout << "  Fits within 256 bytes: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: Full handover flow simulation
// UAV 7 moves from cluster 0 (SKDC 100) to cluster 1 (SKDC 101)
// ===========================================================================
bool test_full_handover_flow() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Phase 1: UAV initiates
    auto init  = HandoverPacket::BuildInit(
        7, 100, 0, 1, 101, 1, hmac_key, seq);
    auto w1 = init.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w1);
    auto r1 = HandoverPacket::Deserialize(w1, hmac_key);
    ASSERT_EQ(r1.GetPhase(), HandoverPhase::INITIATED);

    // Phase 2: Old SKDC transfers to new SKDC
    auto transfer = HandoverPacket::BuildTransfer(
        7, 100, 101, 0, 1, 1, 0, hmac_key, seq);
    auto w2 = transfer.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w2);
    auto r2 = HandoverPacket::Deserialize(w2, hmac_key);
    ASSERT_EQ(r2.GetPhase(), HandoverPhase::OLD_LEAVE);

    // Phase 3: New SKDC accepts
    auto accept = HandoverPacket::BuildAccept(
        7, 101, 0, 1, 0, 5, hmac_key, seq);
    auto w3 = accept.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w3);
    auto r3 = HandoverPacket::Deserialize(w3, hmac_key);
    ASSERT_EQ(r3.GetPhase(), HandoverPhase::NEW_JOIN);

    // Phase 4: Old cluster rekeys
    auto rekey_old = HandoverPacket::BuildRekey(
        100, 0, 4, HandoverPhase::OLD_REKEY, hmac_key, seq);
    auto w4 = rekey_old.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w4);
    auto r4 = HandoverPacket::Deserialize(w4, hmac_key);
    ASSERT_EQ(r4.GetPhase(), HandoverPhase::OLD_REKEY);

    // Phase 5: New cluster rekeys
    auto rekey_new = HandoverPacket::BuildRekey(
        101, 1, 5, HandoverPhase::NEW_REKEY, hmac_key, seq);
    auto w5 = rekey_new.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w5);
    auto r5 = HandoverPacket::Deserialize(w5, hmac_key);
    ASSERT_EQ(r5.GetPhase(), HandoverPhase::NEW_REKEY);

    // Phase 6: UAV confirms complete
    auto complete = HandoverPacket::BuildComplete(
        7, 101, 0, 1, 0, hmac_key, seq);
    auto w6 = complete.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, w6);
    auto r6 = HandoverPacket::Deserialize(w6, hmac_key);
    ASSERT_EQ(r6.GetPhase(), HandoverPhase::COMPLETE);

    std::cout << "  Phase 1 INITIATED:  PASS\n";
    std::cout << "  Phase 2 OLD_LEAVE:  PASS\n";
    std::cout << "  Phase 3 NEW_JOIN:   PASS\n";
    std::cout << "  Phase 4 OLD_REKEY:  PASS\n";
    std::cout << "  Phase 5 NEW_REKEY:  PASS\n";
    std::cout << "  Phase 6 COMPLETE:   PASS\n";
    std::cout << "  Full handover flow: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 21 — HANDOVER Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_handover_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("body_wire_size",       test_body_wire_size);
    RunTest("body_roundtrip",       test_body_roundtrip);
    RunTest("build_init",           test_build_init);
    RunTest("build_transfer",       test_build_transfer);
    RunTest("build_accept",         test_build_accept);
    RunTest("build_rekey",          test_build_rekey);
    RunTest("build_complete",       test_build_complete);
    RunTest("serialize_roundtrip",  test_serialize_roundtrip);
    RunTest("tamper_detection",     test_tamper_detection);
    RunTest("fits_in_control_size", test_fits_in_control_size);
    RunTest("full_handover_flow",   test_full_handover_flow);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
