/**
 * tests/test_join_packet.cc
 * Unit test for Phase 3 Module 19: JOIN Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_join_packet.cc \
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
 *       headers/uav-join-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_join_packet
 */

#include "headers/uav-join-packet.h"
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
// Test 1: JoinBody fixed wire size
// ===========================================================================
bool test_join_body_wire_size() {
    ASSERT_EQ(JoinBody::WIRE_SIZE, 56u);

    JoinBody body;
    body.join_type = JoinType::REQUEST;
    body.uav_id    = 5;
    auto wire = body.Serialize();
    ASSERT_EQ(wire.size(), 56u);

    std::cout << "  JoinBody wire size: " << wire.size()
              << " bytes\n";
    return true;
}

// ===========================================================================
// Test 2: JoinBody serialize/deserialize round-trip
// ===========================================================================
bool test_join_body_roundtrip() {
    JoinBody body;
    body.join_type    = JoinType::ACCEPT;
    body.uav_id       = 7;
    body.skdc_id      = 101;
    body.cluster_id   = 1;
    body.uav_index    = 3;
    body.version      = 5;
    body.timestamp_us = 1234567890ULL;

    for (std::size_t i = 0; i < 16; ++i) {
        body.identity[i]   = static_cast<utils::u8>(i + 0x10);
        body.join_nonce[i] = static_cast<utils::u8>(i + 0x20);
    }

    auto wire  = body.Serialize();
    auto body2 = JoinBody::Deserialize(wire);

    ASSERT_EQ(body2.join_type,    body.join_type);
    ASSERT_EQ(body2.uav_id,       body.uav_id);
    ASSERT_EQ(body2.skdc_id,      body.skdc_id);
    ASSERT_EQ(body2.cluster_id,   body.cluster_id);
    ASSERT_EQ(body2.uav_index,    body.uav_index);
    ASSERT_EQ(body2.version,      body.version);
    ASSERT_EQ(body2.timestamp_us, body.timestamp_us);
    ASSERT_EQ(body2.identity,     body.identity);
    ASSERT_EQ(body2.join_nonce,   body.join_nonce);

    std::cout << "  JoinBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: BuildRequest
// ===========================================================================
bool test_build_request() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = JoinPacket::BuildRequest(
        5, 100, 0, 2, hmac_key, seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_TRUE(pkt.IsRequest());
    ASSERT_EQ(pkt.GetBody().join_type,  JoinType::REQUEST);
    ASSERT_EQ(pkt.GetBody().uav_id,     utils::u16(5));
    ASSERT_EQ(pkt.GetBody().skdc_id,    utils::u16(100));
    ASSERT_EQ(pkt.GetBody().cluster_id, utils::u16(0));
    ASSERT_EQ(pkt.GetBody().uav_index,  utils::u32(2));
    ASSERT_EQ(pkt.GetHeader().packet_type,
              PacketType::JOIN_PACKET);
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(5));
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(100));
    ASSERT_TRUE(pkt.GetHeader().IsReplayProtected());

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 4: BuildAccept
// ===========================================================================
bool test_build_accept() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = JoinPacket::BuildAccept(
        5, 100, 0, 2, 3, hmac_key, seq);

    ASSERT_TRUE(pkt.IsAccept());
    ASSERT_EQ(pkt.GetBody().version,  utils::u32(3));
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(100));
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(5));
    ASSERT_EQ(pkt.GetHeader().src_type, NodeTypeCode::SKDC);
    ASSERT_EQ(pkt.GetHeader().dst_type, NodeTypeCode::UAV);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 5: BuildReject
// ===========================================================================
bool test_build_reject() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = JoinPacket::BuildReject(
        5, 100, 0, hmac_key, seq);

    ASSERT_TRUE(pkt.IsReject());
    ASSERT_EQ(pkt.GetBody().join_type, JoinType::REJECT);

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 6: BuildNotify (broadcast)
// ===========================================================================
bool test_build_notify() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = JoinPacket::BuildNotify(
        5, 100, 0, 2, 4, hmac_key, seq);

    ASSERT_TRUE(pkt.IsNotify());
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(0xFFFF));
    ASSERT_EQ(pkt.GetBody().version, utils::u32(4));

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 7: Full serialize/deserialize round-trip
// ===========================================================================
bool test_serialize_roundtrip() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = JoinPacket::BuildRequest(
        3, 101, 1, 0, hmac_key, seq);
    auto wire = pkt.Serialize();

    // Wire = 32+16+56 = 104 before HMAC
    ASSERT_EQ(wire.size(),
              BaseHeader::WIRE_SIZE +
              BaseHeader::NONCE_SIZE +
              JoinBody::WIRE_SIZE);

    // Append HMAC → 104+32 = 136 total
    HmacSha256Util::AppendHmac(hmac_key, wire);
    ASSERT_EQ(wire.size(), 136u);

    std::cout << "  Wire size: " << wire.size() << " bytes\n";

    auto pkt2 = JoinPacket::Deserialize(wire, hmac_key);
    ASSERT_EQ(pkt2.GetBody().join_type,
              pkt.GetBody().join_type);
    ASSERT_EQ(pkt2.GetBody().uav_id,
              pkt.GetBody().uav_id);
    ASSERT_EQ(pkt2.GetBody().cluster_id,
              pkt.GetBody().cluster_id);
    ASSERT_EQ(pkt2.GetBody().uav_index,
              pkt.GetBody().uav_index);
    ASSERT_EQ(pkt2.GetBody().join_nonce,
              pkt.GetBody().join_nonce);

    std::cout << "  Serialize/Deserialize: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: HMAC tamper detection
// ===========================================================================
bool test_tamper_detection() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = JoinPacket::BuildRequest(
        4, 100, 0, 1, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    // Tamper with body
    auto tampered = wire;
    tampered[50] ^= 0xFF;
    ASSERT_THROWS(JoinPacket::Deserialize(tampered, hmac_key));

    // Wrong key
    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(JoinPacket::Deserialize(wire, wrong_key));

    std::cout << "  Tamper detection: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Fits in CONTROL_PACKET_SIZE (256 bytes)
// ===========================================================================
bool test_fits_in_control_size() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = JoinPacket::BuildNotify(
        5, 100, 0, 2, 3, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  JOIN packet size: " << wire.size()
              << " bytes\n";
    ASSERT_TRUE(wire.size() <= 256u);
    std::cout << "  Fits within 256 bytes: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Full join flow simulation
// (UAV→SKDC request, SKDC→UAV accept, SKDC→ALL notify)
// ===========================================================================
bool test_full_join_flow() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Step 1: UAV 7 requests to join cluster 1 (SKDC 101)
    auto req  = JoinPacket::BuildRequest(7, 101, 1, 1, hmac_key, seq);
    auto req_wire = req.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, req_wire);

    auto req2 = JoinPacket::Deserialize(req_wire, hmac_key);
    ASSERT_TRUE(req2.IsRequest());
    ASSERT_EQ(req2.GetBody().uav_id, utils::u16(7));

    // Step 2: SKDC accepts
    auto acc  = JoinPacket::BuildAccept(7, 101, 1, 1, 3, hmac_key, seq);
    auto acc_wire = acc.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, acc_wire);

    auto acc2 = JoinPacket::Deserialize(acc_wire, hmac_key);
    ASSERT_TRUE(acc2.IsAccept());
    ASSERT_EQ(acc2.GetBody().version, utils::u32(3));

    // Step 3: SKDC notifies cluster
    auto ntf  = JoinPacket::BuildNotify(7, 101, 1, 1, 3, hmac_key, seq);
    auto ntf_wire = ntf.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, ntf_wire);

    auto ntf2 = JoinPacket::Deserialize(ntf_wire, hmac_key);
    ASSERT_TRUE(ntf2.IsNotify());
    ASSERT_EQ(ntf2.GetHeader().dst_node_id, utils::u16(0xFFFF));

    std::cout << "  Request : " << req2.Describe() << "\n";
    std::cout << "  Accept  : " << acc2.Describe() << "\n";
    std::cout << "  Notify  : " << ntf2.Describe() << "\n";
    std::cout << "  Full join flow: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: 18 UAVs each send join request
// ===========================================================================
bool test_18_uavs_join() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    for (utils::u16 uav = 0; uav < 18; ++uav) {
        utils::u16 cluster = uav / 6;
        utils::u16 skdc    = cluster + 100;
        utils::u32 index   = uav % 6;

        auto pkt  = JoinPacket::BuildRequest(
            uav, skdc, cluster, index, hmac_key, seq);
        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);

        auto pkt2 = JoinPacket::Deserialize(wire, hmac_key);
        ASSERT_EQ(pkt2.GetBody().uav_id,     uav);
        ASSERT_EQ(pkt2.GetBody().cluster_id, cluster);
        ASSERT_EQ(pkt2.GetBody().uav_index,  index);
    }

    std::cout << "  18 UAVs join requests: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 19 — JOIN Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_join_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("join_body_wire_size",   test_join_body_wire_size);
    RunTest("join_body_roundtrip",   test_join_body_roundtrip);
    RunTest("build_request",         test_build_request);
    RunTest("build_accept",          test_build_accept);
    RunTest("build_reject",          test_build_reject);
    RunTest("build_notify",          test_build_notify);
    RunTest("serialize_roundtrip",   test_serialize_roundtrip);
    RunTest("tamper_detection",      test_tamper_detection);
    RunTest("fits_in_control_size",  test_fits_in_control_size);
    RunTest("full_join_flow",        test_full_join_flow);
    RunTest("18_uavs_join",          test_18_uavs_join);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
