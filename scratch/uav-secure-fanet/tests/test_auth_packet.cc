/**
 * tests/test_auth_packet.cc
 * Unit test for Phase 3 Module 18: AUTH Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_auth_packet.cc \
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
 *       headers/uav-auth-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_auth_packet
 */

#include "headers/uav-auth-packet.h"
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
// Test 1: AuthBody fixed wire size
// ===========================================================================
bool test_auth_body_wire_size() {
    ASSERT_EQ(AuthBody::WIRE_SIZE, 48u);

    AuthBody body;
    body.auth_type  = AuthType::REQUEST;
    body.uav_id     = 5;
    body.skdc_id    = 100;
    auto wire = body.Serialize();
    ASSERT_EQ(wire.size(), 48u);

    std::cout << "  AuthBody wire size: " << wire.size()
              << " bytes\n";
    return true;
}

// ===========================================================================
// Test 2: AuthBody serialize/deserialize round-trip
// ===========================================================================
bool test_auth_body_roundtrip() {
    AuthBody body;
    body.auth_type    = AuthType::RESPONSE;
    body.status       = AuthStatus::SUCCESS;
    body.uav_id       = 7;
    body.skdc_id      = 101;
    body.cluster_id   = 1;
    body.timestamp_us = 9876543210ULL;

    for (std::size_t i = 0; i < 16; ++i) {
        body.challenge[i] = static_cast<utils::u8>(i + 0x10);
        body.response[i]  = static_cast<utils::u8>(i + 0x20);
    }

    auto wire  = body.Serialize();
    auto body2 = AuthBody::Deserialize(wire);

    ASSERT_EQ(body2.auth_type,    body.auth_type);
    ASSERT_EQ(body2.status,       body.status);
    ASSERT_EQ(body2.uav_id,       body.uav_id);
    ASSERT_EQ(body2.skdc_id,      body.skdc_id);
    ASSERT_EQ(body2.cluster_id,   body.cluster_id);
    ASSERT_EQ(body2.timestamp_us, body.timestamp_us);
    ASSERT_EQ(body2.challenge,    body.challenge);
    ASSERT_EQ(body2.response,     body.response);

    std::cout << "  AuthBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: BuildRequest
// ===========================================================================
bool test_build_request() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt = AuthPacket::BuildRequest(
        5,    // uav_id
        100,  // skdc_id
        0,    // cluster_id
        hmac_key, seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_TRUE(pkt.IsRequest());
    ASSERT_TRUE(!pkt.IsResponse());
    ASSERT_EQ(pkt.GetBody().auth_type,  AuthType::REQUEST);
    ASSERT_EQ(pkt.GetBody().status,     AuthStatus::PENDING);
    ASSERT_EQ(pkt.GetBody().uav_id,     utils::u16(5));
    ASSERT_EQ(pkt.GetBody().skdc_id,    utils::u16(100));
    ASSERT_EQ(pkt.GetBody().cluster_id, utils::u16(0));
    ASSERT_EQ(pkt.GetHeader().packet_type,
              PacketType::AUTH_PACKET);
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(5));
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(100));
    ASSERT_TRUE(pkt.GetHeader().IsReplayProtected());
    ASSERT_TRUE(pkt.GetHeader().HasHmac());

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 4: BuildResponse
// ===========================================================================
bool test_build_response() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    std::array<utils::u8, 16> challenge{};
    for (std::size_t i = 0; i < 16; ++i)
        challenge[i] = static_cast<utils::u8>(i + 0xAA);

    auto pkt = AuthPacket::BuildResponse(
        5,      // uav_id
        100,    // skdc_id
        0,      // cluster_id
        AuthStatus::SUCCESS,
        challenge,
        hmac_key, seq);

    ASSERT_TRUE(pkt.IsResponse());
    ASSERT_TRUE(!pkt.IsRequest());
    ASSERT_TRUE(pkt.IsSuccess());
    ASSERT_EQ(pkt.GetBody().auth_type, AuthType::RESPONSE);
    ASSERT_EQ(pkt.GetBody().status,    AuthStatus::SUCCESS);
    ASSERT_EQ(pkt.GetBody().challenge, challenge);
    ASSERT_EQ(pkt.GetHeader().src_node_id, utils::u16(100));
    ASSERT_EQ(pkt.GetHeader().dst_node_id, utils::u16(5));

    std::cout << "  " << pkt.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 5: Serialize/Deserialize round-trip with HMAC
// ===========================================================================
bool test_serialize_roundtrip() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = AuthPacket::BuildRequest(
        3, 101, 1, hmac_key, seq);
    auto wire = pkt.Serialize();

    // Wire = 32+16+48 = 96 bytes before HMAC
    ASSERT_EQ(wire.size(),
              BaseHeader::WIRE_SIZE +
              BaseHeader::NONCE_SIZE +
              AuthBody::WIRE_SIZE);

    // Append HMAC
    HmacSha256Util::AppendHmac(hmac_key, wire);

    // Total = 96 + 32 = 128 bytes
    ASSERT_EQ(wire.size(), 128u);
    std::cout << "  Wire size: " << wire.size() << " bytes\n";

    // Deserialize
    auto pkt2 = AuthPacket::Deserialize(wire, hmac_key);

    ASSERT_EQ(pkt2.GetBody().auth_type,
              pkt.GetBody().auth_type);
    ASSERT_EQ(pkt2.GetBody().uav_id,
              pkt.GetBody().uav_id);
    ASSERT_EQ(pkt2.GetBody().skdc_id,
              pkt.GetBody().skdc_id);
    ASSERT_EQ(pkt2.GetBody().cluster_id,
              pkt.GetBody().cluster_id);
    ASSERT_EQ(pkt2.GetHeader().sequence_num,
              pkt.GetHeader().sequence_num);

    std::cout << "  Serialize/Deserialize: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: HMAC tamper detection
// ===========================================================================
bool test_tamper_detection() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = AuthPacket::BuildRequest(
        4, 100, 0, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    // Tamper with uav_id in body
    auto tampered = wire;
    tampered[48] ^= 0xFF;  // body starts at offset 48
    ASSERT_THROWS(AuthPacket::Deserialize(tampered, hmac_key));

    // Wrong key
    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(AuthPacket::Deserialize(wire, wrong_key));

    std::cout << "  Tampered packet rejected: PASS\n";
    std::cout << "  Wrong key rejected: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: All AuthStatus values
// ===========================================================================
bool test_auth_status_values() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    std::array<utils::u8, 16> ch{};

    const AuthStatus statuses[] = {
        AuthStatus::SUCCESS,
        AuthStatus::FAIL_HMAC,
        AuthStatus::FAIL_REPLAY,
        AuthStatus::FAIL_MTK,
        AuthStatus::FAIL_EXPIRED,
        AuthStatus::FAIL_UNKNOWN,
        AuthStatus::FAIL_REVOKED,
    };

    for (auto s : statuses) {
        auto pkt = AuthPacket::BuildResponse(
            1, 100, 0, s, ch, hmac_key, seq);
        ASSERT_EQ(pkt.GetBody().status, s);
        ASSERT_EQ(pkt.IsSuccess(),
                  IsAuthSuccess(s));

        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);
        auto pkt2 = AuthPacket::Deserialize(wire, hmac_key);
        ASSERT_EQ(pkt2.GetBody().status, s);

        std::cout << "  Status "
                  << AuthStatusToString(s) << ": PASS\n";
    }
    return true;
}

// ===========================================================================
// Test 8: Fits within CONTROL_PACKET_SIZE (256 bytes)
// ===========================================================================
bool test_fits_in_control_size() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto pkt  = AuthPacket::BuildRequest(
        5, 100, 0, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  Auth packet size: "
              << wire.size() << " bytes\n";
    std::cout << "  CONTROL_PACKET_SIZE: 256 bytes\n";

    ASSERT_TRUE(wire.size() <= 256u);
    std::cout << "  Fits within 256 bytes: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Request/Response flow simulation
// ===========================================================================
bool test_request_response_flow() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Step 1: UAV sends AUTH_REQUEST
    auto req = AuthPacket::BuildRequest(
        7, 101, 2, hmac_key, seq);
    auto req_wire = req.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, req_wire);

    // Step 2: SKDC receives and parses request
    auto req2 = AuthPacket::Deserialize(req_wire, hmac_key);
    ASSERT_TRUE(req2.IsRequest());
    ASSERT_EQ(req2.GetBody().uav_id, utils::u16(7));

    // Step 3: SKDC sends AUTH_RESPONSE with challenge
    std::array<utils::u8, 16> challenge{};
    OpenSSLRand::FillBytes(challenge.data(), 16);

    auto resp = AuthPacket::BuildResponse(
        req2.GetBody().uav_id,
        req2.GetBody().skdc_id,
        req2.GetBody().cluster_id,
        AuthStatus::SUCCESS,
        challenge,
        hmac_key, seq);

    auto resp_wire = resp.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, resp_wire);

    // Step 4: UAV receives response
    auto resp2 = AuthPacket::Deserialize(resp_wire, hmac_key);
    ASSERT_TRUE(resp2.IsResponse());
    ASSERT_TRUE(resp2.IsSuccess());
    ASSERT_EQ(resp2.GetBody().challenge, challenge);

    std::cout << "  Request:  " << req2.Describe()  << "\n";
    std::cout << "  Response: " << resp2.Describe() << "\n";
    std::cout << "  Full auth flow: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Replay token unique per packet
// ===========================================================================
bool test_replay_unique() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    auto p1 = AuthPacket::BuildRequest(
        1, 100, 0, hmac_key, seq);
    auto p2 = AuthPacket::BuildRequest(
        1, 100, 0, hmac_key, seq);

    ASSERT_TRUE(
        p1.GetHeader().sequence_num !=
        p2.GetHeader().sequence_num);
    ASSERT_TRUE(
        p1.GetHeader().nonce != p2.GetHeader().nonce);

    std::cout << "  Seq: "
              << p1.GetHeader().sequence_num << ", "
              << p2.GetHeader().sequence_num << "\n";
    std::cout << "  Unique replay tokens: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: 18 UAVs each send auth request
// ===========================================================================
bool test_18_uavs_auth() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    for (utils::u16 uav = 0; uav < 18; ++uav) {
        utils::u16 cluster = uav / 6;
        utils::u16 skdc    = cluster + 100;

        auto pkt  = AuthPacket::BuildRequest(
            uav, skdc, cluster, hmac_key, seq);
        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);

        auto pkt2 = AuthPacket::Deserialize(wire, hmac_key);
        ASSERT_EQ(pkt2.GetBody().uav_id,     uav);
        ASSERT_EQ(pkt2.GetBody().cluster_id, cluster);
    }

    std::cout << "  18 UAVs authenticated: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 18 — AUTH Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_auth_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("auth_body_wire_size",    test_auth_body_wire_size);
    RunTest("auth_body_roundtrip",    test_auth_body_roundtrip);
    RunTest("build_request",          test_build_request);
    RunTest("build_response",         test_build_response);
    RunTest("serialize_roundtrip",    test_serialize_roundtrip);
    RunTest("tamper_detection",       test_tamper_detection);
    RunTest("auth_status_values",     test_auth_status_values);
    RunTest("fits_in_control_size",   test_fits_in_control_size);
    RunTest("request_response_flow",  test_request_response_flow);
    RunTest("replay_unique",          test_replay_unique);
    RunTest("18_uavs_auth",           test_18_uavs_auth);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
