/**
 * tests/test_packet_manager.cc
 * Unit test for Phase 3 Module 23: Packet Serialization Manager
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_packet_manager.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-bigint.cc crypto/uav-aes.cc \
 *       crypto/uav-hmac.cc crypto/uav-replay.cc \
 *       headers/uav-packet-enums.cc \
 *       headers/uav-base-header.cc \
 *       headers/uav-auth-packet.cc \
 *       headers/uav-join-packet.cc \
 *       headers/uav-rekey-packet.cc \
 *       headers/uav-mtk-packet.cc \
 *       headers/uav-handover-packet.cc \
 *       headers/uav-data-packet.cc \
 *       headers/uav-packet-manager.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_packet_manager
 */

#include "headers/uav-packet-manager.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <atomic>

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

// Shared test keys
auto make_keys() {
    struct Keys {
        crypto::HmacKey   hmac;
        crypto::AesGcmKey tek;
    };
    return Keys{
        HmacSha256Util::GenerateKey(),
        AesGcm::GenerateKey()
    };
}

// ===========================================================================
// Test 1: Construction and accessors
// ===========================================================================
bool test_construction() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    ASSERT_EQ(mgr.GetNodeId(),    utils::u16(5));
    ASSERT_EQ(mgr.GetClusterId(), utils::u16(0));

    std::cout << "  NodeId=5, ClusterId=0: PASS\n";
    return true;
}

// ===========================================================================
// Test 2: PeekType
// ===========================================================================
bool test_peek_type() {
    auto keys = make_keys();
    SequenceCounter seq;

    // Build and serialize an AUTH packet
    auto pkt  = AuthPacket::BuildRequest(
        5, 100, 0, keys.hmac, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(keys.hmac, wire);

    ASSERT_EQ(PacketManager::PeekType(wire),
              PacketType::AUTH_PACKET);

    // Build a DATA packet
    utils::ByteBuffer pt = {0x01, 0x02};
    auto dpkt  = DataPacket::Build(
        0, 5, 100, 1, pt, keys.tek, keys.hmac, seq);
    auto dwire = dpkt.Serialize();
    HmacSha256Util::AppendHmac(keys.hmac, dwire);

    ASSERT_EQ(PacketManager::PeekType(dwire),
              PacketType::DATA_PACKET);

    // Unknown magic
    utils::ByteBuffer bad(32, 0x00);
    ASSERT_EQ(PacketManager::PeekType(bad),
              PacketType::UNKNOWN);

    std::cout << "  PeekType AUTH: PASS\n";
    std::cout << "  PeekType DATA: PASS\n";
    std::cout << "  PeekType unknown: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: SerializeAuth + Dispatch
// ===========================================================================
bool test_dispatch_auth() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    std::atomic<int> called{0};
    utils::u16 received_uav = 0;

    mgr.OnAuth([&](const AuthPacket& pkt) {
        ++called;
        received_uav = pkt.GetBody().uav_id;
    });

    SequenceCounter seq;
    auto pkt  = AuthPacket::BuildRequest(
        5, 100, 0, keys.hmac, seq);
    auto wire = mgr.SerializeAuth(pkt);

    ASSERT_TRUE(mgr.Dispatch(wire));
    ASSERT_EQ(called.load(), 1);
    ASSERT_EQ(received_uav, utils::u16(5));

    std::cout << "  AUTH dispatch: PASS\n";
    return true;
}

// ===========================================================================
// Test 4: SerializeJoin + Dispatch
// ===========================================================================
bool test_dispatch_join() {
    auto keys = make_keys();
    PacketManager mgr(7, 1, keys.hmac, keys.tek);

    std::atomic<int> called{0};
    utils::u16 recv_uav = 0;
    mgr.OnJoin([&](const JoinPacket& pkt) {
        ++called;
        recv_uav = pkt.GetBody().uav_id;
    });

    SequenceCounter seq;
    auto pkt  = JoinPacket::BuildRequest(
        7, 101, 1, 1, keys.hmac, seq);
    auto wire = mgr.SerializeJoin(pkt);

    ASSERT_TRUE(mgr.Dispatch(wire));
    ASSERT_EQ(called.load(), 1);
    ASSERT_EQ(recv_uav, utils::u16(7));

    std::cout << "  JOIN dispatch: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: SerializeRekey + Dispatch
// ===========================================================================
bool test_dispatch_rekey() {
    auto keys = make_keys();
    PacketManager mgr(100, 0, keys.hmac, keys.tek);

    std::atomic<int> called{0};
    RekeyReason recv_reason = RekeyReason::NONE;

    mgr.OnRekey([&](const RekeyPacket& pkt) {
        ++called;
        recv_reason = pkt.GetBody().reason;
    });

    SequenceCounter seq;
    BigInt mtk("123456789012345678901234567890");
    auto pkt  = RekeyPacket::Build(
        0, 100, 3, RekeyReason::LEAVE,
        mtk, keys.hmac, seq);
    auto wire = mgr.SerializeRekey(pkt);

    ASSERT_TRUE(mgr.Dispatch(wire));
    ASSERT_EQ(called.load(), 1);
    ASSERT_EQ(recv_reason, RekeyReason::LEAVE);

    std::cout << "  REKEY dispatch: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: SerializeData + Dispatch + Decrypt
// ===========================================================================
bool test_dispatch_data() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    std::atomic<int> called{0};
    utils::ByteBuffer received_pt;

    mgr.OnData([&](const DataPacket& pkt) {
        ++called;
        try { received_pt = pkt.Decrypt(keys.tek); }
        catch (...) {}
    });

    std::string msg = "sensor data";
    utils::ByteBuffer pt(msg.begin(), msg.end());

    SequenceCounter seq;
    auto pkt  = DataPacket::Build(
        0, 5, 100, 1, pt, keys.tek, keys.hmac, seq);
    auto wire = mgr.SerializeData(pkt);

    ASSERT_TRUE(mgr.Dispatch(wire));
    ASSERT_EQ(called.load(), 1);
    ASSERT_EQ(received_pt, pt);

    std::cout << "  DATA dispatch+decrypt: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: Tampered packet rejected
// ===========================================================================
bool test_tamper_rejected() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    SequenceCounter seq;
    auto pkt  = AuthPacket::BuildRequest(
        5, 100, 0, keys.hmac, seq);
    auto wire = mgr.SerializeAuth(pkt);

    // Tamper
    wire[30] ^= 0xFF;
    bool ok = mgr.Dispatch(wire);
    ASSERT_TRUE(!ok);

    ASSERT_EQ(mgr.GetStats().err_hmac.load(),
              utils::u64(1));

    std::cout << "  Tampered packet rejected: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: Stats tracking
// ===========================================================================
bool test_stats() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    mgr.OnAuth([](const AuthPacket&){});
    mgr.OnJoin([](const JoinPacket&){});
    mgr.OnData([&keys](const DataPacket& p){
        try { p.Decrypt(keys.tek); } catch(...) {}
    });

    SequenceCounter seq;

    // Send 2 AUTH
    for (int i = 0; i < 2; ++i) {
        auto p = AuthPacket::BuildRequest(
            5, 100, 0, keys.hmac, seq);
        mgr.Dispatch(mgr.SerializeAuth(p));
    }
    // Send 1 JOIN
    {
        auto p = JoinPacket::BuildRequest(
            5, 100, 0, 0, keys.hmac, seq);
        mgr.Dispatch(mgr.SerializeJoin(p));
    }
    // Send 3 DATA
    utils::ByteBuffer pt = {0x01};
    for (int i = 0; i < 3; ++i) {
        auto p = DataPacket::Build(
            0, 5, 100, static_cast<utils::u32>(i+1),
            pt, keys.tek, keys.hmac, seq);
        mgr.Dispatch(mgr.SerializeData(p));
    }

    const auto& s = mgr.GetStats();
    ASSERT_EQ(s.tx_total.load(),  utils::u64(6));
    ASSERT_EQ(s.rx_total.load(),  utils::u64(6));
    ASSERT_EQ(s.rx_auth.load(),   utils::u64(2));
    ASSERT_EQ(s.rx_join.load(),   utils::u64(1));
    ASSERT_EQ(s.rx_data.load(),   utils::u64(3));

    std::cout << "  " << s.Summary() << "\n";
    return true;
}

// ===========================================================================
// Test 9: MakeAuthRequest factory
// ===========================================================================
bool test_make_auth_request() {
    auto keys = make_keys();
    PacketManager mgr(7, 1, keys.hmac, keys.tek);

    std::atomic<int> called{0};
    utils::u16 recv_uav2 = 0;
    mgr.OnAuth([&](const AuthPacket& pkt) {
        ++called;
        recv_uav2 = pkt.GetBody().uav_id;
    });

    auto wire = mgr.MakeAuthRequest(101, 1);
    ASSERT_EQ(PacketManager::PeekType(wire),
              PacketType::AUTH_PACKET);
    ASSERT_TRUE(mgr.Dispatch(wire));
    ASSERT_EQ(called.load(), 1);
    ASSERT_EQ(recv_uav2, utils::u16(7));

    std::cout << "  MakeAuthRequest: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Key update changes HMAC
// ===========================================================================
bool test_key_update() {
    auto keys = make_keys();
    PacketManager mgr(5, 0, keys.hmac, keys.tek);

    SequenceCounter seq;
    auto pkt  = AuthPacket::BuildRequest(
        5, 100, 0, keys.hmac, seq);
    auto old_wire = mgr.SerializeAuth(pkt);

    // Update HMAC key
    auto new_hmac = HmacSha256Util::GenerateKey();
    mgr.UpdateHmacKey(new_hmac);

    // Old packet should fail with new key
    ASSERT_TRUE(!mgr.Dispatch(old_wire));

    // New packet with new key should succeed
    mgr.OnAuth([](const AuthPacket&){});
    auto pkt2     = AuthPacket::BuildRequest(
        5, 100, 0, new_hmac, seq);
    auto new_wire = mgr.SerializeAuth(pkt2);
    ASSERT_TRUE(mgr.Dispatch(new_wire));

    std::cout << "  Old key rejected after update: PASS\n";
    std::cout << "  New key accepted: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: 18 UAVs full dispatch simulation
// ===========================================================================
bool test_18_uav_simulation() {
    auto keys = make_keys();

    // SKDC manager
    PacketManager skdc(100, 0, keys.hmac, keys.tek);

    std::atomic<int> auth_count{0};
    std::atomic<int> join_count{0};
    std::atomic<int> data_count{0};

    skdc.OnAuth([&](const AuthPacket&)  { ++auth_count; });
    skdc.OnJoin([&](const JoinPacket&)  { ++join_count; });
    skdc.OnData([&](const DataPacket& p) {
        ++data_count;
        p.Decrypt(keys.tek);
    });

    // 18 UAV managers
    for (utils::u16 uav = 0; uav < 18; ++uav) {
        utils::u16 cluster = uav / 6;
        utils::u16 skdc_id = cluster + 100;
        utils::u32 idx     = uav % 6;

        PacketManager uav_mgr(uav, cluster, keys.hmac, keys.tek);

        // AUTH
        auto auth_wire = uav_mgr.MakeAuthRequest(skdc_id, cluster);
        skdc.Dispatch(auth_wire);

        // JOIN
        auto join_wire = uav_mgr.MakeJoinRequest(
            skdc_id, cluster, idx);
        skdc.Dispatch(join_wire);

        // DATA
        std::string msg = "UAV" + std::to_string(uav);
        utils::ByteBuffer pt(msg.begin(), msg.end());
        auto data_wire = uav_mgr.MakeDataPacket(skdc_id, 1, pt);
        skdc.Dispatch(data_wire);
    }

    ASSERT_EQ(auth_count.load(), 18);
    ASSERT_EQ(join_count.load(), 18);
    ASSERT_EQ(data_count.load(), 18);

    std::cout << "  Auth: " << auth_count
              << " Join: " << join_count
              << " Data: " << data_count << "\n";
    std::cout << "  18 UAVs simulation: PASS\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 23 — Packet Serialization Manager\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_packet_manager_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("construction",       test_construction);
    RunTest("peek_type",          test_peek_type);
    RunTest("dispatch_auth",      test_dispatch_auth);
    RunTest("dispatch_join",      test_dispatch_join);
    RunTest("dispatch_rekey",     test_dispatch_rekey);
    RunTest("dispatch_data",      test_dispatch_data);
    RunTest("tamper_rejected",    test_tamper_rejected);
    RunTest("stats",              test_stats);
    RunTest("make_auth_request",  test_make_auth_request);
    RunTest("key_update",         test_key_update);
    RunTest("18_uav_simulation",  test_18_uav_simulation);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
