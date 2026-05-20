/**
 * tests/test_base_header.cc
 * Unit test for Phase 3 Module 16: Base Packet Header
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_base_header.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-replay.cc \
 *       headers/uav-packet-enums.cc \
 *       headers/uav-base-header.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_base_header
 */

#include "headers/uav-base-header.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"
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

// ===========================================================================
// Test 1: Default construction
// ===========================================================================
bool test_default_construction() {
    BaseHeader h;
    ASSERT_EQ(h.magic,       BaseHeader::MAGIC);
    ASSERT_EQ(h.version,     PROTOCOL_VERSION);
    ASSERT_EQ(h.packet_type, PacketType::UNKNOWN);
    ASSERT_EQ(h.flags,       PacketFlag::NONE);
    ASSERT_EQ(h.priority,    PacketPriority::NORMAL);
    ASSERT_EQ(h.payload_len, utils::u16(0));
    ASSERT_EQ(h.cluster_id,  utils::u16(0));
    ASSERT_EQ(h.src_node_id, utils::u16(0));
    ASSERT_EQ(h.dst_node_id, utils::u16(0));

    std::cout << "  Default header: magic=0x"
              << std::hex << h.magic << std::dec
              << " version=" << (int)h.version << "\n";
    return true;
}

// ===========================================================================
// Test 2: Parameterized construction
// ===========================================================================
bool test_parameterized_construction() {
    BaseHeader h(
        PacketType::DATA_PACKET,
        2,    // cluster_id
        5,    // src (UAV 5)
        100,  // dst (SKDC)
        NodeTypeCode::UAV,
        NodeTypeCode::SKDC,
        PacketFlag::ENCRYPTED,
        PacketPriority::HIGH);

    ASSERT_EQ(h.magic,       BaseHeader::MAGIC);
    ASSERT_EQ(h.packet_type, PacketType::DATA_PACKET);
    ASSERT_EQ(h.cluster_id,  utils::u16(2));
    ASSERT_EQ(h.src_node_id, utils::u16(5));
    ASSERT_EQ(h.dst_node_id, utils::u16(100));
    ASSERT_EQ(h.src_type,    NodeTypeCode::UAV);
    ASSERT_EQ(h.dst_type,    NodeTypeCode::SKDC);
    ASSERT_EQ(h.priority,    PacketPriority::HIGH);
    ASSERT_TRUE(h.IsEncrypted());
    ASSERT_TRUE(h.timestamp_us > 0);

    std::cout << "  " << h.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 3: Wire format size
// ===========================================================================
bool test_wire_size() {
    ASSERT_EQ(BaseHeader::WIRE_SIZE,  32u);
    ASSERT_EQ(BaseHeader::NONCE_SIZE, 16u);

    BaseHeader h;
    auto wire = h.Serialize();
    ASSERT_EQ(wire.size(), 32u);

    std::cout << "  Wire size: " << wire.size() << " bytes\n";
    std::cout << "  Nonce size: " << BaseHeader::NONCE_SIZE
              << " bytes\n";
    std::cout << "  Total header+nonce: "
              << (BaseHeader::WIRE_SIZE + BaseHeader::NONCE_SIZE)
              << " bytes\n";
    return true;
}

// ===========================================================================
// Test 4: Serialize / Deserialize round-trip
// ===========================================================================
bool test_serialize_roundtrip() {
    BaseHeader h(
        PacketType::MTK_PACKET,
        1,    // cluster
        10,   // src SKDC
        255,  // dst broadcast
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        PacketFlag::HAS_MTK | PacketFlag::HMAC_PRESENT,
        PacketPriority::HIGH);

    h.payload_len  = 512;
    h.timestamp_us = 1234567890ULL;
    h.sequence_num = 42ULL;

    // Set nonce
    for (std::size_t i = 0; i < 16; ++i)
        h.nonce[i] = static_cast<utils::u8>(i + 1);

    // Serialize
    auto wire = h.Serialize();
    ASSERT_EQ(wire.size(), 32u);

    // Deserialize
    auto h2 = BaseHeader::Deserialize(wire);

    ASSERT_EQ(h2.magic,       h.magic);
    ASSERT_EQ(h2.version,     h.version);
    ASSERT_EQ(h2.packet_type, h.packet_type);
    ASSERT_EQ(h2.flags,       h.flags);
    ASSERT_EQ(h2.priority,    h.priority);
    ASSERT_EQ(h2.payload_len, h.payload_len);
    ASSERT_EQ(h2.cluster_id,  h.cluster_id);
    ASSERT_EQ(h2.src_node_id, h.src_node_id);
    ASSERT_EQ(h2.dst_node_id, h.dst_node_id);
    ASSERT_EQ(h2.src_type,    h.src_type);
    ASSERT_EQ(h2.dst_type,    h.dst_type);
    ASSERT_EQ(h2.timestamp_us,h.timestamp_us);
    ASSERT_EQ(h2.sequence_num,h.sequence_num);

    std::cout << "  Serialize round-trip: PASS\n";
    std::cout << "  " << h2.Describe() << "\n";
    return true;
}

// ===========================================================================
// Test 5: Nonce serialize/deserialize
// ===========================================================================
bool test_nonce_roundtrip() {
    BaseHeader h;
    auto nonce = OpenSSLRand::RandomNonce128();
    h.nonce = nonce;

    auto nonce_buf = h.SerializeNonce();
    ASSERT_EQ(nonce_buf.size(), 16u);

    BaseHeader h2;
    h2.DeserializeNonce(nonce_buf.data(), nonce_buf.size());
    ASSERT_EQ(h2.nonce, nonce);

    std::cout << "  Nonce: "
              << utils::StringUtils::BytesToHex(nonce.data(), 8)
              << "...\n";
    std::cout << "  Nonce round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: Replay token integration
// ===========================================================================
bool test_replay_token() {
    SequenceCounter seq;
    auto token = ReplayToken::Generate(seq.Next());

    BaseHeader h;
    h.ApplyReplayToken(token);

    ASSERT_EQ(h.timestamp_us, token.timestamp_us);
    ASSERT_EQ(h.sequence_num, token.sequence_num);
    ASSERT_EQ(h.nonce,        token.nonce);
    ASSERT_TRUE(h.IsReplayProtected());

    // Extract back
    auto token2 = h.ExtractReplayToken();
    ASSERT_EQ(token2.timestamp_us, token.timestamp_us);
    ASSERT_EQ(token2.sequence_num, token.sequence_num);
    ASSERT_EQ(token2.nonce,        token.nonce);

    std::cout << "  ApplyReplayToken: PASS\n";
    std::cout << "  ExtractReplayToken: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: Flag operations
// ===========================================================================
bool test_flag_operations() {
    BaseHeader h;

    h.SetEncrypted(true);
    ASSERT_TRUE(h.IsEncrypted());

    h.SetHasMtk(true);
    ASSERT_TRUE(h.HasMtk());
    ASSERT_TRUE(h.IsEncrypted());  // still set

    h.SetEncrypted(false);
    ASSERT_TRUE(!h.IsEncrypted());
    ASSERT_TRUE(h.HasMtk());       // still set

    h.SetHmacPresent(true);
    ASSERT_TRUE(h.HasHmac());

    h.SetReplayProtected(true);
    ASSERT_TRUE(h.IsReplayProtected());

    std::cout << "  Flags: "
              << PacketFlagsToString(h.flags) << "\n";
    return true;
}

// ===========================================================================
// Test 8: Validation
// ===========================================================================
bool test_validation() {
    // Valid header
    BaseHeader h(PacketType::AUTH_PACKET, 0, 1, 2,
                 NodeTypeCode::UAV, NodeTypeCode::SKDC);
    ASSERT_TRUE(h.IsValid());

    // Invalid magic
    BaseHeader bad;
    bad.magic = 0xDEAD;
    ASSERT_TRUE(!bad.IsValid());

    // Deserialize with bad magic throws
    utils::ByteBuffer buf(32, 0x00);
    ASSERT_THROWS(BaseHeader::Deserialize(buf));

    // Too short throws
    utils::ByteBuffer short_buf(10, 0x00);
    ASSERT_THROWS(BaseHeader::Deserialize(short_buf));

    std::cout << "  Valid header: PASS\n";
    std::cout << "  Bad magic rejected: PASS\n";
    std::cout << "  Short buffer throws: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: PacketBuilder
// ===========================================================================
bool test_packet_builder() {
    SequenceCounter seq;
    auto token = ReplayToken::Generate(seq.Next());

    auto builder = PacketBuilder(
        PacketType::JOIN_PACKET,
        0,   // cluster
        7,   // src UAV
        1,   // dst SKDC
        NodeTypeCode::UAV,
        NodeTypeCode::SKDC)
        .WithFlags(PacketFlag::REPLAY_PROTECTED |
                   PacketFlag::HMAC_PRESENT)
        .WithPriority(PacketPriority::HIGH)
        .WithReplayToken(token)
        .WithPayloadLen(256);

    const auto& h = builder.GetHeader();
    ASSERT_EQ(h.packet_type, PacketType::JOIN_PACKET);
    ASSERT_EQ(h.src_node_id, utils::u16(7));
    ASSERT_EQ(h.dst_node_id, utils::u16(1));
    ASSERT_EQ(h.payload_len, utils::u16(256));
    ASSERT_TRUE(h.IsReplayProtected());
    ASSERT_TRUE(h.HasHmac());

    // Build header bytes = 32 + 16 = 48
    auto bytes = builder.BuildHeaderBytes();
    ASSERT_EQ(bytes.size(), 48u);

    std::cout << "  Builder: " << h.Describe() << "\n";
    std::cout << "  Header bytes: " << bytes.size() << "\n";
    return true;
}

// ===========================================================================
// Test 10: Offset deserialization
// ===========================================================================
bool test_offset_deserialize() {
    BaseHeader h(PacketType::REKEY_PACKET, 1, 2, 3,
                 NodeTypeCode::SKDC, NodeTypeCode::UAV);
    h.payload_len  = 512;
    h.sequence_num = 99;

    // Prepend 10 bytes of garbage
    utils::ByteBuffer buf(10, 0xAA);
    h.SerializeTo(buf);
    ASSERT_EQ(buf.size(), 42u);  // 10 + 32

    // Deserialize with offset=10
    auto h2 = BaseHeader::Deserialize(buf, 10);
    ASSERT_EQ(h2.packet_type,  h.packet_type);
    ASSERT_EQ(h2.payload_len,  h.payload_len);
    ASSERT_EQ(h2.sequence_num, h.sequence_num);
    ASSERT_EQ(h2.cluster_id,   h.cluster_id);

    std::cout << "  Offset deserialization: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: All 8 packet types build valid headers
// ===========================================================================
bool test_all_packet_types() {
    const PacketType types[] = {
        PacketType::AUTH_PACKET,
        PacketType::JOIN_PACKET,
        PacketType::REKEY_PACKET,
        PacketType::MTK_PACKET,
        PacketType::DATA_PACKET,
        PacketType::HANDOVER_PACKET,
        PacketType::JAMMER_ALERT,
        PacketType::CONTROL_PACKET,
    };

    for (auto t : types) {
        BaseHeader h(t, 0, 1, 2,
                     NodeTypeCode::UAV,
                     NodeTypeCode::SKDC);
        ASSERT_TRUE(h.IsValid());

        auto wire = h.Serialize();
        ASSERT_EQ(wire.size(), 32u);

        auto h2 = BaseHeader::Deserialize(wire);
        ASSERT_EQ(h2.packet_type, t);

        std::cout << "  " << PacketTypeToString(t) << ": OK\n";
    }
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 16 — Base Packet Header\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_base_header_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("default_construction",     test_default_construction);
    RunTest("parameterized_construction",test_parameterized_construction);
    RunTest("wire_size",                test_wire_size);
    RunTest("serialize_roundtrip",      test_serialize_roundtrip);
    RunTest("nonce_roundtrip",          test_nonce_roundtrip);
    RunTest("replay_token",             test_replay_token);
    RunTest("flag_operations",          test_flag_operations);
    RunTest("validation",               test_validation);
    RunTest("packet_builder",           test_packet_builder);
    RunTest("offset_deserialize",       test_offset_deserialize);
    RunTest("all_packet_types",         test_all_packet_types);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
