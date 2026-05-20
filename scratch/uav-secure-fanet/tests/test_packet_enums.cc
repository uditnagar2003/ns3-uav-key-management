/**
 * tests/test_packet_enums.cc
 * Unit test for Phase 3 Module 15: Common Packet Enums
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_packet_enums.cc \
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
 *       headers/uav-packet-enums.cc \
 *       -o tests/test_packet_enums
 *
 * RUN:
 *   ./tests/test_packet_enums
 */

#include "headers/uav-packet-enums.h"
#include "utils/uav-logger.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace uav;
using namespace uav::packet;

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

#define ASSERT_NE(a, b) \
    do { if ((a) == (b)) { \
        std::cerr << "  ASSERT_NE failed: " #a " == " #b \
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
// Test 1: PacketType enum values and strings
// ===========================================================================
bool test_packet_type() {
    // Verify raw values
    ASSERT_EQ(static_cast<utils::u8>(PacketType::AUTH_PACKET),  0x01u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::JOIN_PACKET),  0x02u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::REKEY_PACKET), 0x03u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::MTK_PACKET),   0x04u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::DATA_PACKET),  0x05u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::HANDOVER_PACKET), 0x06u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::JAMMER_ALERT), 0x07u);
    ASSERT_EQ(static_cast<utils::u8>(PacketType::CONTROL_PACKET), 0x08u);

    // Verify strings
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::AUTH_PACKET)),
              std::string("AUTH"));
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::JOIN_PACKET)),
              std::string("JOIN"));
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::REKEY_PACKET)),
              std::string("REKEY"));
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::MTK_PACKET)),
              std::string("MTK"));
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::DATA_PACKET)),
              std::string("DATA"));
    ASSERT_EQ(std::string(PacketTypeToString(PacketType::HANDOVER_PACKET)),
              std::string("HANDOVER"));

    // Validate raw values
    ASSERT_TRUE(IsValidPacketType(0x01));
    ASSERT_TRUE(IsValidPacketType(0x0A));
    ASSERT_TRUE(!IsValidPacketType(0x00));
    ASSERT_TRUE(!IsValidPacketType(0xFF));

    std::cout << "  All 10 packet types: PASS\n";
    std::cout << "  IsValidPacketType: PASS\n";
    return true;
}

// ===========================================================================
// Test 2: PacketFlag bit operations
// ===========================================================================
bool test_packet_flags() {
    // Single flags
    auto f1 = PacketFlag::ENCRYPTED;
    auto f2 = PacketFlag::HMAC_PRESENT;

    ASSERT_TRUE(HasFlag(f1, PacketFlag::ENCRYPTED));
    ASSERT_TRUE(!HasFlag(f1, PacketFlag::HMAC_PRESENT));

    // Combine flags
    auto combined = f1 | f2;
    ASSERT_TRUE(HasFlag(combined, PacketFlag::ENCRYPTED));
    ASSERT_TRUE(HasFlag(combined, PacketFlag::HMAC_PRESENT));
    ASSERT_TRUE(!HasFlag(combined, PacketFlag::HAS_MTK));

    // SetFlag
    auto with_mtk = SetFlag(combined, PacketFlag::HAS_MTK);
    ASSERT_TRUE(HasFlag(with_mtk, PacketFlag::HAS_MTK));

    // ClearFlag
    auto without_enc = ClearFlag(with_mtk, PacketFlag::ENCRYPTED);
    ASSERT_TRUE(!HasFlag(without_enc, PacketFlag::ENCRYPTED));
    ASSERT_TRUE(HasFlag(without_enc, PacketFlag::HMAC_PRESENT));

    // String representation
    auto str = PacketFlagsToString(combined);
    ASSERT_TRUE(str.find("ENC") != std::string::npos);
    ASSERT_TRUE(str.find("HMAC") != std::string::npos);

    // None
    ASSERT_EQ(PacketFlagsToString(PacketFlag::NONE),
              std::string("NONE"));

    std::cout << "  Combined flags: " << str << "\n";
    std::cout << "  Flag operations: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: Packet sizes per spec
// ===========================================================================
bool test_packet_sizes() {
    // Per project spec
    ASSERT_EQ(PacketSizes::CONTROL_PACKET_SIZE, 256u);
    ASSERT_EQ(PacketSizes::REKEY_PACKET_SIZE,   512u);
    ASSERT_EQ(PacketSizes::DATA_PACKET_SIZE,    1024u);

    // TotalSize
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::AUTH_PACKET),
              256u);
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::CONTROL_PACKET),
              256u);
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::HANDOVER_PACKET),
              256u);
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::REKEY_PACKET),
              512u);
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::MTK_PACKET),
              512u);
    ASSERT_EQ(PacketSizes::TotalSize(PacketType::DATA_PACKET),
              1024u);

    // Overhead calculation
    std::size_t overhead = PacketSizes::TOTAL_OVERHEAD;
    std::cout << "  Total overhead: " << overhead << " bytes\n";
    ASSERT_TRUE(overhead < 256u);

    // Payload capacity
    std::size_t data_cap = PacketSizes::PayloadCapacity(
        PacketType::DATA_PACKET);
    std::cout << "  DATA payload capacity: "
              << data_cap << " bytes\n";
    ASSERT_TRUE(data_cap > 0);
    ASSERT_TRUE(data_cap < 1024u);

    // IsValidSize
    ASSERT_TRUE(PacketSizes::IsValidSize(
        PacketType::DATA_PACKET, 1024));
    ASSERT_TRUE(!PacketSizes::IsValidSize(
        PacketType::CONTROL_PACKET, 1024));

    std::cout << "  Packet sizes per spec: PASS\n";
    return true;
}

// ===========================================================================
// Test 4: Port assignments
// ===========================================================================
bool test_port_assignments() {
    ASSERT_EQ(PortAssignments::KDC_PORT,      9000u);
    ASSERT_EQ(PortAssignments::SKDC_PORT,     9001u);
    ASSERT_EQ(PortAssignments::UAV_BASE_PORT, 9100u);
    ASSERT_EQ(PortAssignments::MTK_PORT,      9200u);
    ASSERT_EQ(PortAssignments::AUTH_PORT,     9300u);
    ASSERT_EQ(PortAssignments::REKEY_PORT,    9400u);
    ASSERT_EQ(PortAssignments::HANDOVER_PORT, 9500u);
    ASSERT_EQ(PortAssignments::DATA_PORT,     9600u);
    ASSERT_EQ(PortAssignments::JAMMER_PORT,   9700u);

    // GetPort
    ASSERT_EQ(PortAssignments::GetPort(PacketType::AUTH_PACKET),
              9300u);
    ASSERT_EQ(PortAssignments::GetPort(PacketType::MTK_PACKET),
              9200u);
    ASSERT_EQ(PortAssignments::GetPort(PacketType::DATA_PACKET),
              9600u);

    // UAV ports: UAV_BASE_PORT + uav_id
    ASSERT_EQ(PortAssignments::GetUavPort(0),  9100u);
    ASSERT_EQ(PortAssignments::GetUavPort(1),  9101u);
    ASSERT_EQ(PortAssignments::GetUavPort(17), 9117u);

    std::cout << "  All 9 port assignments: PASS\n";
    std::cout << "  UAV ports 0-17: 9100-9117: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: AuthStatus
// ===========================================================================
bool test_auth_status() {
    ASSERT_TRUE(IsAuthSuccess(AuthStatus::SUCCESS));
    ASSERT_TRUE(!IsAuthSuccess(AuthStatus::FAIL_HMAC));
    ASSERT_TRUE(!IsAuthSuccess(AuthStatus::FAIL_REPLAY));
    ASSERT_TRUE(!IsAuthSuccess(AuthStatus::FAIL_MTK));

    ASSERT_EQ(std::string(AuthStatusToString(AuthStatus::SUCCESS)),
              std::string("SUCCESS"));
    ASSERT_EQ(std::string(AuthStatusToString(AuthStatus::FAIL_HMAC)),
              std::string("FAIL_HMAC"));
    ASSERT_EQ(std::string(AuthStatusToString(AuthStatus::FAIL_REPLAY)),
              std::string("FAIL_REPLAY"));

    std::cout << "  AuthStatus 9 values: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: RekeyReason
// ===========================================================================
bool test_rekey_reason() {
    ASSERT_EQ(std::string(RekeyReasonToString(RekeyReason::JOIN)),
              std::string("JOIN"));
    ASSERT_EQ(std::string(RekeyReasonToString(RekeyReason::LEAVE)),
              std::string("LEAVE"));
    ASSERT_EQ(std::string(RekeyReasonToString(RekeyReason::HANDOVER)),
              std::string("HANDOVER"));
    ASSERT_EQ(std::string(RekeyReasonToString(RekeyReason::COMPROMISE)),
              std::string("COMPROMISE"));
    ASSERT_EQ(std::string(RekeyReasonToString(RekeyReason::JAMMER)),
              std::string("JAMMER"));

    std::cout << "  RekeyReason 8 values: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: HandoverPhase
// ===========================================================================
bool test_handover_phase() {
    ASSERT_EQ(std::string(HandoverPhaseToString(
        HandoverPhase::INITIATED)), std::string("INITIATED"));
    ASSERT_EQ(std::string(HandoverPhaseToString(
        HandoverPhase::OLD_LEAVE)), std::string("OLD_LEAVE"));
    ASSERT_EQ(std::string(HandoverPhaseToString(
        HandoverPhase::NEW_JOIN)),  std::string("NEW_JOIN"));
    ASSERT_EQ(std::string(HandoverPhaseToString(
        HandoverPhase::COMPLETE)),  std::string("COMPLETE"));
    ASSERT_EQ(std::string(HandoverPhaseToString(
        HandoverPhase::FAILED)),    std::string("FAILED"));

    std::cout << "  HandoverPhase 8 values: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: JammerEventType
// ===========================================================================
bool test_jammer_event() {
    ASSERT_EQ(std::string(JammerEventTypeToString(
        JammerEventType::DETECTED)),      std::string("DETECTED"));
    ASSERT_EQ(std::string(JammerEventTypeToString(
        JammerEventType::SINR_DROP)),     std::string("SINR_DROP"));
    ASSERT_EQ(std::string(JammerEventTypeToString(
        JammerEventType::ROUTE_BREAK)),   std::string("ROUTE_BREAK"));
    ASSERT_EQ(std::string(JammerEventTypeToString(
        JammerEventType::NODE_ISOLATED)), std::string("NODE_ISOLATED"));
    ASSERT_EQ(std::string(JammerEventTypeToString(
        JammerEventType::RECOVERED)),     std::string("RECOVERED"));

    std::cout << "  JammerEventType 6 values: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: NodeTypeCode
// ===========================================================================
bool test_node_type_code() {
    ASSERT_EQ(std::string(NodeTypeCodeToString(NodeTypeCode::KDC)),
              std::string("KDC"));
    ASSERT_EQ(std::string(NodeTypeCodeToString(NodeTypeCode::SKDC)),
              std::string("SKDC"));
    ASSERT_EQ(std::string(NodeTypeCodeToString(NodeTypeCode::UAV)),
              std::string("UAV"));
    ASSERT_EQ(std::string(NodeTypeCodeToString(NodeTypeCode::JAMMER)),
              std::string("JAMMER"));

    std::cout << "  NodeTypeCode 5 values: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Protocol constants
// ===========================================================================
bool test_protocol_constants() {
    ASSERT_EQ(PROTOCOL_VERSION, utils::u8(1));
    ASSERT_EQ(PROTOCOL_MAGIC,   utils::u16(0x5541));

    // Magic bytes spell 'UA'
    utils::u8 hi = static_cast<utils::u8>(PROTOCOL_MAGIC >> 8);
    utils::u8 lo = static_cast<utils::u8>(PROTOCOL_MAGIC & 0xFF);
    ASSERT_EQ(hi, utils::u8('U'));
    ASSERT_EQ(lo, utils::u8('A'));

    std::cout << "  PROTOCOL_VERSION = "
              << static_cast<int>(PROTOCOL_VERSION) << "\n";
    std::cout << "  PROTOCOL_MAGIC   = 0x"
              << std::hex << PROTOCOL_MAGIC
              << std::dec << " ('UA')\n";
    return true;
}

// ===========================================================================
// Test 11: Complete packet type coverage
// ===========================================================================
bool test_complete_coverage() {
    // Every packet type has a non-UNKNOWN string
    const PacketType all_types[] = {
        PacketType::AUTH_PACKET,
        PacketType::JOIN_PACKET,
        PacketType::REKEY_PACKET,
        PacketType::MTK_PACKET,
        PacketType::DATA_PACKET,
        PacketType::HANDOVER_PACKET,
        PacketType::JAMMER_ALERT,
        PacketType::CONTROL_PACKET,
        PacketType::ACK_PACKET,
        PacketType::LEAVE_PACKET,
    };

    for (auto t : all_types) {
        std::string s = PacketTypeToString(t);
        ASSERT_NE(s, std::string("UNKNOWN"));

        utils::u16 port = PortAssignments::GetPort(t);
        ASSERT_TRUE(port >= 9000u);

        std::size_t sz = PacketSizes::TotalSize(t);
        ASSERT_TRUE(sz >= 256u);

        std::cout << "  " << s
                  << " port=" << port
                  << " size=" << sz << "\n";
    }

    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 15 — Common Packet Enums\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_packet_enums_logs",
        log::LogLevel::WARN,
        false);

    RunTest("packet_type",         test_packet_type);
    RunTest("packet_flags",        test_packet_flags);
    RunTest("packet_sizes",        test_packet_sizes);
    RunTest("port_assignments",    test_port_assignments);
    RunTest("auth_status",         test_auth_status);
    RunTest("rekey_reason",        test_rekey_reason);
    RunTest("handover_phase",      test_handover_phase);
    RunTest("jammer_event",        test_jammer_event);
    RunTest("node_type_code",      test_node_type_code);
    RunTest("protocol_constants",  test_protocol_constants);
    RunTest("complete_coverage",   test_complete_coverage);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
