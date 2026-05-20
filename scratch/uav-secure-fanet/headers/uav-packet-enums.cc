/**
 * headers/uav-packet-enums.cc
 */

#include "uav-packet-enums.h"

#include <sstream>

namespace uav {
namespace packet {

// ===========================================================================
// PacketType
// ===========================================================================

const char* PacketTypeToString(PacketType t) {
    switch (t) {
        case PacketType::UNKNOWN:         return "UNKNOWN";
        case PacketType::AUTH_PACKET:     return "AUTH";
        case PacketType::JOIN_PACKET:     return "JOIN";
        case PacketType::REKEY_PACKET:    return "REKEY";
        case PacketType::MTK_PACKET:      return "MTK";
        case PacketType::DATA_PACKET:     return "DATA";
        case PacketType::HANDOVER_PACKET: return "HANDOVER";
        case PacketType::JAMMER_ALERT:    return "JAMMER_ALERT";
        case PacketType::CONTROL_PACKET:  return "CONTROL";
        case PacketType::ACK_PACKET:      return "ACK";
        case PacketType::LEAVE_PACKET:    return "LEAVE";
    }
    return "UNKNOWN";
}

bool IsValidPacketType(utils::u8 raw) {
    return raw >= 0x01 && raw <= 0x0A;
}

// ===========================================================================
// PacketDirection
// ===========================================================================

const char* PacketDirectionToString(PacketDirection d) {
    switch (d) {
        case PacketDirection::UNKNOWN:      return "UNKNOWN";
        case PacketDirection::KDC_TO_SKDC:  return "KDC->SKDC";
        case PacketDirection::SKDC_TO_UAV:  return "SKDC->UAV";
        case PacketDirection::UAV_TO_SKDC:  return "UAV->SKDC";
        case PacketDirection::SKDC_TO_KDC:  return "SKDC->KDC";
        case PacketDirection::SKDC_TO_SKDC: return "SKDC->SKDC";
        case PacketDirection::BROADCAST:    return "BROADCAST";
        case PacketDirection::UNICAST:      return "UNICAST";
    }
    return "UNKNOWN";
}

// ===========================================================================
// PacketPriority
// ===========================================================================

const char* PacketPriorityToString(PacketPriority p) {
    switch (p) {
        case PacketPriority::LOW:      return "LOW";
        case PacketPriority::NORMAL:   return "NORMAL";
        case PacketPriority::HIGH:     return "HIGH";
        case PacketPriority::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

// ===========================================================================
// PacketFlag
// ===========================================================================

std::string PacketFlagsToString(PacketFlag flags) {
    utils::u8 raw = static_cast<utils::u8>(flags);
    if (raw == 0) return "NONE";

    std::ostringstream oss;
    bool first = true;

    auto append = [&](const char* name) {
        if (!first) oss << "|";
        oss << name;
        first = false;
    };

    if (HasFlag(flags, PacketFlag::ENCRYPTED))        append("ENC");
    if (HasFlag(flags, PacketFlag::HAS_MTK))          append("MTK");
    if (HasFlag(flags, PacketFlag::REPLAY_PROTECTED))  append("RPL");
    if (HasFlag(flags, PacketFlag::HMAC_PRESENT))     append("HMAC");
    if (HasFlag(flags, PacketFlag::FRAGMENTED))       append("FRAG");
    if (HasFlag(flags, PacketFlag::LAST_FRAGMENT))    append("LAST");
    if (HasFlag(flags, PacketFlag::ACK_REQUIRED))     append("ACK");
    if (HasFlag(flags, PacketFlag::EMERGENCY))        append("EMRG");

    return oss.str();
}

// ===========================================================================
// AuthStatus
// ===========================================================================

const char* AuthStatusToString(AuthStatus s) {
    switch (s) {
        case AuthStatus::UNKNOWN:      return "UNKNOWN";
        case AuthStatus::SUCCESS:      return "SUCCESS";
        case AuthStatus::FAIL_HMAC:    return "FAIL_HMAC";
        case AuthStatus::FAIL_REPLAY:  return "FAIL_REPLAY";
        case AuthStatus::FAIL_MTK:     return "FAIL_MTK";
        case AuthStatus::FAIL_EXPIRED: return "FAIL_EXPIRED";
        case AuthStatus::FAIL_UNKNOWN: return "FAIL_UNKNOWN";
        case AuthStatus::FAIL_REVOKED: return "FAIL_REVOKED";
        case AuthStatus::PENDING:      return "PENDING";
    }
    return "UNKNOWN";
}

bool IsAuthSuccess(AuthStatus s) {
    return s == AuthStatus::SUCCESS;
}

// ===========================================================================
// RekeyReason
// ===========================================================================

const char* RekeyReasonToString(RekeyReason r) {
    switch (r) {
        case RekeyReason::NONE:       return "NONE";
        case RekeyReason::JOIN:       return "JOIN";
        case RekeyReason::LEAVE:      return "LEAVE";
        case RekeyReason::HANDOVER:   return "HANDOVER";
        case RekeyReason::COMPROMISE: return "COMPROMISE";
        case RekeyReason::PERIODIC:   return "PERIODIC";
        case RekeyReason::JAMMER:     return "JAMMER";
        case RekeyReason::FORCED:     return "FORCED";
    }
    return "NONE";
}

// ===========================================================================
// HandoverPhase
// ===========================================================================

const char* HandoverPhaseToString(HandoverPhase p) {
    switch (p) {
        case HandoverPhase::NONE:       return "NONE";
        case HandoverPhase::INITIATED:  return "INITIATED";
        case HandoverPhase::OLD_LEAVE:  return "OLD_LEAVE";
        case HandoverPhase::NEW_JOIN:   return "NEW_JOIN";
        case HandoverPhase::OLD_REKEY:  return "OLD_REKEY";
        case HandoverPhase::NEW_REKEY:  return "NEW_REKEY";
        case HandoverPhase::COMPLETE:   return "COMPLETE";
        case HandoverPhase::FAILED:     return "FAILED";
    }
    return "NONE";
}

// ===========================================================================
// JammerEventType
// ===========================================================================

const char* JammerEventTypeToString(JammerEventType e) {
    switch (e) {
        case JammerEventType::NONE:         return "NONE";
        case JammerEventType::DETECTED:     return "DETECTED";
        case JammerEventType::SINR_DROP:    return "SINR_DROP";
        case JammerEventType::ROUTE_BREAK:  return "ROUTE_BREAK";
        case JammerEventType::NODE_ISOLATED:return "NODE_ISOLATED";
        case JammerEventType::RECOVERED:    return "RECOVERED";
    }
    return "NONE";
}

// ===========================================================================
// PacketSizes
// ===========================================================================

std::size_t PacketSizes::TotalSize(PacketType t) {
    switch (t) {
        case PacketType::AUTH_PACKET:
        case PacketType::JOIN_PACKET:
        case PacketType::LEAVE_PACKET:
        case PacketType::ACK_PACKET:
        case PacketType::JAMMER_ALERT:
        case PacketType::CONTROL_PACKET:
        case PacketType::HANDOVER_PACKET:
            return CONTROL_PACKET_SIZE;

        case PacketType::REKEY_PACKET:
        case PacketType::MTK_PACKET:
            return REKEY_PACKET_SIZE;

        case PacketType::DATA_PACKET:
            return DATA_PACKET_SIZE;

        default:
            return CONTROL_PACKET_SIZE;
    }
}

std::size_t PacketSizes::PayloadCapacity(PacketType t) {
    std::size_t total = TotalSize(t);
    if (total <= TOTAL_OVERHEAD) return 0;
    return total - TOTAL_OVERHEAD;
}

bool PacketSizes::IsValidSize(PacketType t, std::size_t size) {
    return size <= TotalSize(t);
}

// ===========================================================================
// PortAssignments
// ===========================================================================

utils::u16 PortAssignments::GetPort(PacketType t) {
    switch (t) {
        case PacketType::AUTH_PACKET:     return AUTH_PORT;
        case PacketType::JOIN_PACKET:     return SKDC_PORT;
        case PacketType::LEAVE_PACKET:    return SKDC_PORT;
        case PacketType::REKEY_PACKET:    return REKEY_PORT;
        case PacketType::MTK_PACKET:      return MTK_PORT;
        case PacketType::DATA_PACKET:     return DATA_PORT;
        case PacketType::HANDOVER_PACKET: return HANDOVER_PORT;
        case PacketType::JAMMER_ALERT:    return JAMMER_PORT;
        case PacketType::CONTROL_PACKET:  return KDC_PORT;
        case PacketType::ACK_PACKET:      return SKDC_PORT;
        default:                          return SKDC_PORT;
    }
}

utils::u16 PortAssignments::GetUavPort(utils::u32 uav_id) {
    return static_cast<utils::u16>(UAV_BASE_PORT + uav_id);
}

// ===========================================================================
// NodeTypeCode
// ===========================================================================

const char* NodeTypeCodeToString(NodeTypeCode n) {
    switch (n) {
        case NodeTypeCode::UNKNOWN: return "UNKNOWN";
        case NodeTypeCode::KDC:     return "KDC";
        case NodeTypeCode::SKDC:    return "SKDC";
        case NodeTypeCode::UAV:     return "UAV";
        case NodeTypeCode::JAMMER:  return "JAMMER";
    }
    return "UNKNOWN";
}

} // namespace packet
} // namespace uav
