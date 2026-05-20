
/**
 * headers/uav-packet-enums.h
 *
 * Common enumerations and constants for all UAV Secure FANET packets.
 *
 * PACKET TYPES (per project spec):
 *   AUTH_PACKET      - Authentication request/response
 *   JOIN_PACKET      - UAV join multicast group request
 *   REKEY_PACKET     - Key update broadcast from SKDC
 *   MTK_PACKET       - MT_K distribution from SKDC to UAVs
 *   DATA_PACKET      - Encrypted UAV payload data
 *   HANDOVER_PACKET  - UAV cluster handover notification
 *   JAMMER_ALERT_PACKET - Jammer detection alert
 *   CONTROL_PACKET   - General control messages
 *
 * PACKET SIZES (per project spec):
 *   Control packets  = 256 bytes
 *   Rekey packets    = 512 bytes
 *   Data packets     = 1024 bytes
 *
 * WIRE FORMAT:
 *   [HEADER][MT_K][AES_PAYLOAD][HMAC]
 *   Header = plaintext, fixed-size, serializable
 *
 * VERSION:
 *   Protocol version = 1
 */

#ifndef UAV_PACKET_ENUMS_H
#define UAV_PACKET_ENUMS_H

#include "uav-types.h"

#include <string>
#include <cstddef>

namespace uav {
namespace packet {

// ===========================================================================
// Protocol version
// ===========================================================================
constexpr utils::u8  PROTOCOL_VERSION   = 1;
constexpr utils::u16 PROTOCOL_MAGIC     = 0x5541; // 'UA'

// ===========================================================================
// PacketType — identifies packet purpose
// 1 byte on wire
// ===========================================================================
enum class PacketType : utils::u8 {
    UNKNOWN         = 0x00,
    AUTH_PACKET     = 0x01,   // Authentication
    JOIN_PACKET     = 0x02,   // Multicast group join
    REKEY_PACKET    = 0x03,   // Key update broadcast
    MTK_PACKET      = 0x04,   // MT_K distribution
    DATA_PACKET     = 0x05,   // Encrypted payload
    HANDOVER_PACKET = 0x06,   // Cluster handover
    JAMMER_ALERT    = 0x07,   // Jammer detection
    CONTROL_PACKET  = 0x08,   // General control
    ACK_PACKET      = 0x09,   // Acknowledgement
    LEAVE_PACKET    = 0x0A,   // Multicast group leave
};

/// Human-readable string for PacketType.
const char* PacketTypeToString(PacketType t);

/// Returns true if the type is a valid defined type.
bool IsValidPacketType(utils::u8 raw);

// ===========================================================================
// PacketDirection — which way a packet flows
// ===========================================================================
enum class PacketDirection : utils::u8 {
    UNKNOWN         = 0x00,
    KDC_TO_SKDC     = 0x01,   // KDC → SKDC (wired backbone)
    SKDC_TO_UAV     = 0x02,   // SKDC → UAV cluster (wireless)
    UAV_TO_SKDC     = 0x03,   // UAV → SKDC (wireless)
    SKDC_TO_KDC     = 0x04,   // SKDC → KDC (wired backbone)
    SKDC_TO_SKDC    = 0x05,   // SKDC → SKDC (via KDC backbone)
    BROADCAST       = 0x06,   // One-to-many
    UNICAST         = 0x07,   // One-to-one
};

const char* PacketDirectionToString(PacketDirection d);

// ===========================================================================
// PacketPriority — QoS priority level
// ===========================================================================
enum class PacketPriority : utils::u8 {
    LOW             = 0x00,   // Data packets
    NORMAL          = 0x01,   // Join/Leave
    HIGH            = 0x02,   // Rekey/MTK
    CRITICAL        = 0x03,   // Auth/Handover/Jammer
};

const char* PacketPriorityToString(PacketPriority p);

// ===========================================================================
// PacketFlag — bit flags in header flags field (1 byte)
// ===========================================================================
enum class PacketFlag : utils::u8 {
    NONE            = 0x00,
    ENCRYPTED       = 0x01,   // AES payload present
    HAS_MTK         = 0x02,   // MT_K field present
    REPLAY_PROTECTED= 0x04,   // Replay token present
    HMAC_PRESENT    = 0x08,   // HMAC appended
    FRAGMENTED      = 0x10,   // Part of fragmented sequence
    LAST_FRAGMENT   = 0x20,   // Last fragment
    ACK_REQUIRED    = 0x40,   // Sender expects ACK
    EMERGENCY       = 0x80,   // Emergency/jammer alert
};

/// Bitwise OR of flags
inline PacketFlag operator|(PacketFlag a, PacketFlag b) {
    return static_cast<PacketFlag>(
        static_cast<utils::u8>(a) |
        static_cast<utils::u8>(b));
}

/// Bitwise AND test
inline bool HasFlag(PacketFlag flags, PacketFlag test) {
    return (static_cast<utils::u8>(flags) &
            static_cast<utils::u8>(test)) != 0;
}

/// Set a flag
inline PacketFlag SetFlag(PacketFlag flags, PacketFlag f) {
    return flags | f;
}

/// Clear a flag
inline PacketFlag ClearFlag(PacketFlag flags, PacketFlag f) {
    return static_cast<PacketFlag>(
        static_cast<utils::u8>(flags) &
        ~static_cast<utils::u8>(f));
}

std::string PacketFlagsToString(PacketFlag flags);

// ===========================================================================
// AuthStatus — result of authentication check
// ===========================================================================
enum class AuthStatus : utils::u8 {
    UNKNOWN         = 0x00,
    SUCCESS         = 0x01,   // Authentication passed
    FAIL_HMAC       = 0x02,   // HMAC verification failed
    FAIL_REPLAY     = 0x03,   // Replay attack detected
    FAIL_MTK        = 0x04,   // MT_K decryption failed
    FAIL_EXPIRED    = 0x05,   // Token expired
    FAIL_UNKNOWN    = 0x06,   // Unknown sender
    FAIL_REVOKED    = 0x07,   // Sender revoked
    PENDING         = 0x08,   // Awaiting response
};

const char* AuthStatusToString(AuthStatus s);
bool IsAuthSuccess(AuthStatus s);

// ===========================================================================
// RekeyReason — why a rekey event was triggered
// ===========================================================================
enum class RekeyReason : utils::u8 {
    NONE            = 0x00,
    JOIN            = 0x01,   // New UAV joined (Algorithm 3)
    LEAVE           = 0x02,   // UAV left (Algorithm 5)
    HANDOVER        = 0x03,   // UAV moved to new cluster
    COMPROMISE      = 0x04,   // Node compromised
    PERIODIC        = 0x05,   // Scheduled periodic rekey
    JAMMER          = 0x06,   // Jammer detected
    FORCED          = 0x07,   // KDC-forced rekey
};

const char* RekeyReasonToString(RekeyReason r);

// ===========================================================================
// HandoverPhase — stage of handover process
// ===========================================================================
enum class HandoverPhase : utils::u8 {
    NONE            = 0x00,
    INITIATED       = 0x01,   // UAV requests handover
    OLD_LEAVE       = 0x02,   // Old SKDC processes leave
    NEW_JOIN        = 0x03,   // New SKDC processes join
    OLD_REKEY       = 0x04,   // Old cluster rekeyed
    NEW_REKEY       = 0x05,   // New cluster rekeyed
    COMPLETE        = 0x06,   // Handover done
    FAILED          = 0x07,   // Handover failed
};

const char* HandoverPhaseToString(HandoverPhase p);

// ===========================================================================
// JammerEventType — jammer-related events
// ===========================================================================
enum class JammerEventType : utils::u8 {
    NONE            = 0x00,
    DETECTED        = 0x01,   // Jammer signal detected
    SINR_DROP       = 0x02,   // SINR below threshold
    ROUTE_BREAK     = 0x03,   // Routing path broken
    NODE_ISOLATED   = 0x04,   // Node cut off from cluster
    RECOVERED       = 0x05,   // Connection restored
};

const char* JammerEventTypeToString(JammerEventType e);

// ===========================================================================
// PacketSizeConstants — wire sizes per project spec
// ===========================================================================
struct PacketSizes {
    // Fixed payload capacities (bytes)
    static constexpr std::size_t CONTROL_PACKET_SIZE  = 256;
    static constexpr std::size_t REKEY_PACKET_SIZE    = 512;
    static constexpr std::size_t DATA_PACKET_SIZE     = 1024;

    // Header fixed size
    static constexpr std::size_t BASE_HEADER_SIZE     = 32;

    // Crypto overhead (from Modules 9, 10, 11)
    static constexpr std::size_t AES_GCM_OVERHEAD     = 28;  // IV+tag
    static constexpr std::size_t HMAC_SIZE            = 32;
    static constexpr std::size_t REPLAY_TOKEN_SIZE    = 32;
    static constexpr std::size_t MTK_FIELD_SIZE       = 64;  // stub

    // Total per-packet overhead
    static constexpr std::size_t TOTAL_OVERHEAD =
        BASE_HEADER_SIZE  +
        AES_GCM_OVERHEAD  +
        HMAC_SIZE         +
        REPLAY_TOKEN_SIZE;

    /// Returns expected total packet size for a given type.
    static std::size_t TotalSize(PacketType t);

    /// Returns payload capacity for a given type.
    static std::size_t PayloadCapacity(PacketType t);

    /// Returns true if size is valid for given type.
    static bool IsValidSize(PacketType t, std::size_t size);
};

// ===========================================================================
// PortAssignments — UDP ports per project spec
// ===========================================================================
struct PortAssignments {
    static constexpr utils::u16 KDC_PORT       = 9000;
    static constexpr utils::u16 SKDC_PORT      = 9001;
    static constexpr utils::u16 UAV_BASE_PORT  = 9100;
    static constexpr utils::u16 MTK_PORT       = 9200;
    static constexpr utils::u16 AUTH_PORT      = 9300;
    static constexpr utils::u16 REKEY_PORT     = 9400;
    static constexpr utils::u16 HANDOVER_PORT  = 9500;
    static constexpr utils::u16 DATA_PORT      = 9600;
    static constexpr utils::u16 JAMMER_PORT    = 9700;

    /// Returns port for a given packet type.
    static utils::u16 GetPort(PacketType t);

    /// Returns UAV-specific port (base + uav_id).
    static utils::u16 GetUavPort(utils::u32 uav_id);
};

// ===========================================================================
// NodeTypeCode — identifies node role in packet header
// ===========================================================================
enum class NodeTypeCode : utils::u8 {
    UNKNOWN   = 0x00,
    KDC       = 0x01,
    SKDC      = 0x02,
    UAV       = 0x03,
    JAMMER    = 0x04,   // used in simulation metadata
};

const char* NodeTypeCodeToString(NodeTypeCode n);

} // namespace packet
} // namespace uav

#endif // UAV_PACKET_ENUMS_H
