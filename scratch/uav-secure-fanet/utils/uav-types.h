/**
 * utils/uav-types.h
 * Project-wide type aliases, identifier types, and core enumerations.
 *
 * Scope: HEADER-ONLY. No translation unit required.
 *
 * Used by: ALL future modules (3–65).
 *
 * Design notes:
 *   - Strong typedefs for IDs prevent accidental int-mixing
 *     (e.g. passing a ClusterId where a UavId is expected).
 *   - All integer widths fixed-size for serialisation determinism.
 *   - Byte buffer aliased to std::vector<uint8_t> — used everywhere
 *     for crypto payloads, packet bodies, HMACs, nonces, etc.
 */

#ifndef UAV_TYPES_H
#define UAV_TYPES_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <chrono>
#include <ostream>

namespace uav {
namespace utils {

// ===========================================================================
// Fixed-width integer aliases (used throughout the project)
// ===========================================================================
using u8   = std::uint8_t;
using u16  = std::uint16_t;
using u32  = std::uint32_t;
using u64  = std::uint64_t;
using i8   = std::int8_t;
using i16  = std::int16_t;
using i32  = std::int32_t;
using i64  = std::int64_t;

// ===========================================================================
// Byte buffer — universal binary container
// ===========================================================================
using ByteBuffer = std::vector<u8>;

// ===========================================================================
// Fixed-size cryptographic buffers
// ===========================================================================
using Aes256Key   = std::array<u8, 32>;   // 256-bit AES key
using AesIv       = std::array<u8, 16>;   // 128-bit AES IV (CBC/GCM 12 used separately)
using HmacSha256  = std::array<u8, 32>;   // 256-bit HMAC-SHA256 output
using Nonce128    = std::array<u8, 16>;   // 128-bit nonce
using Sha256Hash  = std::array<u8, 32>;   // 256-bit SHA-256 digest

// ===========================================================================
// Strong identifier types
// Implemented as wrapper structs to avoid implicit int conversions
// while remaining trivially-copyable and POD-like.
// ===========================================================================

#define UAV_DEFINE_STRONG_ID(NAME, UNDERLYING)                                 \
    struct NAME {                                                              \
        UNDERLYING value;                                                      \
        constexpr NAME() : value(0) {}                                         \
        constexpr explicit NAME(UNDERLYING v) : value(v) {}                    \
        constexpr bool operator==(const NAME& o) const { return value == o.value; } \
        constexpr bool operator!=(const NAME& o) const { return value != o.value; } \
        constexpr bool operator< (const NAME& o) const { return value <  o.value; } \
        constexpr bool operator> (const NAME& o) const { return value >  o.value; } \
        constexpr bool operator<=(const NAME& o) const { return value <= o.value; } \
        constexpr bool operator>=(const NAME& o) const { return value >= o.value; } \
    };                                                                         \
    inline std::ostream& operator<<(std::ostream& os, const NAME& id) {        \
        return os << #NAME << "(" << id.value << ")";                          \
    }

UAV_DEFINE_STRONG_ID(NodeId,      u32)  // NS-3 node id
UAV_DEFINE_STRONG_ID(UavId,       u32)  // UAV logical id
UAV_DEFINE_STRONG_ID(ClusterId,   u32)  // 0..NUM_CLUSTERS-1
UAV_DEFINE_STRONG_ID(SkdcId,      u32)  // 0..NUM_SKDCS-1
UAV_DEFINE_STRONG_ID(MulticastGroupId, u32)
UAV_DEFINE_STRONG_ID(KeyVersion,  u32)  // monotonic key version counter
UAV_DEFINE_STRONG_ID(SequenceNum, u64)  // packet sequence number

// ===========================================================================
// Role enumeration — every node has exactly one
// ===========================================================================
enum class NodeRole : u8 {
    KDC        = 0,
    SKDC       = 1,
    UAV        = 2,
    JAMMER     = 3,
    UNKNOWN    = 255
};

const char* NodeRoleToString(NodeRole r);

// ===========================================================================
// UAV operational state
// ===========================================================================
enum class UavState : u8 {
    UNREGISTERED   = 0,
    AUTHENTICATING = 1,
    ACTIVE         = 2,
    HANDOVER       = 3,
    COMPROMISED    = 4,
    DISCONNECTED   = 5,
    LEAVING        = 6
};

const char* UavStateToString(UavState s);

// ===========================================================================
// Security event types — used by event logging and metrics
// ===========================================================================
enum class SecurityEventType : u8 {
    JOIN              = 0,
    LEAVE             = 1,
    REKEY             = 2,
    HANDOVER_START    = 3,
    HANDOVER_COMPLETE = 4,
    COMPROMISE        = 5,
    JAMMER_DETECTED   = 6,
    AUTH_FAILURE      = 7,
    REPLAY_DETECTED   = 8,
    HMAC_FAILURE      = 9,
    TEK_ROTATION      = 10
};

const char* SecurityEventTypeToString(SecurityEventType e);

// ===========================================================================
// Time aliases — high-precision steady clock for benchmarking
// ===========================================================================
using SteadyClock  = std::chrono::steady_clock;
using TimePoint    = SteadyClock::time_point;
using Microseconds = std::chrono::microseconds;
using Milliseconds = std::chrono::milliseconds;
using Seconds      = std::chrono::seconds;

// ===========================================================================
// 3D position vector (NS-3 uses ns3::Vector but we keep a project-local
// alias for places that should not depend on NS-3 — e.g. crypto, utils,
// pure unit tests).
// ===========================================================================
struct Vec3 {
    double x;
    double y;
    double z;

    constexpr Vec3() : x(0), y(0), z(0) {}
    constexpr Vec3(double xx, double yy, double zz) : x(xx), y(yy), z(zz) {}

    constexpr bool operator==(const Vec3& o) const {
        return x == o.x && y == o.y && z == o.z;
    }
};

inline std::ostream& operator<<(std::ostream& os, const Vec3& v) {
    return os << "(" << v.x << "," << v.y << "," << v.z << ")";
}

// ===========================================================================
// Return-status enumeration — simple status codes for non-throwing APIs.
// Exceptions are used for fatal errors; Status is used for recoverable flow.
// ===========================================================================
enum class Status : u8 {
    OK                  = 0,
    INVALID_ARGUMENT    = 1,
    NOT_FOUND           = 2,
    ALREADY_EXISTS      = 3,
    OUT_OF_RANGE        = 4,
    PERMISSION_DENIED   = 5,
    UNAUTHENTICATED     = 6,
    REPLAY_DETECTED     = 7,
    HMAC_INVALID        = 8,
    DECRYPT_FAILED      = 9,
    SERIALIZATION_ERROR = 10,
    INTERNAL_ERROR      = 11
};

const char* StatusToString(Status s);

} // namespace utils
} // namespace uav

// ===========================================================================
// std::hash specialisations for strong-ID types (needed for unordered_map)
// ===========================================================================
namespace std {

#define UAV_HASH_FOR_STRONG_ID(NAME)                                           \
    template<> struct hash<::uav::utils::NAME> {                               \
        std::size_t operator()(const ::uav::utils::NAME& id) const noexcept {  \
            return std::hash<decltype(id.value)>{}(id.value);                  \
        }                                                                      \
    };

UAV_HASH_FOR_STRONG_ID(NodeId)
UAV_HASH_FOR_STRONG_ID(UavId)
UAV_HASH_FOR_STRONG_ID(ClusterId)
UAV_HASH_FOR_STRONG_ID(SkdcId)
UAV_HASH_FOR_STRONG_ID(MulticastGroupId)
UAV_HASH_FOR_STRONG_ID(KeyVersion)
UAV_HASH_FOR_STRONG_ID(SequenceNum)

#undef UAV_HASH_FOR_STRONG_ID

} // namespace std

#endif // UAV_TYPES_H