/**
 * headers/uav-auth-packet.h
 *
 * Authentication Packet
 * Exchanged between UAV and SKDC during initial authentication.
 *
 * AUTH FLOW:
 *   UAV → SKDC : AUTH_REQUEST  (UAV sends identity + nonce)
 *   SKDC → UAV : AUTH_RESPONSE (SKDC sends status + challenge)
 *
 * WIRE FORMAT (fits in CONTROL_PACKET_SIZE = 256 bytes):
 *   [BASE_HEADER  (32)]  plaintext header
 *   [NONCE        (16)]  replay nonce
 *   [AUTH_BODY   (var)]  auth body (see below)
 *   [HMAC         (32)]  integrity
 *
 * AUTH BODY WIRE FORMAT:
 *   [0]     auth_type    u8   (REQUEST=1, RESPONSE=2)
 *   [1]     status       u8   (AuthStatus enum)
 *   [2-3]   uav_id       u16 BE
 *   [4-5]   skdc_id      u16 BE
 *   [6-7]   cluster_id   u16 BE
 *   [8-23]  challenge    16 bytes (random nonce for challenge)
 *   [24-39] response     16 bytes (response to challenge)
 *   [40-47] timestamp_us u64 BE
 *   Total body: 48 bytes (fixed)
 *
 * SECURITY:
 *   HMAC covers entire packet (header + nonce + body).
 *   Challenge/response uses shared TEK-derived material.
 */

#ifndef UAV_AUTH_PACKET_H
#define UAV_AUTH_PACKET_H

#include "uav-base-header.h"
#include "uav-hmac.h"
#include "uav-replay.h"
#include "uav-types.h"
#include "uav-error.h"

#include <array>
#include <string>

namespace uav {
namespace packet {

// ===========================================================================
// AuthType — request or response
// ===========================================================================
enum class AuthType : utils::u8 {
    UNKNOWN  = 0x00,
    REQUEST  = 0x01,
    RESPONSE = 0x02,
};

const char* AuthTypeToString(AuthType t);

// ===========================================================================
// AuthBody — fixed 48-byte auth payload
// ===========================================================================
struct AuthBody {
    AuthType        auth_type    = AuthType::UNKNOWN;
    AuthStatus      status       = AuthStatus::PENDING;
    utils::u16      uav_id       = 0;
    utils::u16      skdc_id      = 0;
    utils::u16      cluster_id   = 0;

    // 16-byte challenge (SKDC→UAV) or zero-filled (UAV→SKDC)
    std::array<utils::u8, 16> challenge  = {};
    // 16-byte response (UAV→SKDC after receiving challenge)
    std::array<utils::u8, 16> response   = {};

    utils::u64      timestamp_us = 0;

    static constexpr std::size_t WIRE_SIZE = 48;

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------
    utils::ByteBuffer Serialize() const;
    static AuthBody Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset = 0);
    static AuthBody Deserialize(const utils::u8* data,
                                std::size_t len,
                                std::size_t offset = 0);

    bool IsValid() const {
        return auth_type != AuthType::UNKNOWN;
    }
};

// ===========================================================================
// AuthPacket — complete authentication packet
// ===========================================================================
class AuthPacket {
public:
    AuthPacket() = default;

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /// Build AUTH_REQUEST: UAV → SKDC
    static AuthPacket BuildRequest(
        utils::u16              uav_id,
        utils::u16              skdc_id,
        utils::u16              cluster_id,
        const crypto::HmacKey&  hmac_key,
        crypto::SequenceCounter& seq);

    /// Build AUTH_RESPONSE: SKDC → UAV
    static AuthPacket BuildResponse(
        utils::u16              uav_id,
        utils::u16              skdc_id,
        utils::u16              cluster_id,
        AuthStatus              status,
        const std::array<utils::u8, 16>& challenge,
        const crypto::HmacKey&  hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize to wire bytes (without HMAC).
    utils::ByteBuffer Serialize() const;

    /// Deserialize and verify HMAC.
    static AuthPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader& GetHeader() const { return m_header; }
    const AuthBody&   GetBody()   const { return m_body;   }
    BaseHeader&       GetHeader()       { return m_header; }
    AuthBody&         GetBody()         { return m_body;   }

    bool IsRequest()  const {
        return m_body.auth_type == AuthType::REQUEST;
    }
    bool IsResponse() const {
        return m_body.auth_type == AuthType::RESPONSE;
    }
    bool IsSuccess()  const {
        return IsAuthSuccess(m_body.status);
    }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::string Describe() const;

private:
    BaseHeader  m_header;
    AuthBody    m_body;
};

} // namespace packet
} // namespace uav

#endif // UAV_AUTH_PACKET_H
