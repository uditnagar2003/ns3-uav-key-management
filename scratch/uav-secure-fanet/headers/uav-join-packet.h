/**
 * headers/uav-join-packet.h
 *
 * JOIN Packet — UAV requests to join a multicast cluster.
 *
 * JOIN FLOW (Algorithm 3 — JoKeyUpdate):
 *   UAV    → SKDC : JOIN_REQUEST  (UAV identity + requested cluster)
 *   SKDC   → UAV  : JOIN_ACCEPT   (new slave key + MT_K)
 *   SKDC   → ALL  : JOIN_NOTIFY   (broadcast: new member joined)
 *
 * Per project spec (JOIN_PACKET contents):
 *   - UAV identity
 *   - nonce
 *   - timestamp
 *   - requested SKDC
 *
 * WIRE FORMAT (fits in CONTROL_PACKET_SIZE = 256 bytes):
 *   [BASE_HEADER  (32)]  plaintext header
 *   [NONCE        (16)]  replay nonce
 *   [JOIN_BODY   (var)]  join body
 *   [HMAC         (32)]  integrity
 *
 * JOIN BODY WIRE FORMAT (56 bytes fixed):
 *   [0]     join_type    u8   (REQUEST=1, ACCEPT=2, NOTIFY=3)
 *   [1]     reserved     u8
 *   [2-3]   uav_id       u16 BE
 *   [4-5]   skdc_id      u16 BE   (requested/assigned SKDC)
 *   [6-7]   cluster_id   u16 BE
 *   [8-23]  identity     16 bytes (UAV identity material)
 *   [24-39] join_nonce   16 bytes (freshness nonce)
 *   [40-47] timestamp_us u64 BE
 *   [48-51] uav_index    u32 BE   (index within cluster 0-5)
 *   [52-55] version      u32 BE   (rekey version after join)
 *   Total: 56 bytes
 */

#ifndef UAV_JOIN_PACKET_H
#define UAV_JOIN_PACKET_H

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
// JoinType
// ===========================================================================
enum class JoinType : utils::u8 {
    UNKNOWN  = 0x00,
    REQUEST  = 0x01,   // UAV → SKDC: join request
    ACCEPT   = 0x02,   // SKDC → UAV: join accepted
    REJECT   = 0x03,   // SKDC → UAV: join rejected
    NOTIFY   = 0x04,   // SKDC → ALL: new member broadcast
    LEAVE    = 0x05,   // UAV → SKDC: leave request (also used here)
};

const char* JoinTypeToString(JoinType t);

// ===========================================================================
// JoinBody — fixed 56-byte join payload
// ===========================================================================
struct JoinBody {
    JoinType        join_type    = JoinType::UNKNOWN;
    utils::u8       reserved     = 0;
    utils::u16      uav_id       = 0;
    utils::u16      skdc_id      = 0;
    utils::u16      cluster_id   = 0;

    // 16-byte UAV identity material
    std::array<utils::u8, 16> identity   = {};
    // 16-byte freshness nonce
    std::array<utils::u8, 16> join_nonce = {};

    utils::u64      timestamp_us = 0;
    utils::u32      uav_index    = 0;   // 0-5 within cluster
    utils::u32      version      = 0;   // rekey version after join

    static constexpr std::size_t WIRE_SIZE = 56;

    utils::ByteBuffer Serialize() const;
    static JoinBody Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset = 0);
    static JoinBody Deserialize(const utils::u8* data,
                                std::size_t len,
                                std::size_t offset = 0);

    bool IsValid() const {
        return join_type != JoinType::UNKNOWN;
    }
};

// ===========================================================================
// JoinPacket
// ===========================================================================
class JoinPacket {
public:
    JoinPacket() = default;

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /// UAV → SKDC: request to join cluster
    static JoinPacket BuildRequest(
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        utils::u32               uav_index,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// SKDC → UAV: accept join
    static JoinPacket BuildAccept(
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        utils::u32               uav_index,
        utils::u32               new_version,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// SKDC → UAV: reject join
    static JoinPacket BuildReject(
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// SKDC → ALL: notify cluster of new member
    static JoinPacket BuildNotify(
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        utils::u32               uav_index,
        utils::u32               new_version,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------
    utils::ByteBuffer Serialize() const;

    static JoinPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader& GetHeader() const { return m_header; }
    const JoinBody&   GetBody()   const { return m_body;   }
    BaseHeader&       GetHeader()       { return m_header; }
    JoinBody&         GetBody()         { return m_body;   }

    bool IsRequest()  const {
        return m_body.join_type == JoinType::REQUEST; }
    bool IsAccept()   const {
        return m_body.join_type == JoinType::ACCEPT;  }
    bool IsReject()   const {
        return m_body.join_type == JoinType::REJECT;  }
    bool IsNotify()   const {
        return m_body.join_type == JoinType::NOTIFY;  }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::string Describe() const;

private:
    BaseHeader  m_header;
    JoinBody    m_body;

    static JoinPacket BuildInternal(
        JoinType                 join_type,
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        utils::u32               uav_index,
        utils::u32               version,
        NodeTypeCode             src_type,
        NodeTypeCode             dst_type,
        utils::u16               dst_id,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);
};

} // namespace packet
} // namespace uav

#endif // UAV_JOIN_PACKET_H
