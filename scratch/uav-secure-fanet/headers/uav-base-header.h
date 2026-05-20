/**
 * headers/uav-base-header.h
 *
 * Base packet header for all UAV Secure FANET packets.
 *
 * WIRE FORMAT (32 bytes fixed):
 *   [0-1]   magic        (2 bytes) 0x5541 'UA'
 *   [2]     version      (1 byte)  protocol version
 *   [3]     packet_type  (1 byte)  PacketType enum
 *   [4]     flags        (1 byte)  PacketFlag bitmask
 *   [5]     priority     (1 byte)  PacketPriority enum
 *   [6-7]   payload_len  (2 bytes) encrypted payload length
 *   [8-9]   cluster_id   (2 bytes) cluster identifier
 *   [10-11] src_node_id  (2 bytes) sender node ID
 *   [12-13] dst_node_id  (2 bytes) destination node ID
 *   [14]    src_type     (1 byte)  NodeTypeCode of sender
 *   [15]    dst_type     (1 byte)  NodeTypeCode of destination
 *   [16-23] replay token timestamp (8 bytes)
 *   [24-31] replay token sequence  (8 bytes)
 *   Total: 32 bytes (BASE_HEADER_SIZE)
 *
 * NOTE: The 16-byte nonce from ReplayToken is carried separately
 *       in the MT_K field to keep header at exactly 32 bytes.
 *
 * PACKET STRUCTURE:
 *   [BASE_HEADER(32)][REPLAY_NONCE(16)][MT_K(variable)][AES_PAYLOAD][HMAC(32)]
 */

#ifndef UAV_BASE_HEADER_H
#define UAV_BASE_HEADER_H

#include "uav-packet-enums.h"
#include "uav-types.h"
#include "uav-error.h"
#include "uav-byte-utils.h"
#include "uav-replay.h"

#include <string>
#include <array>

namespace uav {
namespace packet {

// ===========================================================================
// BaseHeader — fixed 32-byte plaintext header
// Carried at the front of every packet, unencrypted
// ===========================================================================
class BaseHeader {
public:
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------
    static constexpr std::size_t WIRE_SIZE      = 32;
    static constexpr std::size_t NONCE_SIZE     = 16;
    static constexpr utils::u16  MAGIC          = 0x5541;

    // -----------------------------------------------------------------------
    // Fields (public for direct access)
    // -----------------------------------------------------------------------
    utils::u16          magic       = MAGIC;
    utils::u8           version     = PROTOCOL_VERSION;
    PacketType          packet_type = PacketType::UNKNOWN;
    PacketFlag          flags       = PacketFlag::NONE;
    PacketPriority      priority    = PacketPriority::NORMAL;
    utils::u16          payload_len = 0;
    utils::u16          cluster_id  = 0;
    utils::u16          src_node_id = 0;
    utils::u16          dst_node_id = 0;
    NodeTypeCode        src_type    = NodeTypeCode::UNKNOWN;
    NodeTypeCode        dst_type    = NodeTypeCode::UNKNOWN;
    utils::u64          timestamp_us= 0;   // from ReplayToken
    utils::u64          sequence_num= 0;   // from ReplayToken

    // Nonce carried alongside header (16 bytes, not counted in WIRE_SIZE)
    utils::Nonce128     nonce       = {};

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    BaseHeader() = default;

    /// Construct with all key fields
    BaseHeader(PacketType      type,
               utils::u16      cluster,
               utils::u16      src,
               utils::u16      dst,
               NodeTypeCode    src_t,
               NodeTypeCode    dst_t,
               PacketFlag      fl    = PacketFlag::NONE,
               PacketPriority  prio  = PacketPriority::NORMAL);

    // -----------------------------------------------------------------------
    // Replay token integration
    // -----------------------------------------------------------------------

    /// Apply a ReplayToken to this header.
    void ApplyReplayToken(const crypto::ReplayToken& token);

    /// Extract a ReplayToken from this header.
    crypto::ReplayToken ExtractReplayToken() const;

    // -----------------------------------------------------------------------
    // Flag helpers
    // -----------------------------------------------------------------------
    bool IsEncrypted()       const { return HasFlag(flags, PacketFlag::ENCRYPTED);        }
    bool HasMtk()            const { return HasFlag(flags, PacketFlag::HAS_MTK);          }
    bool IsReplayProtected() const { return HasFlag(flags, PacketFlag::REPLAY_PROTECTED); }
    bool HasHmac()           const { return HasFlag(flags, PacketFlag::HMAC_PRESENT);     }
    bool IsEmergency()       const { return HasFlag(flags, PacketFlag::EMERGENCY);        }

    void SetEncrypted(bool v) {
        flags = v ? SetFlag(flags, PacketFlag::ENCRYPTED)
                  : ClearFlag(flags, PacketFlag::ENCRYPTED);
    }
    void SetHasMtk(bool v) {
        flags = v ? SetFlag(flags, PacketFlag::HAS_MTK)
                  : ClearFlag(flags, PacketFlag::HAS_MTK);
    }
    void SetReplayProtected(bool v) {
        flags = v ? SetFlag(flags, PacketFlag::REPLAY_PROTECTED)
                  : ClearFlag(flags, PacketFlag::REPLAY_PROTECTED);
    }
    void SetHmacPresent(bool v) {
        flags = v ? SetFlag(flags, PacketFlag::HMAC_PRESENT)
                  : ClearFlag(flags, PacketFlag::HMAC_PRESENT);
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize header to exactly WIRE_SIZE (32) bytes.
    utils::ByteBuffer Serialize() const;

    /// Serialize to pre-allocated buffer at offset.
    void SerializeTo(utils::ByteBuffer& buf) const;

    /// Deserialize from wire bytes.
    /// Throws SerializationException if buffer too small or magic wrong.
    static BaseHeader Deserialize(const utils::ByteBuffer& buf,
                                  std::size_t offset = 0);
    static BaseHeader Deserialize(const utils::u8* data,
                                  std::size_t len,
                                  std::size_t offset = 0);

    // -----------------------------------------------------------------------
    // Nonce serialization (16 bytes, separate from 32-byte header)
    // -----------------------------------------------------------------------

    /// Serialize nonce to 16 bytes.
    utils::ByteBuffer SerializeNonce() const;

    /// Deserialize nonce from 16 bytes.
    void DeserializeNonce(const utils::u8* data, std::size_t len);

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------
    bool IsValid() const;
    std::string Describe() const;

    // -----------------------------------------------------------------------
    // Equality
    // -----------------------------------------------------------------------
    bool operator==(const BaseHeader& o) const;
    bool operator!=(const BaseHeader& o) const { return !(*this == o); }
};

// ===========================================================================
// PacketBuilder — fluent builder for creating packet wire buffers
// ===========================================================================
class PacketBuilder {
public:
    explicit PacketBuilder(PacketType type,
                           utils::u16 cluster_id,
                           utils::u16 src_id,
                           utils::u16 dst_id,
                           NodeTypeCode src_type,
                           NodeTypeCode dst_type);

    PacketBuilder& WithFlags(PacketFlag f);
    PacketBuilder& WithPriority(PacketPriority p);
    PacketBuilder& WithReplayToken(const crypto::ReplayToken& t);
    PacketBuilder& WithPayloadLen(utils::u16 len);

    /// Get the constructed header
    const BaseHeader& GetHeader() const { return m_header; }
    BaseHeader& GetHeader()             { return m_header; }

    /// Build wire buffer: [HEADER(32)][NONCE(16)] = 48 bytes base
    utils::ByteBuffer BuildHeaderBytes() const;

private:
    BaseHeader m_header;
};

} // namespace packet
} // namespace uav

#endif // UAV_BASE_HEADER_H
