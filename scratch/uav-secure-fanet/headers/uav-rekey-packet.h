/**
 * headers/uav-rekey-packet.h
 *
 * REKEY Packet — key update broadcast from SKDC to UAV cluster.
 *
 * Per project spec (REKEY_PACKET contents):
 *   - MT_K
 *   - sequence number
 *   - nonce
 *   - timestamp
 *   - cluster ID
 *
 * REKEY TRIGGERS (per spec):
 *   - JOIN  event (Algorithm 3: JoKeyUpdate)
 *   - LEAVE event (Algorithm 5: LeKeyUpdate)
 *   - HANDOVER
 *   - COMPROMISE detection
 *   - PERIODIC rekey
 *   - JAMMER detected
 *
 * WIRE FORMAT (REKEY_PACKET_SIZE = 512 bytes):
 *   [BASE_HEADER    (32)]  plaintext header
 *   [NONCE          (16)]  replay nonce
 *   [REKEY_BODY    (var)]  rekey body
 *   [HMAC           (32)]  integrity
 *
 * REKEY BODY WIRE FORMAT:
 *   [0-3]   cluster_id    u32 BE
 *   [4-7]   version       u32 BE   (rekey counter)
 *   [8]     reason        u8       (RekeyReason enum)
 *   [9-11]  reserved      3 bytes
 *   [12-15] mtk_len       u32 BE
 *   [16-23] timestamp_us  u64 BE
 *   [24-39] rekey_nonce   16 bytes
 *   [40+]   mtk_bytes     (mtk_len bytes) MT_K BigInt
 *   Fixed header: 40 bytes + variable MTK
 */

#ifndef UAV_REKEY_PACKET_H
#define UAV_REKEY_PACKET_H

#include "uav-base-header.h"
#include "uav-bigint.h"
#include "uav-hmac.h"
#include "uav-replay.h"
#include "uav-types.h"
#include "uav-error.h"

#include <array>
#include <string>

namespace uav {
namespace packet {

// ===========================================================================
// RekeyBody — rekey packet payload
// ===========================================================================
struct RekeyBody {
    utils::u32      cluster_id   = 0;
    utils::u32      version      = 0;
    RekeyReason     reason       = RekeyReason::NONE;
    crypto::BigInt  mtk;
    utils::u64      timestamp_us = 0;
    utils::Nonce128 rekey_nonce  = {};

    static constexpr std::size_t FIXED_SIZE = 40;

    utils::ByteBuffer Serialize() const;
    static RekeyBody Deserialize(const utils::ByteBuffer& buf,
                                  std::size_t offset = 0);

    std::size_t WireSize() const;

    bool IsValid() const {
        return cluster_id < 3 && version > 0;
    }
};

// ===========================================================================
// RekeyPacket
// ===========================================================================
class RekeyPacket {
public:
    RekeyPacket() = default;

    /// Build rekey packet: SKDC → cluster broadcast
    /// @param cluster_id  Target cluster
    /// @param skdc_id     Source SKDC
    /// @param version     New rekey version
    /// @param reason      Why rekey was triggered
    /// @param mtk         New MT_K ciphertext
    /// @param hmac_key    HMAC key for integrity
    /// @param seq         Sequence counter
    static RekeyPacket Build(
        utils::u32               cluster_id,
        utils::u16               skdc_id,
        utils::u32               version,
        RekeyReason              reason,
        const crypto::BigInt&    mtk,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------
    utils::ByteBuffer Serialize() const;

    static RekeyPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader& GetHeader() const { return m_header; }
    const RekeyBody&  GetBody()   const { return m_body;   }
    BaseHeader&       GetHeader()       { return m_header; }
    RekeyBody&        GetBody()         { return m_body;   }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::string Describe() const;

private:
    BaseHeader  m_header;
    RekeyBody   m_body;
};

} // namespace packet
} // namespace uav

#endif // UAV_REKEY_PACKET_H
