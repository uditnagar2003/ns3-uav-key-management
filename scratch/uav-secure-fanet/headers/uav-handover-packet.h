/**
 * headers/uav-handover-packet.h
 *
 * HANDOVER Packet — UAV cluster handover notification.
 *
 * HANDOVER FLOW (per project spec):
 *   Handover = leave old cluster + join new cluster
 *   BOTH old and new clusters rekey after handover.
 *
 *   Phase 1: UAV → Old SKDC  : HANDOVER_INIT
 *   Phase 2: Old SKDC → New SKDC : HANDOVER_TRANSFER (via KDC backbone)
 *   Phase 3: New SKDC → UAV  : HANDOVER_ACCEPT
 *   Phase 4: Old SKDC → ALL  : HANDOVER_REKEY_OLD
 *   Phase 5: New SKDC → ALL  : HANDOVER_REKEY_NEW
 *   Phase 6: UAV → New SKDC  : HANDOVER_COMPLETE
 *
 * Per project spec (HANDOVER_PACKET):
 *   - UAV identity
 *   - old cluster ID
 *   - new cluster ID
 *   - handover phase
 *   - timestamp
 *   - nonce
 *
 * WIRE FORMAT (CONTROL_PACKET_SIZE = 256 bytes):
 *   [BASE_HEADER  (32)]
 *   [NONCE        (16)]
 *   [HO_BODY      (64)]  fixed size
 *   [HMAC         (32)]
 *   Total: 144 bytes
 *
 * HANDOVER BODY (64 bytes):
 *   [0]     phase          u8
 *   [1]     reserved       u8
 *   [2-3]   uav_id         u16 BE
 *   [4-5]   old_cluster_id u16 BE
 *   [6-7]   new_cluster_id u16 BE
 *   [8-9]   old_skdc_id    u16 BE
 *   [10-11] new_skdc_id    u16 BE
 *   [12-15] old_version    u32 BE  (rekey version old cluster)
 *   [16-19] new_version    u32 BE  (rekey version new cluster)
 *   [20-27] timestamp_us   u64 BE
 *   [28-43] ho_nonce       16 bytes
 *   [44-47] uav_index_old  u32 BE
 *   [48-51] uav_index_new  u32 BE
 *   [52-63] reserved       12 bytes
 *   Total: 64 bytes
 */

#ifndef UAV_HANDOVER_PACKET_H
#define UAV_HANDOVER_PACKET_H

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
// HandoverBody — fixed 64-byte handover payload
// ===========================================================================
struct HandoverBody {
    HandoverPhase   phase          = HandoverPhase::NONE;
    utils::u8       reserved       = 0;
    utils::u16      uav_id         = 0;
    utils::u16      old_cluster_id = 0;
    utils::u16      new_cluster_id = 0;
    utils::u16      old_skdc_id    = 0;
    utils::u16      new_skdc_id    = 0;
    utils::u32      old_version    = 0;
    utils::u32      new_version    = 0;
    utils::u64      timestamp_us   = 0;
    std::array<utils::u8, 16> ho_nonce    = {};
    utils::u32      uav_index_old  = 0;
    utils::u32      uav_index_new  = 0;
    std::array<utils::u8, 12> reserved2   = {};

    static constexpr std::size_t WIRE_SIZE = 64;

    utils::ByteBuffer Serialize() const;
    static HandoverBody Deserialize(
        const utils::ByteBuffer& buf,
        std::size_t offset = 0);
    static HandoverBody Deserialize(
        const utils::u8* data,
        std::size_t len,
        std::size_t offset = 0);

    bool IsValid() const {
        return phase != HandoverPhase::NONE;
    }
};

// ===========================================================================
// HandoverPacket
// ===========================================================================
class HandoverPacket {
public:
    HandoverPacket() = default;

    // -----------------------------------------------------------------------
    // Factory methods for each handover phase
    // -----------------------------------------------------------------------

    /// Phase 1: UAV → Old SKDC (initiate handover)
    static HandoverPacket BuildInit(
        utils::u16               uav_id,
        utils::u16               old_skdc_id,
        utils::u16               old_cluster_id,
        utils::u16               new_cluster_id,
        utils::u16               new_skdc_id,
        utils::u32               uav_index_old,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// Phase 2: Old SKDC → New SKDC (transfer via KDC backbone)
    static HandoverPacket BuildTransfer(
        utils::u16               uav_id,
        utils::u16               old_skdc_id,
        utils::u16               new_skdc_id,
        utils::u16               old_cluster_id,
        utils::u16               new_cluster_id,
        utils::u32               uav_index_old,
        utils::u32               uav_index_new,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// Phase 3: New SKDC → UAV (accept handover)
    static HandoverPacket BuildAccept(
        utils::u16               uav_id,
        utils::u16               new_skdc_id,
        utils::u16               old_cluster_id,
        utils::u16               new_cluster_id,
        utils::u32               uav_index_new,
        utils::u32               new_version,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// Phase 4/5: SKDC → ALL (rekey after handover)
    static HandoverPacket BuildRekey(
        utils::u16               skdc_id,
        utils::u16               cluster_id,
        utils::u32               version,
        HandoverPhase            phase,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    /// Phase 6: UAV → New SKDC (complete)
    static HandoverPacket BuildComplete(
        utils::u16               uav_id,
        utils::u16               new_skdc_id,
        utils::u16               old_cluster_id,
        utils::u16               new_cluster_id,
        utils::u32               uav_index_new,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------
    utils::ByteBuffer Serialize() const;

    static HandoverPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader&    GetHeader() const { return m_header; }
    const HandoverBody&  GetBody()   const { return m_body;   }
    BaseHeader&          GetHeader()       { return m_header; }
    HandoverBody&        GetBody()         { return m_body;   }

    HandoverPhase GetPhase() const {
        return m_body.phase;
    }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::string Describe() const;

private:
    BaseHeader    m_header;
    HandoverBody  m_body;

    static HandoverPacket BuildInternal(
        HandoverPhase            phase,
        utils::u16               uav_id,
        utils::u16               src_id,
        utils::u16               dst_id,
        NodeTypeCode             src_type,
        NodeTypeCode             dst_type,
        utils::u16               old_cluster_id,
        utils::u16               new_cluster_id,
        utils::u16               old_skdc_id,
        utils::u16               new_skdc_id,
        utils::u32               uav_index_old,
        utils::u32               uav_index_new,
        utils::u32               old_version,
        utils::u32               new_version,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);
};

} // namespace packet
} // namespace uav

#endif // UAV_HANDOVER_PACKET_H
