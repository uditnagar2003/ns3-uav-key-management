/**
 * headers/uav-mtk-packet.h
 *
 * MT_K (Master Token Key) Packet
 * Sent from SKDC to UAV cluster to distribute the current MT_K.
 *
 * PURPOSE:
 *   Carries the MT_K ciphertext so each UAV can decrypt
 *   the TEK using its slave decryption key d_i.
 *
 * WIRE FORMAT (fits in REKEY_PACKET_SIZE = 512 bytes):
 *   [BASE_HEADER   (32)]   plaintext header
 *   [NONCE         (16)]   replay nonce
 *   [MTK_BODY     (var)]   MT_K packet body (below)
 *   [HMAC          (32)]   integrity over all above
 *
 * MT_K BODY WIRE FORMAT:
 *   [0-3]   cluster_id     u32 BE
 *   [4-7]   version        u32 BE   (rekey counter)
 *   [8-15]  timestamp_us   u64 BE
 *   [16-19] mtk_len        u32 BE   (length of mtk_bytes)
 *   [20-23] n_group_len    u32 BE   (length of n_group_bytes)
 *   [24-27] body_nonce_len u32 BE   (length of body nonce = 16)
 *   [28+]   mtk_bytes      (mtk_len bytes)  BigInt MT_K as big-endian
 *   [+]     n_group_bytes  (n_group_len bytes) BigInt N_group
 *   [+]     body_nonce     (16 bytes) freshness nonce
 *
 * SECURITY:
 *   MT_K body is authenticated by HMAC.
 *   MT_K itself is the CRT ciphertext — selective decryptability
 *   means only authorized UAVs can recover TEK.
 */

#ifndef UAV_MTK_PACKET_H
#define UAV_MTK_PACKET_H

#include "uav-base-header.h"
#include "uav-bigint.h"
#include "uav-hmac.h"
#include "uav-replay.h"
#include "uav-types.h"
#include "uav-error.h"

#include <string>
#include <vector>

namespace uav {
namespace packet {

// ===========================================================================
// MtkBody — the MT_K packet payload
// ===========================================================================
struct MtkBody {
    utils::u32      cluster_id    = 0;
    utils::u32      version       = 0;
    utils::u64      timestamp_us  = 0;
    crypto::BigInt  mtk;           // MT_K ciphertext (BigInt)
    crypto::BigInt  n_group;       // N_group modulus (BigInt)
    utils::Nonce128 body_nonce    = {};  // freshness nonce

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize MtkBody to bytes.
    utils::ByteBuffer Serialize() const;

    /// Deserialize MtkBody from bytes.
    static MtkBody Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset = 0);

    /// Wire size (variable due to BigInt)
    std::size_t WireSize() const;

    /// Minimum wire size (fixed fields only)
    static constexpr std::size_t MIN_SIZE = 28;

    bool IsValid() const {
        return cluster_id < 3 && version > 0 &&
               mtk > crypto::BigInt(0) &&
               n_group > crypto::BigInt(0);
    }
};

// ===========================================================================
// MtkPacket — complete MT_K distribution packet
// ===========================================================================
class MtkPacket {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    MtkPacket() = default;

    /// Build a complete MT_K packet.
    /// @param cluster_id  Which cluster this MT_K is for
    /// @param src_skdc    SKDC node ID (sender)
    /// @param version     Rekey version counter
    /// @param mtk         MT_K BigInt ciphertext
    /// @param n_group     N_group modulus
    /// @param hmac_key    TEK-derived HMAC key for integrity
    /// @param seq         Outgoing sequence counter
    static MtkPacket Build(
        utils::u32              cluster_id,
        utils::u16              src_skdc,
        utils::u32              version,
        const crypto::BigInt&   mtk,
        const crypto::BigInt&   n_group,
        const crypto::HmacKey&  hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Serialize to complete wire bytes.
    /// Layout: [HEADER(32)][NONCE(16)][BODY(var)][HMAC(32)]
    utils::ByteBuffer Serialize() const;

    /// Deserialize and verify HMAC.
    /// Throws CryptoException if HMAC fails.
    /// Throws SerializationException if malformed.
    static MtkPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    /// Deserialize with SHA-256 integrity check (no HMAC key needed).
    /// Throws CryptoException if SHA-256 check fails.
    static MtkPacket DeserializeNoHmac(
        const utils::ByteBuffer& wire);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader& GetHeader() const { return m_header; }
    const MtkBody&    GetBody()   const { return m_body;   }
    BaseHeader&       GetHeader()       { return m_header; }
    MtkBody&          GetBody()         { return m_body;   }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::string Describe() const;

private:
    BaseHeader  m_header;
    MtkBody     m_body;
};

} // namespace packet
} // namespace uav

#endif // UAV_MTK_PACKET_H
