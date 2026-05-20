/**
 * headers/uav-data-packet.h
 *
 * DATA Packet — AES-256-GCM encrypted UAV payload.
 *
 * This is the primary data-carrying packet in the simulation.
 * UAVs encrypt sensor/telemetry data using the current TEK.
 *
 * WIRE FORMAT (DATA_PACKET_SIZE = 1024 bytes):
 *   [BASE_HEADER    (32)]  plaintext
 *   [NONCE          (16)]  replay nonce
 *   [DATA_BODY     (var)]  encrypted body
 *   [HMAC           (32)]  integrity over all above
 *
 * DATA BODY WIRE FORMAT:
 *   [0-3]   cluster_id    u32 BE
 *   [4-7]   sequence_num  u32 BE   (data sequence)
 *   [8-15]  timestamp_us  u64 BE
 *   [16-19] plaintext_len u32 BE   (original data length)
 *   [20-23] ct_len        u32 BE   (ciphertext length)
 *   [24-39] aes_iv        16 bytes (from AES-GCM)
 *   [40-55] aes_tag       16 bytes (GCM auth tag)
 *   [56+]   ciphertext    (ct_len bytes)
 *   Fixed header: 56 bytes + variable ciphertext
 *
 * SECURITY:
 *   Payload encrypted with AES-256-GCM using current TEK.
 *   GCM tag authenticates ciphertext.
 *   Outer HMAC authenticates entire packet.
 *   Replay protected via BaseHeader timestamp+nonce+seq.
 */

#ifndef UAV_DATA_PACKET_H
#define UAV_DATA_PACKET_H

#include "uav-base-header.h"
#include "uav-aes.h"
#include "uav-hmac.h"
#include "uav-replay.h"
#include "uav-types.h"
#include "uav-error.h"

#include <array>
#include <string>

namespace uav {
namespace packet {

// ===========================================================================
// DataBody — encrypted data payload
// ===========================================================================
struct DataBody {
    utils::u32      cluster_id    = 0;
    utils::u32      data_sequence = 0;
    utils::u64      timestamp_us  = 0;
    utils::u32      plaintext_len = 0;

    // AES-GCM components
    std::array<utils::u8, 12> aes_iv  = {};
    std::array<utils::u8, 16> aes_tag = {};
    utils::ByteBuffer          ciphertext;

    static constexpr std::size_t FIXED_SIZE = 56;

    utils::ByteBuffer Serialize() const;
    static DataBody Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset = 0);

    std::size_t WireSize() const {
        return FIXED_SIZE + ciphertext.size();
    }

    bool IsValid() const {
        return plaintext_len > 0 && !ciphertext.empty();
    }
};

// ===========================================================================
// DataPacket
// ===========================================================================
class DataPacket {
public:
    DataPacket() = default;

    // -----------------------------------------------------------------------
    // Build: encrypt plaintext with TEK → data packet
    // -----------------------------------------------------------------------

    /// Build encrypted data packet.
    /// @param cluster_id   Cluster this UAV belongs to
    /// @param uav_id       Sender UAV
    /// @param skdc_id      Destination SKDC
    /// @param data_seq     Data sequence counter
    /// @param plaintext    Raw payload to encrypt
    /// @param tek          Traffic Encryption Key (AES-256)
    /// @param hmac_key     HMAC key for integrity
    /// @param seq          Replay sequence counter
    static DataPacket Build(
        utils::u16               cluster_id,
        utils::u16               uav_id,
        utils::u16               skdc_id,
        utils::u32               data_seq,
        const utils::ByteBuffer& plaintext,
        const crypto::AesGcmKey& tek,
        const crypto::HmacKey&   hmac_key,
        crypto::SequenceCounter& seq);

    // -----------------------------------------------------------------------
    // Decrypt: recover plaintext from data packet
    // -----------------------------------------------------------------------

    /// Decrypt payload using TEK.
    /// Throws CryptoException if AES-GCM tag fails.
    utils::ByteBuffer Decrypt(
        const crypto::AesGcmKey& tek) const;

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------
    utils::ByteBuffer Serialize() const;

    static DataPacket Deserialize(
        const utils::ByteBuffer& wire,
        const crypto::HmacKey&   hmac_key);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const BaseHeader& GetHeader() const { return m_header; }
    const DataBody&   GetBody()   const { return m_body;   }
    BaseHeader&       GetHeader()       { return m_header; }
    DataBody&         GetBody()         { return m_body;   }

    bool IsValid() const {
        return m_header.IsValid() && m_body.IsValid();
    }

    std::size_t PayloadSize() const {
        return m_body.plaintext_len;
    }

    std::string Describe() const;

private:
    BaseHeader  m_header;
    DataBody    m_body;
};

} // namespace packet
} // namespace uav

#endif // UAV_DATA_PACKET_H
