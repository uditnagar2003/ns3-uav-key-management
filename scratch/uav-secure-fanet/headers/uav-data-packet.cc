/**
 * headers/uav-data-packet.cc
 */

#include "uav-data-packet.h"
#include "uav-byte-utils.h"
#include "uav-time-utils.h"
#include "uav-string-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <cstring>
#include <sstream>

namespace uav {
namespace packet {

// ===========================================================================
// DataBody::Serialize
// [0-3]   cluster_id    u32 BE
// [4-7]   data_sequence u32 BE
// [8-15]  timestamp_us  u64 BE
// [16-19] plaintext_len u32 BE
// [20-23] ct_len        u32 BE
// [24-35] aes_iv        12 bytes
// [36-39] padding       4 bytes  (align to 56)
// [40-55] aes_tag       16 bytes
// [56+]   ciphertext
// ===========================================================================
utils::ByteBuffer DataBody::Serialize() const {
    utils::ByteBuffer buf(FIXED_SIZE, 0x00);
    utils::u8* p = buf.data();

    utils::ByteUtils::WriteU32BE(p + 0,  cluster_id);
    utils::ByteUtils::WriteU32BE(p + 4,  data_sequence);
    utils::ByteUtils::WriteU64BE(p + 8,  timestamp_us);
    utils::ByteUtils::WriteU32BE(p + 16, plaintext_len);
    utils::ByteUtils::WriteU32BE(p + 20,
        static_cast<utils::u32>(ciphertext.size()));
    std::memcpy(p + 24, aes_iv.data(),  12);
    // [36-39] padding = 0
    std::memcpy(p + 40, aes_tag.data(), 16);

    // Append ciphertext
    utils::ByteUtils::AppendBytes(buf, ciphertext);
    return buf;
}

DataBody DataBody::Deserialize(
    const utils::ByteBuffer& buf,
    std::size_t offset)
{
    if (buf.size() < offset + FIXED_SIZE) {
        UAV_THROW(utils::SerializationException,
            "DataBody::Deserialize: buffer too small ("
            + std::to_string(buf.size()) + ")");
    }

    const utils::u8* p = buf.data() + offset;
    DataBody body;

    body.cluster_id    = utils::ByteUtils::ReadU32BE(p + 0);
    body.data_sequence = utils::ByteUtils::ReadU32BE(p + 4);
    body.timestamp_us  = utils::ByteUtils::ReadU64BE(p + 8);
    body.plaintext_len = utils::ByteUtils::ReadU32BE(p + 16);
    utils::u32 ct_len  = utils::ByteUtils::ReadU32BE(p + 20);
    std::memcpy(body.aes_iv.data(),  p + 24, 12);
    std::memcpy(body.aes_tag.data(), p + 40, 16);

    std::size_t ct_offset = offset + FIXED_SIZE;
    if (buf.size() < ct_offset + ct_len) {
        UAV_THROW(utils::SerializationException,
            "DataBody::Deserialize: truncated ciphertext");
    }

    body.ciphertext.assign(
        buf.begin() + static_cast<std::ptrdiff_t>(ct_offset),
        buf.begin() + static_cast<std::ptrdiff_t>(
            ct_offset + ct_len));

    return body;
}

// ===========================================================================
// DataPacket::Build
// ===========================================================================
DataPacket DataPacket::Build(
    utils::u16               cluster_id,
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u32               data_seq,
    const utils::ByteBuffer& plaintext,
    const crypto::AesGcmKey& tek,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;

    DataPacket pkt;

    // Encrypt payload with AES-256-GCM
    // AAD = cluster_id + uav_id (4 bytes)
    utils::ByteBuffer aad(4);
    utils::ByteUtils::WriteU16BE(aad.data(),     cluster_id);
    utils::ByteUtils::WriteU16BE(aad.data() + 2, uav_id);

    auto enc = crypto::AesGcm::Encrypt(tek, plaintext, aad);

    // Body
    pkt.m_body.cluster_id    = cluster_id;
    pkt.m_body.data_sequence = data_seq;
    pkt.m_body.timestamp_us  =
        utils::TimeUtils::NowEpochMicros();
    pkt.m_body.plaintext_len =
        static_cast<utils::u32>(plaintext.size());
    pkt.m_body.aes_iv        = enc.iv;
    pkt.m_body.aes_tag       = enc.tag;
    pkt.m_body.ciphertext    = std::move(enc.ciphertext);

    // Header
    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::DATA_PACKET,
        cluster_id,
        uav_id,
        skdc_id,
        NodeTypeCode::UAV,
        NodeTypeCode::SKDC,
        PacketFlag::ENCRYPTED |
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::NORMAL);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(pkt.m_body.WireSize());

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "DataPacket::Build: uav=" << uav_id
        << " cluster=" << cluster_id
        << " plaintext=" << plaintext.size()
        << " ct=" << pkt.m_body.ciphertext.size());

    return pkt;
}

// ===========================================================================
// DataPacket::Decrypt
// ===========================================================================
utils::ByteBuffer DataPacket::Decrypt(
    const crypto::AesGcmKey& tek) const
{
    // Reconstruct AAD
    utils::ByteBuffer aad(4);
    utils::ByteUtils::WriteU16BE(aad.data(),
        m_header.cluster_id);
    utils::ByteUtils::WriteU16BE(aad.data() + 2,
        m_header.src_node_id);

    // Convert 12-byte IV
    std::array<utils::u8, 12> iv = m_body.aes_iv;

    // Convert 16-byte tag
    std::array<utils::u8, 16> tag = m_body.aes_tag;

    return crypto::AesGcm::Decrypt(
        tek, iv, m_body.ciphertext, tag, aad);
}

// ===========================================================================
// Serialize: [HEADER(32)][NONCE(16)][BODY(var)]
// ===========================================================================
utils::ByteBuffer DataPacket::Serialize() const {
    utils::ByteBuffer buf;
    m_header.SerializeTo(buf);
    utils::ByteUtils::AppendBytes(buf,
        m_header.SerializeNonce());
    utils::ByteUtils::AppendBytes(buf,
        m_body.Serialize());
    return buf;
}

// ===========================================================================
// Deserialize
// ===========================================================================
DataPacket DataPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        DataBody::FIXED_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "DataPacket::Deserialize: too small ("
            + std::to_string(wire.size()) + ")");
    }

    auto body =
        crypto::HmacSha256Util::StripAndVerifyHmac(
            hmac_key, wire);

    std::size_t pos = 0;
    DataPacket pkt;

    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    pkt.m_header.DeserializeNonce(
        body.data() + pos, body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    pkt.m_body = DataBody::Deserialize(body, pos);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string DataPacket::Describe() const {
    std::ostringstream oss;
    oss << "DataPacket{"
        << " uav="     << m_header.src_node_id
        << " cluster=" << m_body.cluster_id
        << " seq="     << m_body.data_sequence
        << " plen="    << m_body.plaintext_len
        << " ct="      << m_body.ciphertext.size()
        << " rseq="    << m_header.sequence_num
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
