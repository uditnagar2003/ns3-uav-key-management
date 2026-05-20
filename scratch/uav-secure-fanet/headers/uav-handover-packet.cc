/**
 * headers/uav-handover-packet.cc
 */

#include "uav-handover-packet.h"
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
// HandoverBody::Serialize (64 bytes)
// ===========================================================================
utils::ByteBuffer HandoverBody::Serialize() const {
    utils::ByteBuffer buf(WIRE_SIZE, 0x00);
    utils::u8* p = buf.data();

    p[0] = static_cast<utils::u8>(phase);
    p[1] = reserved;
    utils::ByteUtils::WriteU16BE(p + 2,  uav_id);
    utils::ByteUtils::WriteU16BE(p + 4,  old_cluster_id);
    utils::ByteUtils::WriteU16BE(p + 6,  new_cluster_id);
    utils::ByteUtils::WriteU16BE(p + 8,  old_skdc_id);
    utils::ByteUtils::WriteU16BE(p + 10, new_skdc_id);
    utils::ByteUtils::WriteU32BE(p + 12, old_version);
    utils::ByteUtils::WriteU32BE(p + 16, new_version);
    utils::ByteUtils::WriteU64BE(p + 20, timestamp_us);
    std::memcpy(p + 28, ho_nonce.data(), 16);
    utils::ByteUtils::WriteU32BE(p + 44, uav_index_old);
    utils::ByteUtils::WriteU32BE(p + 48, uav_index_new);
    std::memcpy(p + 52, reserved2.data(), 12);

    return buf;
}

HandoverBody HandoverBody::Deserialize(
    const utils::ByteBuffer& buf,
    std::size_t offset)
{
    return Deserialize(buf.data(), buf.size(), offset);
}

HandoverBody HandoverBody::Deserialize(
    const utils::u8* data,
    std::size_t len,
    std::size_t offset)
{
    if (len < offset + WIRE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "HandoverBody::Deserialize: buffer too small");
    }

    const utils::u8* p = data + offset;
    HandoverBody body;

    body.phase          = static_cast<HandoverPhase>(p[0]);
    body.reserved       = p[1];
    body.uav_id         = utils::ByteUtils::ReadU16BE(p + 2);
    body.old_cluster_id = utils::ByteUtils::ReadU16BE(p + 4);
    body.new_cluster_id = utils::ByteUtils::ReadU16BE(p + 6);
    body.old_skdc_id    = utils::ByteUtils::ReadU16BE(p + 8);
    body.new_skdc_id    = utils::ByteUtils::ReadU16BE(p + 10);
    body.old_version    = utils::ByteUtils::ReadU32BE(p + 12);
    body.new_version    = utils::ByteUtils::ReadU32BE(p + 16);
    body.timestamp_us   = utils::ByteUtils::ReadU64BE(p + 20);
    std::memcpy(body.ho_nonce.data(),   p + 28, 16);
    body.uav_index_old  = utils::ByteUtils::ReadU32BE(p + 44);
    body.uav_index_new  = utils::ByteUtils::ReadU32BE(p + 48);
    std::memcpy(body.reserved2.data(), p + 52, 12);

    return body;
}

// ===========================================================================
// Internal builder
// ===========================================================================
HandoverPacket HandoverPacket::BuildInternal(
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
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;

    HandoverPacket pkt;

    pkt.m_body.phase          = phase;
    pkt.m_body.uav_id         = uav_id;
    pkt.m_body.old_cluster_id = old_cluster_id;
    pkt.m_body.new_cluster_id = new_cluster_id;
    pkt.m_body.old_skdc_id    = old_skdc_id;
    pkt.m_body.new_skdc_id    = new_skdc_id;
    pkt.m_body.uav_index_old  = uav_index_old;
    pkt.m_body.uav_index_new  = uav_index_new;
    pkt.m_body.old_version    = old_version;
    pkt.m_body.new_version    = new_version;
    pkt.m_body.timestamp_us   =
        utils::TimeUtils::NowEpochMicros();
    pkt.m_body.ho_nonce       =
        crypto::OpenSSLRand::RandomNonce128();
    pkt.m_body.reserved2.fill(0);

    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::HANDOVER_PACKET,
        old_cluster_id,
        src_id,
        dst_id,
        src_type,
        dst_type,
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::CRITICAL);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(HandoverBody::WIRE_SIZE);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "HandoverPacket::Build: phase="
        << HandoverPhaseToString(phase)
        << " uav=" << uav_id
        << " " << old_cluster_id
        << "->" << new_cluster_id);

    return pkt;
}

// ===========================================================================
// Factory methods
// ===========================================================================
HandoverPacket HandoverPacket::BuildInit(
    utils::u16               uav_id,
    utils::u16               old_skdc_id,
    utils::u16               old_cluster_id,
    utils::u16               new_cluster_id,
    utils::u16               new_skdc_id,
    utils::u32               uav_index_old,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        HandoverPhase::INITIATED,
        uav_id, uav_id, old_skdc_id,
        NodeTypeCode::UAV, NodeTypeCode::SKDC,
        old_cluster_id, new_cluster_id,
        old_skdc_id, new_skdc_id,
        uav_index_old, 0, 0, 0,
        hmac_key, seq);
}

HandoverPacket HandoverPacket::BuildTransfer(
    utils::u16               uav_id,
    utils::u16               old_skdc_id,
    utils::u16               new_skdc_id,
    utils::u16               old_cluster_id,
    utils::u16               new_cluster_id,
    utils::u32               uav_index_old,
    utils::u32               uav_index_new,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        HandoverPhase::OLD_LEAVE,
        uav_id, old_skdc_id, new_skdc_id,
        NodeTypeCode::SKDC, NodeTypeCode::SKDC,
        old_cluster_id, new_cluster_id,
        old_skdc_id, new_skdc_id,
        uav_index_old, uav_index_new, 0, 0,
        hmac_key, seq);
}

HandoverPacket HandoverPacket::BuildAccept(
    utils::u16               uav_id,
    utils::u16               new_skdc_id,
    utils::u16               old_cluster_id,
    utils::u16               new_cluster_id,
    utils::u32               uav_index_new,
    utils::u32               new_version,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        HandoverPhase::NEW_JOIN,
        uav_id, new_skdc_id, uav_id,
        NodeTypeCode::SKDC, NodeTypeCode::UAV,
        old_cluster_id, new_cluster_id,
        0, new_skdc_id,
        0, uav_index_new, 0, new_version,
        hmac_key, seq);
}

HandoverPacket HandoverPacket::BuildRekey(
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    utils::u32               version,
    HandoverPhase            phase,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        phase,
        0, skdc_id, 0xFFFF,
        NodeTypeCode::SKDC, NodeTypeCode::UAV,
        cluster_id, cluster_id,
        skdc_id, skdc_id,
        0, 0, version, version,
        hmac_key, seq);
}

HandoverPacket HandoverPacket::BuildComplete(
    utils::u16               uav_id,
    utils::u16               new_skdc_id,
    utils::u16               old_cluster_id,
    utils::u16               new_cluster_id,
    utils::u32               uav_index_new,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        HandoverPhase::COMPLETE,
        uav_id, uav_id, new_skdc_id,
        NodeTypeCode::UAV, NodeTypeCode::SKDC,
        old_cluster_id, new_cluster_id,
        0, new_skdc_id,
        0, uav_index_new, 0, 0,
        hmac_key, seq);
}

// ===========================================================================
// Serialize: [HEADER(32)][NONCE(16)][BODY(64)]
// ===========================================================================
utils::ByteBuffer HandoverPacket::Serialize() const {
    utils::ByteBuffer buf;
    buf.reserve(BaseHeader::WIRE_SIZE +
                BaseHeader::NONCE_SIZE +
                HandoverBody::WIRE_SIZE);

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
HandoverPacket HandoverPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        HandoverBody::WIRE_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "HandoverPacket::Deserialize: too small ("
            + std::to_string(wire.size()) + ")");
    }

    auto body =
        crypto::HmacSha256Util::StripAndVerifyHmac(
            hmac_key, wire);

    std::size_t pos = 0;
    HandoverPacket pkt;

    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    pkt.m_header.DeserializeNonce(
        body.data() + pos, body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    pkt.m_body = HandoverBody::Deserialize(body, pos);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string HandoverPacket::Describe() const {
    std::ostringstream oss;
    oss << "HandoverPacket{"
        << HandoverPhaseToString(m_body.phase)
        << " uav="       << m_body.uav_id
        << " "           << m_body.old_cluster_id
        << "->"          << m_body.new_cluster_id
        << " old_skdc="  << m_body.old_skdc_id
        << " new_skdc="  << m_body.new_skdc_id
        << " seq="       << m_header.sequence_num
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
