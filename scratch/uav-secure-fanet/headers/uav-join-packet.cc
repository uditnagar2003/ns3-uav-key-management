/**
 * headers/uav-join-packet.cc
 */

#include "uav-join-packet.h"
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
// JoinType string
// ===========================================================================
const char* JoinTypeToString(JoinType t) {
    switch (t) {
        case JoinType::UNKNOWN:  return "UNKNOWN";
        case JoinType::REQUEST:  return "REQUEST";
        case JoinType::ACCEPT:   return "ACCEPT";
        case JoinType::REJECT:   return "REJECT";
        case JoinType::NOTIFY:   return "NOTIFY";
        case JoinType::LEAVE:    return "LEAVE";
    }
    return "UNKNOWN";
}

// ===========================================================================
// JoinBody::Serialize (56 bytes)
// [0]     join_type  u8
// [1]     reserved   u8
// [2-3]   uav_id     u16 BE
// [4-5]   skdc_id    u16 BE
// [6-7]   cluster_id u16 BE
// [8-23]  identity   16 bytes
// [24-39] join_nonce 16 bytes
// [40-47] timestamp  u64 BE
// [48-51] uav_index  u32 BE
// [52-55] version    u32 BE
// ===========================================================================
utils::ByteBuffer JoinBody::Serialize() const {
    utils::ByteBuffer buf(WIRE_SIZE, 0x00);
    utils::u8* p = buf.data();

    p[0] = static_cast<utils::u8>(join_type);
    p[1] = reserved;
    utils::ByteUtils::WriteU16BE(p + 2,  uav_id);
    utils::ByteUtils::WriteU16BE(p + 4,  skdc_id);
    utils::ByteUtils::WriteU16BE(p + 6,  cluster_id);
    std::memcpy(p + 8,  identity.data(),   16);
    std::memcpy(p + 24, join_nonce.data(), 16);
    utils::ByteUtils::WriteU64BE(p + 40, timestamp_us);
    utils::ByteUtils::WriteU32BE(p + 48, uav_index);
    utils::ByteUtils::WriteU32BE(p + 52, version);

    return buf;
}

JoinBody JoinBody::Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset)
{
    return Deserialize(buf.data(), buf.size(), offset);
}

JoinBody JoinBody::Deserialize(const utils::u8* data,
                                std::size_t len,
                                std::size_t offset)
{
    if (len < offset + WIRE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "JoinBody::Deserialize: buffer too small");
    }

    const utils::u8* p = data + offset;
    JoinBody body;

    body.join_type   = static_cast<JoinType>(p[0]);
    body.reserved    = p[1];
    body.uav_id      = utils::ByteUtils::ReadU16BE(p + 2);
    body.skdc_id     = utils::ByteUtils::ReadU16BE(p + 4);
    body.cluster_id  = utils::ByteUtils::ReadU16BE(p + 6);
    std::memcpy(body.identity.data(),   p + 8,  16);
    std::memcpy(body.join_nonce.data(), p + 24, 16);
    body.timestamp_us = utils::ByteUtils::ReadU64BE(p + 40);
    body.uav_index    = utils::ByteUtils::ReadU32BE(p + 48);
    body.version      = utils::ByteUtils::ReadU32BE(p + 52);

    return body;
}

// ===========================================================================
// Internal builder
// ===========================================================================
JoinPacket JoinPacket::BuildInternal(
    JoinType                 join_type,
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    utils::u32               uav_index,
    utils::u32               version,
    NodeTypeCode             src_type,
    NodeTypeCode             dst_type,
    utils::u16               dst_id,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;  // HMAC appended externally

    JoinPacket pkt;

    // Body
    pkt.m_body.join_type    = join_type;
    pkt.m_body.uav_id       = uav_id;
    pkt.m_body.skdc_id      = skdc_id;
    pkt.m_body.cluster_id   = cluster_id;
    pkt.m_body.uav_index    = uav_index;
    pkt.m_body.version      = version;
    pkt.m_body.timestamp_us =
        utils::TimeUtils::NowEpochMicros();

    // Identity = hash-like material from uav_id
    // (in production: derived from UAV's public material)
    pkt.m_body.identity.fill(0);
    utils::ByteUtils::WriteU16BE(
        pkt.m_body.identity.data(), uav_id);
    utils::ByteUtils::WriteU16BE(
        pkt.m_body.identity.data() + 2, cluster_id);

    // Fresh nonce
    pkt.m_body.join_nonce =
        crypto::OpenSSLRand::RandomNonce128();

    // Header
    auto token = crypto::ReplayToken::Generate(seq.Next());

    // For NOTIFY: src=SKDC, dst=broadcast
    utils::u16 src_id = (src_type == NodeTypeCode::SKDC)
                      ? skdc_id : uav_id;

    pkt.m_header = BaseHeader(
        PacketType::JOIN_PACKET,
        cluster_id,
        src_id,
        dst_id,
        src_type,
        dst_type,
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::HIGH);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(JoinBody::WIRE_SIZE);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "JoinPacket::Build: type="
        << JoinTypeToString(join_type)
        << " uav=" << uav_id
        << " cluster=" << cluster_id);

    return pkt;
}

// ===========================================================================
// Factory methods
// ===========================================================================
JoinPacket JoinPacket::BuildRequest(
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    utils::u32               uav_index,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        JoinType::REQUEST,
        uav_id, skdc_id, cluster_id,
        uav_index, 0,
        NodeTypeCode::UAV,
        NodeTypeCode::SKDC,
        skdc_id,
        hmac_key, seq);
}

JoinPacket JoinPacket::BuildAccept(
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    utils::u32               uav_index,
    utils::u32               new_version,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        JoinType::ACCEPT,
        uav_id, skdc_id, cluster_id,
        uav_index, new_version,
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        uav_id,
        hmac_key, seq);
}

JoinPacket JoinPacket::BuildReject(
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        JoinType::REJECT,
        uav_id, skdc_id, cluster_id,
        0, 0,
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        uav_id,
        hmac_key, seq);
}

JoinPacket JoinPacket::BuildNotify(
    utils::u16               uav_id,
    utils::u16               skdc_id,
    utils::u16               cluster_id,
    utils::u32               uav_index,
    utils::u32               new_version,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    return BuildInternal(
        JoinType::NOTIFY,
        uav_id, skdc_id, cluster_id,
        uav_index, new_version,
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        0xFFFF,   // broadcast
        hmac_key, seq);
}

// ===========================================================================
// Serialize: [HEADER(32)][NONCE(16)][BODY(56)]
// ===========================================================================
utils::ByteBuffer JoinPacket::Serialize() const {
    utils::ByteBuffer buf;
    buf.reserve(BaseHeader::WIRE_SIZE +
                BaseHeader::NONCE_SIZE +
                JoinBody::WIRE_SIZE);

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
JoinPacket JoinPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        JoinBody::WIRE_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "JoinPacket::Deserialize: too small ("
            + std::to_string(wire.size()) + ")");
    }

    // Verify + strip HMAC
    auto body = crypto::HmacSha256Util::StripAndVerifyHmac(
        hmac_key, wire);

    std::size_t pos = 0;
    JoinPacket pkt;

    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    pkt.m_header.DeserializeNonce(
        body.data() + pos, body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    pkt.m_body = JoinBody::Deserialize(body, pos);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string JoinPacket::Describe() const {
    std::ostringstream oss;
    oss << "JoinPacket{"
        << JoinTypeToString(m_body.join_type)
        << " uav="      << m_body.uav_id
        << " skdc="     << m_body.skdc_id
        << " cluster="  << m_body.cluster_id
        << " index="    << m_body.uav_index
        << " version="  << m_body.version
        << " seq="      << m_header.sequence_num
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
