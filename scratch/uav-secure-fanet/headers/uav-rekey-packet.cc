/**
 * headers/uav-rekey-packet.cc
 */

#include "uav-rekey-packet.h"
#include "uav-byte-utils.h"
#include "uav-time-utils.h"
#include "uav-string-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <boost/multiprecision/cpp_int.hpp>
#include <cstring>
#include <sstream>

namespace uav {
namespace packet {

// ===========================================================================
// RekeyBody::Serialize
// [0-3]   cluster_id  u32 BE
// [4-7]   version     u32 BE
// [8]     reason      u8
// [9-11]  reserved    3 bytes
// [12-15] mtk_len     u32 BE
// [16-23] timestamp   u64 BE
// [24-39] rekey_nonce 16 bytes
// [40+]   mtk_bytes
// ===========================================================================
utils::ByteBuffer RekeyBody::Serialize() const {
    // Compute MTK byte size
    std::size_t mtk_size = (mtk > 0)
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(mtk)) + 8) / 8
        : 1;
    auto mtk_bytes = crypto::BigIntOps::ToBytes(mtk, mtk_size);

    utils::ByteBuffer buf;
    buf.reserve(FIXED_SIZE + mtk_bytes.size());

    utils::ByteUtils::AppendU32BE(buf, cluster_id);
    utils::ByteUtils::AppendU32BE(buf, version);
    buf.push_back(static_cast<utils::u8>(reason));
    buf.push_back(0x00);  // reserved
    buf.push_back(0x00);
    buf.push_back(0x00);
    utils::ByteUtils::AppendU32BE(buf,
        static_cast<utils::u32>(mtk_bytes.size()));
    utils::ByteUtils::AppendU64BE(buf, timestamp_us);
    utils::ByteUtils::AppendBytes(buf,
        rekey_nonce.data(), rekey_nonce.size());
    utils::ByteUtils::AppendBytes(buf, mtk_bytes);

    return buf;
}

RekeyBody RekeyBody::Deserialize(
    const utils::ByteBuffer& buf,
    std::size_t offset)
{
    if (buf.size() < offset + FIXED_SIZE) {
        UAV_THROW(utils::SerializationException,
            "RekeyBody::Deserialize: buffer too small");
    }

    const utils::u8* p = buf.data() + offset;
    RekeyBody body;

    body.cluster_id  = utils::ByteUtils::ReadU32BE(p + 0);
    body.version     = utils::ByteUtils::ReadU32BE(p + 4);
    body.reason      = static_cast<RekeyReason>(p[8]);
    utils::u32 mtk_len = utils::ByteUtils::ReadU32BE(p + 12);
    body.timestamp_us = utils::ByteUtils::ReadU64BE(p + 16);
    std::memcpy(body.rekey_nonce.data(), p + 24, 16);

    std::size_t pos = offset + FIXED_SIZE;
    if (buf.size() < pos + mtk_len) {
        UAV_THROW(utils::SerializationException,
            "RekeyBody::Deserialize: truncated MTK");
    }

    utils::ByteBuffer mtk_bytes(
        buf.begin() + static_cast<std::ptrdiff_t>(pos),
        buf.begin() + static_cast<std::ptrdiff_t>(pos + mtk_len));
    body.mtk = crypto::BigIntOps::FromBytes(mtk_bytes);

    return body;
}

std::size_t RekeyBody::WireSize() const {
    std::size_t mtk_size = (mtk > 0)
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(mtk)) + 8) / 8
        : 1;
    return FIXED_SIZE + mtk_size;
}

// ===========================================================================
// RekeyPacket::Build
// ===========================================================================
RekeyPacket RekeyPacket::Build(
    utils::u32               cluster_id,
    utils::u16               skdc_id,
    utils::u32               version,
    RekeyReason              reason,
    const crypto::BigInt&    mtk,
    [[maybe_unused]] const crypto::HmacKey&   hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;

    RekeyPacket pkt;

    pkt.m_body.cluster_id   = cluster_id;
    pkt.m_body.version      = version;
    pkt.m_body.reason       = reason;
    pkt.m_body.mtk          = mtk;
    pkt.m_body.timestamp_us =
        utils::TimeUtils::NowEpochMicros();
    pkt.m_body.rekey_nonce  =
        crypto::OpenSSLRand::RandomNonce128();

    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::REKEY_PACKET,
        static_cast<utils::u16>(cluster_id),
        skdc_id,
        0xFFFF,   // broadcast to cluster
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        PacketFlag::HAS_MTK |
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::CRITICAL);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(pkt.m_body.WireSize());

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "RekeyPacket::Build: cluster=" << cluster_id
        << " version=" << version
        << " reason=" << RekeyReasonToString(reason));

    return pkt;
}

// ===========================================================================
// Serialize: [HEADER(32)][NONCE(16)][BODY(var)]
// ===========================================================================
utils::ByteBuffer RekeyPacket::Serialize() const {
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
RekeyPacket RekeyPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        RekeyBody::FIXED_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "RekeyPacket::Deserialize: too small ("
            + std::to_string(wire.size()) + ")");
    }

    auto body =
        crypto::HmacSha256Util::StripAndVerifyHmac(
            hmac_key, wire);

    std::size_t pos = 0;
    RekeyPacket pkt;

    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    pkt.m_header.DeserializeNonce(
        body.data() + pos, body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    pkt.m_body = RekeyBody::Deserialize(body, pos);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string RekeyPacket::Describe() const {
    std::ostringstream oss;
    oss << "RekeyPacket{"
        << " cluster=" << m_body.cluster_id
        << " version=" << m_body.version
        << " reason="  << RekeyReasonToString(m_body.reason)
        << " mtk="
        << crypto::BigIntOps::ToDecString(
               m_body.mtk).substr(0, 20) << "..."
        << " seq=" << m_header.sequence_num
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
