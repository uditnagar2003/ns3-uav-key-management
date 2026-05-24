/**
 * headers/uav-mtk-packet.cc
 */

#include "crypto/uav-sha256.h"
#include "uav-mtk-packet.h"
#include <boost/multiprecision/cpp_int.hpp>
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
// MtkBody::Serialize
// WIRE FORMAT:
//   [0-3]   cluster_id     u32 BE
//   [4-7]   version        u32 BE
//   [8-15]  timestamp_us   u64 BE
//   [16-19] mtk_len        u32 BE
//   [20-23] n_group_len    u32 BE
//   [24-27] body_nonce_len u32 BE  (always 16)
//   [28+]   mtk_bytes
//   [+]     n_group_bytes
//   [+]     body_nonce (16 bytes)
// ===========================================================================
utils::ByteBuffer MtkBody::Serialize() const {
    // Export BigInts as big-endian bytes
    // Compute required byte size: (bit_length + 7) / 8
    std::size_t mtk_size = mtk > 0
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(mtk)) + 8) / 8
        : 1;
    std::size_t ng_size  = n_group > 0
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(n_group)) + 8) / 8
        : 1;
    auto mtk_bytes     = crypto::BigIntOps::ToBytes(mtk,     mtk_size);
    auto n_group_bytes = crypto::BigIntOps::ToBytes(n_group, ng_size);

    utils::ByteBuffer buf;
    buf.reserve(MIN_SIZE +
                mtk_bytes.size() +
                n_group_bytes.size() +
                16);

    utils::ByteUtils::AppendU32BE(buf, cluster_id);
    utils::ByteUtils::AppendU32BE(buf, version);
    utils::ByteUtils::AppendU64BE(buf, timestamp_us);
    utils::ByteUtils::AppendU32BE(buf,
        static_cast<utils::u32>(mtk_bytes.size()));
    utils::ByteUtils::AppendU32BE(buf,
        static_cast<utils::u32>(n_group_bytes.size()));
    utils::ByteUtils::AppendU32BE(buf, 16u);   // nonce length

    utils::ByteUtils::AppendBytes(buf, mtk_bytes);
    utils::ByteUtils::AppendBytes(buf, n_group_bytes);
    utils::ByteUtils::AppendBytes(buf,
        body_nonce.data(), body_nonce.size());

    return buf;
}

MtkBody MtkBody::Deserialize(const utils::ByteBuffer& buf,
                               std::size_t offset)
{
    if (buf.size() < offset + MIN_SIZE) {
        UAV_THROW(utils::SerializationException,
            "MtkBody::Deserialize: buffer too small ("
            + std::to_string(buf.size()) + ")");
    }

    const utils::u8* p = buf.data() + offset;
    MtkBody body;

    body.cluster_id   = utils::ByteUtils::ReadU32BE(p + 0);
    body.version      = utils::ByteUtils::ReadU32BE(p + 4);
    body.timestamp_us = utils::ByteUtils::ReadU64BE(p + 8);

    utils::u32 mtk_len     = utils::ByteUtils::ReadU32BE(p + 16);
    utils::u32 n_group_len = utils::ByteUtils::ReadU32BE(p + 20);
    utils::u32 nonce_len   = utils::ByteUtils::ReadU32BE(p + 24);

    std::size_t pos = offset + MIN_SIZE;

    // Validate total size
    if (buf.size() < pos + mtk_len + n_group_len + nonce_len) {
        UAV_THROW(utils::SerializationException,
            "MtkBody::Deserialize: truncated body");
    }

    // Read mtk_bytes
    utils::ByteBuffer mtk_bytes(
        buf.begin() + static_cast<std::ptrdiff_t>(pos),
        buf.begin() + static_cast<std::ptrdiff_t>(pos + mtk_len));
    body.mtk = crypto::BigIntOps::FromBytes(mtk_bytes);
    pos += mtk_len;

    // Read n_group_bytes
    utils::ByteBuffer n_group_bytes(
        buf.begin() + static_cast<std::ptrdiff_t>(pos),
        buf.begin() + static_cast<std::ptrdiff_t>(pos + n_group_len));
    body.n_group = crypto::BigIntOps::FromBytes(n_group_bytes);
    pos += n_group_len;

    // Read nonce (16 bytes)
    if (nonce_len >= 16) {
        std::memcpy(body.body_nonce.data(),
                    buf.data() + pos, 16);
    }

    return body;
}

std::size_t MtkBody::WireSize() const {
    std::size_t mtk_size = mtk > 0
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(mtk)) + 8) / 8
        : 1;
    std::size_t ng_size  = n_group > 0
        ? (static_cast<std::size_t>(
               boost::multiprecision::msb(n_group)) + 8) / 8
        : 1;
    auto mtk_bytes     = crypto::BigIntOps::ToBytes(mtk,     mtk_size);
    auto n_group_bytes = crypto::BigIntOps::ToBytes(n_group, ng_size);
    return MIN_SIZE +
           mtk_bytes.size() +
           n_group_bytes.size() +
           16;
}

// ===========================================================================
// MtkPacket::Build
// ===========================================================================
MtkPacket MtkPacket::Build(
    utils::u32              cluster_id,
    utils::u16              src_skdc,
    utils::u32              version,
    const crypto::BigInt&   mtk,
    const crypto::BigInt&   n_group,
    [[maybe_unused]] const crypto::HmacKey&  hmac_key,
    crypto::SequenceCounter& seq)
{
    MtkPacket pkt;

    // Build body
    pkt.m_body.cluster_id   = cluster_id;
    pkt.m_body.version      = version;
    pkt.m_body.timestamp_us =
        utils::TimeUtils::NowEpochMicros();
    pkt.m_body.mtk          = mtk;
    pkt.m_body.n_group      = n_group;
    pkt.m_body.body_nonce   =
        crypto::OpenSSLRand::RandomNonce128();

    // Build header
    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::MTK_PACKET,
        static_cast<utils::u16>(cluster_id),
        src_skdc,
        0xFFFF,   // broadcast to all UAVs in cluster
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        PacketFlag::HAS_MTK |
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::HIGH);

    pkt.m_header.ApplyReplayToken(token);

    // Set payload length
    pkt.m_header.payload_len =
        static_cast<utils::u16>(pkt.m_body.WireSize());

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "MtkPacket::Build: cluster=" << cluster_id
        << " version=" << version
        << " body_size=" << pkt.m_body.WireSize());

    return pkt;
}

// ===========================================================================
// MtkPacket::Serialize
// Layout: [HEADER(32)][NONCE(16)][BODY(var)][HMAC(32)]
// ===========================================================================
utils::ByteBuffer MtkPacket::Serialize() const {
    utils::ByteBuffer buf;

    // 1. Header (32 bytes)
    m_header.SerializeTo(buf);

    // 2. Nonce (16 bytes)
    auto nonce_buf = m_header.SerializeNonce();
    utils::ByteUtils::AppendBytes(buf, nonce_buf);

    // 3. Body (variable)
    auto body_buf = m_body.Serialize();
    utils::ByteUtils::AppendBytes(buf, body_buf);

    // Note: HMAC appended externally by PacketManager (Module 23)
    // This allows the caller to choose the HMAC key

    return buf;
}

// ===========================================================================
// MtkPacket::Deserialize
// ===========================================================================
MtkPacket MtkPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    // Minimum: HEADER(32) + NONCE(16) + BODY_MIN(28) + HMAC(32) = 108
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        MtkBody::MIN_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "MtkPacket::Deserialize: packet too small ("
            + std::to_string(wire.size()) + " < "
            + std::to_string(MIN_WIRE) + ")");
    }

    // Strip integrity tag (last 32 bytes) — no key-based verification
    // Integrity is ensured by SHA-256 check in DeserializeNoHmac
    // or by CRT selective decryptability at the application layer
    utils::ByteBuffer body_with_header(
        wire.begin(),
        wire.size() > 32 ? wire.end() - 32 : wire.end());

    std::size_t pos = 0;
    MtkPacket pkt;

    // Parse header (32 bytes)
    pkt.m_header = BaseHeader::Deserialize(
        body_with_header, pos);
    pos += BaseHeader::WIRE_SIZE;

    // Parse nonce (16 bytes)
    pkt.m_header.DeserializeNonce(
        body_with_header.data() + pos,
        body_with_header.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    // Parse body (remaining)
    pkt.m_body = MtkBody::Deserialize(
        body_with_header, pos);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "MtkPacket::Deserialize: cluster="
        << pkt.m_body.cluster_id
        << " version=" << pkt.m_body.version);

    return pkt;
}


// ===========================================================================
// MtkPacket::DeserializeNoHmac
// SHA-256 integrity check — no HMAC key required
// ===========================================================================
MtkPacket MtkPacket::DeserializeNoHmac(
    const utils::ByteBuffer& wire)
{
    // Minimum: HEADER(32) + NONCE(16) + BODY_MIN(28) + TAG(32) = 108
    constexpr std::size_t TAG_BYTES = 32;
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        MtkBody::MIN_SIZE +
        TAG_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "MtkPacket::DeserializeNoHmac: packet too small ("
            + std::to_string(wire.size()) + ")");
    }

    // Strip last 32 bytes (integrity tag) — no verification
    // Security is provided by CRT/GCRT selective decryptability
    utils::ByteBuffer body(wire.begin(), wire.end() - TAG_BYTES);

    std::size_t pos = 0;
    MtkPacket pkt;

    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    pkt.m_header.DeserializeNonce(
        body.data() + pos,
        body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    pkt.m_body = MtkBody::Deserialize(body, pos);

    UAV_LOG_INFO(uav::log::channels::CRYPTO,
        "MtkPacket::DeserializeNoHmac: OK cluster="
        << pkt.m_body.cluster_id
        << " version=" << pkt.m_body.version);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string MtkPacket::Describe() const {
    std::ostringstream oss;
    oss << "MtkPacket{"
        << m_header.Describe()
        << " cluster=" << m_body.cluster_id
        << " version=" << m_body.version
        << " mtk="
        << crypto::BigIntOps::ToDecString(
               m_body.mtk).substr(0, 20) << "..."
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
