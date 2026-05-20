/**
 * headers/uav-auth-packet.cc
 */

#include "uav-auth-packet.h"
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
// AuthType string
// ===========================================================================
const char* AuthTypeToString(AuthType t) {
    switch (t) {
        case AuthType::UNKNOWN:  return "UNKNOWN";
        case AuthType::REQUEST:  return "REQUEST";
        case AuthType::RESPONSE: return "RESPONSE";
    }
    return "UNKNOWN";
}

// ===========================================================================
// AuthBody::Serialize
// WIRE FORMAT (48 bytes):
//   [0]     auth_type  u8
//   [1]     status     u8
//   [2-3]   uav_id     u16 BE
//   [4-5]   skdc_id    u16 BE
//   [6-7]   cluster_id u16 BE
//   [8-23]  challenge  16 bytes
//   [24-39] response   16 bytes
//   [40-47] timestamp  u64 BE
// ===========================================================================
utils::ByteBuffer AuthBody::Serialize() const {
    utils::ByteBuffer buf(WIRE_SIZE, 0x00);
    utils::u8* p = buf.data();

    p[0] = static_cast<utils::u8>(auth_type);
    p[1] = static_cast<utils::u8>(status);
    utils::ByteUtils::WriteU16BE(p + 2, uav_id);
    utils::ByteUtils::WriteU16BE(p + 4, skdc_id);
    utils::ByteUtils::WriteU16BE(p + 6, cluster_id);
    std::memcpy(p + 8,  challenge.data(), 16);
    std::memcpy(p + 24, response.data(),  16);
    utils::ByteUtils::WriteU64BE(p + 40, timestamp_us);

    return buf;
}

AuthBody AuthBody::Deserialize(const utils::ByteBuffer& buf,
                                std::size_t offset)
{
    return Deserialize(buf.data(), buf.size(), offset);
}

AuthBody AuthBody::Deserialize(const utils::u8* data,
                                std::size_t len,
                                std::size_t offset)
{
    if (len < offset + WIRE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "AuthBody::Deserialize: buffer too small ("
            + std::to_string(len) + " bytes at offset "
            + std::to_string(offset) + ")");
    }

    const utils::u8* p = data + offset;
    AuthBody body;

    body.auth_type   = static_cast<AuthType>(p[0]);
    body.status      = static_cast<AuthStatus>(p[1]);
    body.uav_id      = utils::ByteUtils::ReadU16BE(p + 2);
    body.skdc_id     = utils::ByteUtils::ReadU16BE(p + 4);
    body.cluster_id  = utils::ByteUtils::ReadU16BE(p + 6);
    std::memcpy(body.challenge.data(), p + 8,  16);
    std::memcpy(body.response.data(),  p + 24, 16);
    body.timestamp_us = utils::ByteUtils::ReadU64BE(p + 40);

    return body;
}

// ===========================================================================
// AuthPacket::BuildRequest — UAV → SKDC
// ===========================================================================
AuthPacket AuthPacket::BuildRequest(
    utils::u16              uav_id,
    utils::u16              skdc_id,
    utils::u16              cluster_id,
    [[maybe_unused]] const crypto::HmacKey&  hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;  // HMAC appended externally

    AuthPacket pkt;

    // Body
    pkt.m_body.auth_type    = AuthType::REQUEST;
    pkt.m_body.status       = AuthStatus::PENDING;
    pkt.m_body.uav_id       = uav_id;
    pkt.m_body.skdc_id      = skdc_id;
    pkt.m_body.cluster_id   = cluster_id;
    pkt.m_body.timestamp_us =
        utils::TimeUtils::NowEpochMicros();

    // Challenge is zero in request (SKDC fills it in response)
    pkt.m_body.challenge.fill(0);
    pkt.m_body.response.fill(0);

    // Header
    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::AUTH_PACKET,
        cluster_id,
        uav_id,
        skdc_id,
        NodeTypeCode::UAV,
        NodeTypeCode::SKDC,
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::CRITICAL);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(AuthBody::WIRE_SIZE);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "AuthPacket::BuildRequest: uav=" << uav_id
        << " skdc=" << skdc_id
        << " cluster=" << cluster_id);

    return pkt;
}

// ===========================================================================
// AuthPacket::BuildResponse — SKDC → UAV
// ===========================================================================
AuthPacket AuthPacket::BuildResponse(
    utils::u16              uav_id,
    utils::u16              skdc_id,
    utils::u16              cluster_id,
    AuthStatus              status,
    const std::array<utils::u8, 16>& challenge,
    [[maybe_unused]] const crypto::HmacKey&  hmac_key,
    crypto::SequenceCounter& seq)
{
    (void)hmac_key;  // HMAC appended externally

    AuthPacket pkt;

    // Body
    pkt.m_body.auth_type    = AuthType::RESPONSE;
    pkt.m_body.status       = status;
    pkt.m_body.uav_id       = uav_id;
    pkt.m_body.skdc_id      = skdc_id;
    pkt.m_body.cluster_id   = cluster_id;
    pkt.m_body.challenge    = challenge;
    pkt.m_body.timestamp_us =
        utils::TimeUtils::NowEpochMicros();
    pkt.m_body.response.fill(0);

    // Header
    auto token = crypto::ReplayToken::Generate(seq.Next());

    pkt.m_header = BaseHeader(
        PacketType::AUTH_PACKET,
        cluster_id,
        skdc_id,
        uav_id,
        NodeTypeCode::SKDC,
        NodeTypeCode::UAV,
        PacketFlag::REPLAY_PROTECTED |
        PacketFlag::HMAC_PRESENT,
        PacketPriority::CRITICAL);

    pkt.m_header.ApplyReplayToken(token);
    pkt.m_header.payload_len =
        static_cast<utils::u16>(AuthBody::WIRE_SIZE);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "AuthPacket::BuildResponse: uav=" << uav_id
        << " status=" << AuthStatusToString(status));

    return pkt;
}

// ===========================================================================
// AuthPacket::Serialize
// Layout: [HEADER(32)][NONCE(16)][BODY(48)]
// ===========================================================================
utils::ByteBuffer AuthPacket::Serialize() const {
    utils::ByteBuffer buf;
    buf.reserve(BaseHeader::WIRE_SIZE +
                BaseHeader::NONCE_SIZE +
                AuthBody::WIRE_SIZE);

    // Header (32)
    m_header.SerializeTo(buf);

    // Nonce (16)
    auto nonce_buf = m_header.SerializeNonce();
    utils::ByteUtils::AppendBytes(buf, nonce_buf);

    // Body (48)
    auto body_buf = m_body.Serialize();
    utils::ByteUtils::AppendBytes(buf, body_buf);

    return buf;
}

// ===========================================================================
// AuthPacket::Deserialize
// ===========================================================================
AuthPacket AuthPacket::Deserialize(
    const utils::ByteBuffer& wire,
    const crypto::HmacKey&   hmac_key)
{
    // Min size: 32+16+48+32 = 128
    constexpr std::size_t MIN_WIRE =
        BaseHeader::WIRE_SIZE +
        BaseHeader::NONCE_SIZE +
        AuthBody::WIRE_SIZE +
        crypto::HMAC_SHA256_OUTPUT_BYTES;

    if (wire.size() < MIN_WIRE) {
        UAV_THROW(utils::SerializationException,
            "AuthPacket::Deserialize: too small ("
            + std::to_string(wire.size()) + " < "
            + std::to_string(MIN_WIRE) + ")");
    }

    // Verify + strip HMAC
    auto body = crypto::HmacSha256Util::StripAndVerifyHmac(
        hmac_key, wire);

    std::size_t pos = 0;
    AuthPacket pkt;

    // Header
    pkt.m_header = BaseHeader::Deserialize(body, pos);
    pos += BaseHeader::WIRE_SIZE;

    // Nonce
    pkt.m_header.DeserializeNonce(
        body.data() + pos, body.size() - pos);
    pos += BaseHeader::NONCE_SIZE;

    // Body
    pkt.m_body = AuthBody::Deserialize(body, pos);

    return pkt;
}

// ===========================================================================
// Describe
// ===========================================================================
std::string AuthPacket::Describe() const {
    std::ostringstream oss;
    oss << "AuthPacket{"
        << AuthTypeToString(m_body.auth_type)
        << " uav="     << m_body.uav_id
        << " skdc="    << m_body.skdc_id
        << " cluster=" << m_body.cluster_id
        << " status="  << AuthStatusToString(m_body.status)
        << " seq="     << m_header.sequence_num
        << "}";
    return oss.str();
}

} // namespace packet
} // namespace uav
