/**
 * headers/uav-base-header.cc
 */

#include "uav-base-header.h"
#include "uav-time-utils.h"
#include "uav-string-utils.h"

#include <sstream>
#include <cstring>

namespace uav {
namespace packet {

// ===========================================================================
// BaseHeader constructor
// ===========================================================================
BaseHeader::BaseHeader(PacketType      type,
                       utils::u16      cluster,
                       utils::u16      src,
                       utils::u16      dst,
                       NodeTypeCode    src_t,
                       NodeTypeCode    dst_t,
                       PacketFlag      fl,
                       PacketPriority  prio)
    : magic(MAGIC)
    , version(PROTOCOL_VERSION)
    , packet_type(type)
    , flags(fl)
    , priority(prio)
    , payload_len(0)
    , cluster_id(cluster)
    , src_node_id(src)
    , dst_node_id(dst)
    , src_type(src_t)
    , dst_type(dst_t)
    , timestamp_us(utils::TimeUtils::NowEpochMicros())
    , sequence_num(0)
{
    nonce.fill(0);
}

// ===========================================================================
// Replay token
// ===========================================================================
void BaseHeader::ApplyReplayToken(const crypto::ReplayToken& token) {
    timestamp_us = token.timestamp_us;
    sequence_num = token.sequence_num;
    nonce        = token.nonce;
    SetReplayProtected(true);
}

crypto::ReplayToken BaseHeader::ExtractReplayToken() const {
    crypto::ReplayToken token;
    token.timestamp_us = timestamp_us;
    token.sequence_num = sequence_num;
    token.nonce        = nonce;
    return token;
}

// ===========================================================================
// Serialization
// WIRE FORMAT [32 bytes]:
//   [0-1]   magic       u16 BE
//   [2]     version     u8
//   [3]     packet_type u8
//   [4]     flags       u8
//   [5]     priority    u8
//   [6-7]   payload_len u16 BE
//   [8-9]   cluster_id  u16 BE
//   [10-11] src_node_id u16 BE
//   [12-13] dst_node_id u16 BE
//   [14]    src_type    u8
//   [15]    dst_type    u8
//   [16-23] timestamp   u64 BE
//   [24-31] sequence    u64 BE
// ===========================================================================
utils::ByteBuffer BaseHeader::Serialize() const {
    utils::ByteBuffer buf;
    buf.reserve(WIRE_SIZE);
    SerializeTo(buf);
    return buf;
}

void BaseHeader::SerializeTo(utils::ByteBuffer& buf) const {
    std::size_t start = buf.size();
    buf.resize(start + WIRE_SIZE, 0x00);
    utils::u8* p = buf.data() + start;

    utils::ByteUtils::WriteU16BE(p + 0,  magic);
    p[2]  = version;
    p[3]  = static_cast<utils::u8>(packet_type);
    p[4]  = static_cast<utils::u8>(flags);
    p[5]  = static_cast<utils::u8>(priority);
    utils::ByteUtils::WriteU16BE(p + 6,  payload_len);
    utils::ByteUtils::WriteU16BE(p + 8,  cluster_id);
    utils::ByteUtils::WriteU16BE(p + 10, src_node_id);
    utils::ByteUtils::WriteU16BE(p + 12, dst_node_id);
    p[14] = static_cast<utils::u8>(src_type);
    p[15] = static_cast<utils::u8>(dst_type);
    utils::ByteUtils::WriteU64BE(p + 16, timestamp_us);
    utils::ByteUtils::WriteU64BE(p + 24, sequence_num);
}

BaseHeader BaseHeader::Deserialize(const utils::ByteBuffer& buf,
                                    std::size_t offset)
{
    return Deserialize(buf.data(), buf.size(), offset);
}

BaseHeader BaseHeader::Deserialize(const utils::u8* data,
                                    std::size_t len,
                                    std::size_t offset)
{
    if (len < offset + WIRE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "BaseHeader::Deserialize: buffer too small ("
            + std::to_string(len) + " bytes at offset "
            + std::to_string(offset)
            + ", need " + std::to_string(WIRE_SIZE) + ")");
    }

    const utils::u8* p = data + offset;
    BaseHeader h;

    h.magic       = utils::ByteUtils::ReadU16BE(p + 0);
    h.version     = p[2];
    h.packet_type = static_cast<PacketType>(p[3]);
    h.flags       = static_cast<PacketFlag>(p[4]);
    h.priority    = static_cast<PacketPriority>(p[5]);
    h.payload_len = utils::ByteUtils::ReadU16BE(p + 6);
    h.cluster_id  = utils::ByteUtils::ReadU16BE(p + 8);
    h.src_node_id = utils::ByteUtils::ReadU16BE(p + 10);
    h.dst_node_id = utils::ByteUtils::ReadU16BE(p + 12);
    h.src_type    = static_cast<NodeTypeCode>(p[14]);
    h.dst_type    = static_cast<NodeTypeCode>(p[15]);
    h.timestamp_us= utils::ByteUtils::ReadU64BE(p + 16);
    h.sequence_num= utils::ByteUtils::ReadU64BE(p + 24);

    // Validate magic
    if (h.magic != MAGIC) {
        UAV_THROW(utils::SerializationException,
            "BaseHeader::Deserialize: invalid magic 0x"
            + utils::StringUtils::BytesToHex(
                reinterpret_cast<const utils::u8*>(&h.magic), 2));
    }

    return h;
}

// ===========================================================================
// Nonce serialization
// ===========================================================================
utils::ByteBuffer BaseHeader::SerializeNonce() const {
    utils::ByteBuffer buf(nonce.begin(), nonce.end());
    return buf;
}

void BaseHeader::DeserializeNonce(const utils::u8* data,
                                   std::size_t len)
{
    if (len < NONCE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "BaseHeader::DeserializeNonce: need 16 bytes, got "
            + std::to_string(len));
    }
    std::memcpy(nonce.data(), data, NONCE_SIZE);
}

// ===========================================================================
// Validation
// ===========================================================================
bool BaseHeader::IsValid() const {
    if (magic != MAGIC)               return false;
    if (version != PROTOCOL_VERSION)  return false;
    if (!IsValidPacketType(
            static_cast<utils::u8>(packet_type))) return false;
    return true;
}

std::string BaseHeader::Describe() const {
    std::ostringstream oss;
    oss << "BaseHeader{"
        << "type="      << PacketTypeToString(packet_type)
        << " src="      << src_node_id
        << "("          << NodeTypeCodeToString(src_type) << ")"
        << " dst="      << dst_node_id
        << "("          << NodeTypeCodeToString(dst_type) << ")"
        << " cluster="  << cluster_id
        << " flags=["   << PacketFlagsToString(flags) << "]"
        << " prio="     << PacketPriorityToString(priority)
        << " plen="     << payload_len
        << " seq="      << sequence_num
        << "}";
    return oss.str();
}

// ===========================================================================
// Equality
// ===========================================================================
bool BaseHeader::operator==(const BaseHeader& o) const {
    return magic        == o.magic
        && version      == o.version
        && packet_type  == o.packet_type
        && flags        == o.flags
        && priority     == o.priority
        && payload_len  == o.payload_len
        && cluster_id   == o.cluster_id
        && src_node_id  == o.src_node_id
        && dst_node_id  == o.dst_node_id
        && src_type     == o.src_type
        && dst_type     == o.dst_type
        && timestamp_us == o.timestamp_us
        && sequence_num == o.sequence_num
        && nonce        == o.nonce;
}

// ===========================================================================
// PacketBuilder
// ===========================================================================
PacketBuilder::PacketBuilder(PacketType   type,
                              utils::u16   cluster_id,
                              utils::u16   src_id,
                              utils::u16   dst_id,
                              NodeTypeCode src_type,
                              NodeTypeCode dst_type)
    : m_header(type, cluster_id, src_id, dst_id,
               src_type, dst_type)
{}

PacketBuilder& PacketBuilder::WithFlags(PacketFlag f) {
    m_header.flags = f;
    return *this;
}

PacketBuilder& PacketBuilder::WithPriority(PacketPriority p) {
    m_header.priority = p;
    return *this;
}

PacketBuilder& PacketBuilder::WithReplayToken(
    const crypto::ReplayToken& t)
{
    m_header.ApplyReplayToken(t);
    return *this;
}

PacketBuilder& PacketBuilder::WithPayloadLen(utils::u16 len) {
    m_header.payload_len = len;
    return *this;
}

utils::ByteBuffer PacketBuilder::BuildHeaderBytes() const {
    utils::ByteBuffer buf;
    buf.reserve(BaseHeader::WIRE_SIZE + BaseHeader::NONCE_SIZE);
    m_header.SerializeTo(buf);
    auto nonce_buf = m_header.SerializeNonce();
    utils::ByteUtils::AppendBytes(buf, nonce_buf);
    return buf;
}

} // namespace packet
} // namespace uav
