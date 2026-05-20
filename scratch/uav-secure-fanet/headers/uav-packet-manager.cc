/**
 * headers/uav-packet-manager.cc
 */

#include "uav-packet-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-string-utils.h"

#include <sstream>

namespace uav {
namespace packet {

// ===========================================================================
// PacketStats::Summary
// ===========================================================================
std::string PacketStats::Summary() const {
    std::ostringstream oss;
    oss << "PacketStats{"
        << " tx="       << tx_total
        << " rx="       << rx_total
        << " auth="     << rx_auth
        << " join="     << rx_join
        << " rekey="    << rx_rekey
        << " mtk="      << rx_mtk
        << " handover=" << rx_handover
        << " data="     << rx_data
        << " err_hmac=" << err_hmac
        << " err_fmt="  << err_format
        << "}";
    return oss.str();
}

// ===========================================================================
// PacketManager constructor
// ===========================================================================
PacketManager::PacketManager(
    utils::u16               node_id,
    utils::u16               cluster_id,
    const crypto::HmacKey&   hmac_key,
    const crypto::AesGcmKey& tek)
    : m_node_id(node_id)
    , m_cluster_id(cluster_id)
    , m_hmac_key(hmac_key)
    , m_tek(tek)
{}

// ===========================================================================
// Key updates
// ===========================================================================
void PacketManager::UpdateHmacKey(const crypto::HmacKey& key) {
    m_hmac_key = key;
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "PacketManager[" << m_node_id << "]: HMAC key updated");
}

void PacketManager::UpdateTek(const crypto::AesGcmKey& tek) {
    m_tek = tek;
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "PacketManager[" << m_node_id << "]: TEK updated");
}

// ===========================================================================
// Serialization helpers — append HMAC and track stats
// ===========================================================================
utils::ByteBuffer PacketManager::SerializeAuth(
    AuthPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

utils::ByteBuffer PacketManager::SerializeJoin(
    JoinPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

utils::ByteBuffer PacketManager::SerializeRekey(
    RekeyPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

utils::ByteBuffer PacketManager::SerializeMtk(
    MtkPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

utils::ByteBuffer PacketManager::SerializeHandover(
    HandoverPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

utils::ByteBuffer PacketManager::SerializeData(
    DataPacket& pkt)
{
    auto wire = pkt.Serialize();
    crypto::HmacSha256Util::AppendHmac(m_hmac_key, wire);
    ++m_stats.tx_total;
    return wire;
}

// ===========================================================================
// PeekType — read packet_type byte from wire without full parse
// Byte offset 3 in BaseHeader = packet_type
// ===========================================================================
PacketType PacketManager::PeekType(
    const utils::ByteBuffer& wire)
{
    if (wire.size() < 4) {
        return PacketType::UNKNOWN;
    }
    // Validate magic first
    utils::u16 magic = static_cast<utils::u16>(
        (static_cast<utils::u16>(wire[0]) << 8) | wire[1]);
    if (magic != BaseHeader::MAGIC) {
        return PacketType::UNKNOWN;
    }
    return static_cast<PacketType>(wire[3]);
}

// ===========================================================================
// Dispatch — parse and call handler
// ===========================================================================
bool PacketManager::Dispatch(const utils::ByteBuffer& wire) {
    PacketType type = PeekType(wire);

    if (type == PacketType::UNKNOWN) {
        ++m_stats.err_format;
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "PacketManager::Dispatch: unknown magic/type");
        return false;
    }

    ++m_stats.rx_total;

    try {
        switch (type) {

        case PacketType::AUTH_PACKET: {
            auto pkt = AuthPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_auth;
            if (m_auth_handler) m_auth_handler(pkt);
            break;
        }

        case PacketType::JOIN_PACKET:
        case PacketType::LEAVE_PACKET: {
            auto pkt = JoinPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_join;
            if (m_join_handler) m_join_handler(pkt);
            break;
        }

        case PacketType::REKEY_PACKET: {
            auto pkt = RekeyPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_rekey;
            if (m_rekey_handler) m_rekey_handler(pkt);
            break;
        }

        case PacketType::MTK_PACKET: {
            auto pkt = MtkPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_mtk;
            if (m_mtk_handler) m_mtk_handler(pkt);
            break;
        }

        case PacketType::HANDOVER_PACKET: {
            auto pkt = HandoverPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_handover;
            if (m_handover_handler)
                m_handover_handler(pkt);
            break;
        }

        case PacketType::DATA_PACKET: {
            auto pkt = DataPacket::Deserialize(
                wire, m_hmac_key);
            ++m_stats.rx_data;
            if (m_data_handler) m_data_handler(pkt);
            break;
        }

        default:
            ++m_stats.err_format;
            UAV_LOG_WARN(uav::log::channels::PACKET,
                "PacketManager::Dispatch: unhandled type "
                << PacketTypeToString(type));
            return false;
        }

    } catch (const utils::CryptoException&) {
        ++m_stats.err_hmac;
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "PacketManager::Dispatch: HMAC/crypto failure");
        return false;
    } catch (const utils::SerializationException&) {
        ++m_stats.err_format;
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "PacketManager::Dispatch: format error");
        return false;
    }

    return true;
}

// ===========================================================================
// Factory helpers
// ===========================================================================
utils::ByteBuffer PacketManager::MakeAuthRequest(
    utils::u16 skdc_id,
    utils::u16 cluster_id)
{
    auto pkt = AuthPacket::BuildRequest(
        m_node_id, skdc_id, cluster_id,
        m_hmac_key, m_seq);
    return SerializeAuth(pkt);
}

utils::ByteBuffer PacketManager::MakeJoinRequest(
    utils::u16 skdc_id,
    utils::u16 cluster_id,
    utils::u32 uav_index)
{
    auto pkt = JoinPacket::BuildRequest(
        m_node_id, skdc_id, cluster_id,
        uav_index, m_hmac_key, m_seq);
    return SerializeJoin(pkt);
}

utils::ByteBuffer PacketManager::MakeDataPacket(
    utils::u16               skdc_id,
    utils::u32               data_seq,
    const utils::ByteBuffer& plaintext)
{
    auto pkt = DataPacket::Build(
        m_cluster_id, m_node_id, skdc_id,
        data_seq, plaintext,
        m_tek, m_hmac_key, m_seq);
    return SerializeData(pkt);
}

} // namespace packet
} // namespace uav
