/**
 * headers/uav-packet-manager.h
 *
 * Packet Serialization Manager — unified serialize/deserialize/route.
 *
 * PURPOSE:
 *   Central point for all packet I/O in the simulation.
 *   - Serialize any packet type to wire bytes with HMAC
 *   - Deserialize wire bytes to correct packet type
 *   - Route received packets to registered handlers
 *   - Track per-cluster sequence counters
 *   - Validate packet structure before dispatch
 *
 * USAGE:
 *   PacketManager mgr(cluster_id, node_id, hmac_key, tek);
 *
 *   // Send
 *   auto wire = mgr.SerializeAuth(pkt);
 *   auto wire = mgr.SerializeData(pkt);
 *
 *   // Receive
 *   mgr.RegisterHandler(PacketType::AUTH_PACKET, myHandler);
 *   mgr.Dispatch(wire);   // auto-detects type, verifies, calls handler
 *
 *   // Stats
 *   auto stats = mgr.GetStats();
 */

#ifndef UAV_PACKET_MANAGER_H
#define UAV_PACKET_MANAGER_H

#include "uav-auth-packet.h"
#include "uav-join-packet.h"
#include "uav-rekey-packet.h"
#include "uav-mtk-packet.h"
#include "uav-handover-packet.h"
#include "uav-data-packet.h"
#include "uav-base-header.h"
#include "uav-packet-enums.h"
#include "uav-hmac.h"
#include "uav-aes.h"
#include "uav-replay.h"
#include "uav-types.h"
#include "uav-error.h"

#include <functional>
#include <unordered_map>
#include <string>
#include <memory>
#include <atomic>

namespace uav {
namespace packet {

// ===========================================================================
// PacketStats — per-manager counters
// ===========================================================================
struct PacketStats {
    std::atomic<utils::u64> tx_total    {0};
    std::atomic<utils::u64> rx_total    {0};
    std::atomic<utils::u64> rx_auth     {0};
    std::atomic<utils::u64> rx_join     {0};
    std::atomic<utils::u64> rx_rekey    {0};
    std::atomic<utils::u64> rx_mtk      {0};
    std::atomic<utils::u64> rx_handover {0};
    std::atomic<utils::u64> rx_data     {0};
    std::atomic<utils::u64> err_hmac    {0};
    std::atomic<utils::u64> err_replay  {0};
    std::atomic<utils::u64> err_format  {0};

    void Reset() {
        tx_total    = 0; rx_total    = 0;
        rx_auth     = 0; rx_join     = 0;
        rx_rekey    = 0; rx_mtk      = 0;
        rx_handover = 0; rx_data     = 0;
        err_hmac    = 0; err_replay  = 0;
        err_format  = 0;
    }

    std::string Summary() const;
};

// ===========================================================================
// Handler types
// ===========================================================================
using AuthHandler     = std::function<void(const AuthPacket&)>;
using JoinHandler     = std::function<void(const JoinPacket&)>;
using RekeyHandler    = std::function<void(const RekeyPacket&)>;
using MtkHandler      = std::function<void(const MtkPacket&)>;
using HandoverHandler = std::function<void(const HandoverPacket&)>;
using DataHandler     = std::function<void(const DataPacket&)>;

// ===========================================================================
// PacketManager
// ===========================================================================
class PacketManager {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    PacketManager(utils::u16              node_id,
                  utils::u16              cluster_id,
                  const crypto::HmacKey&  hmac_key,
                  const crypto::AesGcmKey& tek);

    // -----------------------------------------------------------------------
    // Update keys (on rekey)
    // -----------------------------------------------------------------------
    void UpdateHmacKey(const crypto::HmacKey& key);
    void UpdateTek(const crypto::AesGcmKey& tek);

    // -----------------------------------------------------------------------
    // Serialization — produce wire bytes (header+body+HMAC)
    // -----------------------------------------------------------------------
    utils::ByteBuffer SerializeAuth(AuthPacket& pkt);
    utils::ByteBuffer SerializeJoin(JoinPacket& pkt);
    utils::ByteBuffer SerializeRekey(RekeyPacket& pkt);
    utils::ByteBuffer SerializeMtk(MtkPacket& pkt);
    utils::ByteBuffer SerializeHandover(HandoverPacket& pkt);
    utils::ByteBuffer SerializeData(DataPacket& pkt);

    // -----------------------------------------------------------------------
    // Peek packet type from wire bytes without full parse
    // -----------------------------------------------------------------------
    static PacketType PeekType(const utils::ByteBuffer& wire);

    // -----------------------------------------------------------------------
    // Dispatch — parse wire bytes and call registered handler
    // Returns false if packet rejected (HMAC/format error)
    // -----------------------------------------------------------------------
    bool Dispatch(const utils::ByteBuffer& wire);

    // -----------------------------------------------------------------------
    // Handler registration
    // -----------------------------------------------------------------------
    void OnAuth    (AuthHandler     h) { m_auth_handler     = h; }
    void OnJoin    (JoinHandler     h) { m_join_handler     = h; }
    void OnRekey   (RekeyHandler    h) { m_rekey_handler    = h; }
    void OnMtk     (MtkHandler      h) { m_mtk_handler      = h; }
    void OnHandover(HandoverHandler h) { m_handover_handler = h; }
    void OnData    (DataHandler     h) { m_data_handler     = h; }

    // -----------------------------------------------------------------------
    // Factory helpers — build + serialize in one call
    // -----------------------------------------------------------------------
    utils::ByteBuffer MakeAuthRequest(
        utils::u16 skdc_id, utils::u16 cluster_id);

    utils::ByteBuffer MakeJoinRequest(
        utils::u16 skdc_id, utils::u16 cluster_id,
        utils::u32 uav_index);

    utils::ByteBuffer MakeDataPacket(
        utils::u16 skdc_id, utils::u32 data_seq,
        const utils::ByteBuffer& plaintext);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    const PacketStats& GetStats() const { return m_stats; }
    void ResetStats() { m_stats.Reset(); }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    utils::u16 GetNodeId()    const { return m_node_id;    }
    utils::u16 GetClusterId() const { return m_cluster_id; }

private:
    utils::u16              m_node_id;
    utils::u16              m_cluster_id;
    crypto::HmacKey         m_hmac_key;
    crypto::AesGcmKey       m_tek;
    crypto::SequenceCounter m_seq;
    PacketStats             m_stats;

    AuthHandler     m_auth_handler;
    JoinHandler     m_join_handler;
    RekeyHandler    m_rekey_handler;
    MtkHandler      m_mtk_handler;
    HandoverHandler m_handover_handler;
    DataHandler     m_data_handler;
};

} // namespace packet
} // namespace uav

#endif // UAV_PACKET_MANAGER_H
