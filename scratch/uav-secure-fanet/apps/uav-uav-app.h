/**
 * apps/uav-uav-app.h
 * Module 37 - UAV Application
 *
 * UAV RESPONSIBILITIES (per project spec):
 *   - Store slave decryption key
 *   - Store current TEK only
 *   - Decrypt MT_K using slave decryption relation
 *   - Use TEK for AES payload encryption
 *   - Send encrypted data to SKDC
 *   - Handle JOIN/LEAVE/REKEY/HANDOVER events
 *
 * UAV communicates ONLY through associated SKDC.
 * No direct UAV-to-UAV communication.
 *
 * PORTS:
 *   Listen: 9200 (MTK_PORT)   receive MT_K from SKDC
 *   Listen: 9400 (REKEY_PORT) receive rekey from SKDC
 *   Send:   9100+uav_id       send data to SKDC
 */

#ifndef UAV_UAV_APP_H
#define UAV_UAV_APP_H

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"

#include "headers/uav-packet-enums.h"
#include "headers/uav-data-packet.h"
#include "headers/uav-mtk-packet.h"
#include "headers/uav-rekey-packet.h"
#include "headers/uav-auth-packet.h"
#include "headers/uav-join-packet.h"
#include "crypto/uav-handover-protocol.h"
#include "headers/uav-packet-manager.h"
#include "routing/uav-topology.h"
#include "crypto/uav-crypto-params.h"
#include "crypto/uav-crt-manager.h"
#include "crypto/uav-aes.h"
#include "crypto/uav-hmac.h"
#include "crypto/uav-replay.h"
#include "utils/uav-types.h"
#include "utils/uav-error.h"

#include <string>

namespace uav {
namespace apps {

// ===========================================================================
// UavState - per-UAV operational state
// ===========================================================================
struct UavState {
    utils::u32          uav_id       = 0;
    utils::u32          uav_index    = 0;  // 0-5 within cluster
    utils::u32          cluster_id   = 0;
    bool                authenticated = false;
    bool                joined        = false;
    bool                tek_valid     = false;

    // Slave decryption key (from crypto_params.json)
    crypto::BigInt      d_i;
    crypto::BigInt      n_i;
    crypto::BigInt      e_i;

    // Current TEK (recovered from MT_K)
    crypto::AesGcmKey   current_tek  = {};
    crypto::HmacKey     hmac_key     = {};

    // Replay protection
    utils::u32          rekey_version = 0;
    utils::u32          data_seq      = 0;
};

// ===========================================================================
// UavApplication - NS-3 Application
// ===========================================================================
class UavApplication : public ns3::Application {
public:
    static ns3::TypeId GetTypeId();

    UavApplication();
    ~UavApplication() override;

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    void SetUavId(utils::u32 uav_id,
                  utils::u32 uav_index,
                  utils::u32 cluster_id);

    void SetTopology(
        const routing::TopologyResult* topo);

    void SetCryptoParams(
        const crypto::CryptoParamsFile* params);

    // -----------------------------------------------------------------------
    // UAV operations
    // -----------------------------------------------------------------------

    /// Decrypt MT_K using slave key → extract TEK
    // Handover slave key delivery
    void ReceiveJoinAccept(ns3::Ptr<ns3::Socket> s);
    void UpdateSlaveKey(const crypto::SlaveKeyBlob& blob,
                        uint32_t new_cluster,
                        uint32_t new_index);
    void SendKeyAck(uint32_t new_cluster,
                    uint32_t new_index);

    bool DecryptMtk(const crypto::BigInt& mt_k,
                    const crypto::BigInt& n_group);

    /// Send encrypted data to SKDC
    void SendData(const utils::ByteBuffer& payload);

    /// Send periodic telemetry
    void SendTelemetry();

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const UavState& GetState() const {
        return m_state;
    }
    utils::u64 GetDataSentCount() const {
        return m_data_sent;
    }
    utils::u64 GetMtkReceivedCount() const {
        return m_mtk_received;
    }
    utils::u64 GetRekeyCount() const {
        return m_rekey_count;
    }
    bool IsTekValid() const {
        return m_state.tek_valid;
    }

protected:
    void StartApplication() override;
    void StopApplication()  override;

private:
    utils::u32 m_uav_id    = 0;
    utils::u32 m_uav_index = 0;
    utils::u32 m_cluster_id= 0;

    const routing::TopologyResult*  m_topo   = nullptr;
    const crypto::CryptoParamsFile* m_params = nullptr;

    UavState m_state;

    // Sockets
    ns3::Ptr<ns3::Socket> m_recv_socket;  // recv MTK/REKEY
    ns3::Ptr<ns3::Socket>  m_join_acc_socket = nullptr; // recv JOIN_ACCEPT (9052)
    ns3::Ptr<ns3::Socket>  m_ack_send_socket  = nullptr; // send KEY_ACK (9053)
    crypto::GlobalKey      m_gk{};             // Global Bootstrap Key
    ns3::Ptr<ns3::Socket> m_send_socket;  // send DATA

    // Sequence counter
    crypto::SequenceCounter m_seq;

    // Stats
    utils::u64 m_data_sent    = 0;
    utils::u64 m_mtk_received = 0;
    utils::u64 m_rekey_count  = 0;

    // Internal
    void InitializeSlaveKey();
    void ScheduleTelemetry();
    void ReceivePacket(ns3::Ptr<ns3::Socket> socket);
    void ProcessMtkPacket(
        const utils::ByteBuffer& wire);
    void ProcessRekeyPacket(
        const utils::ByteBuffer& wire);

    ns3::Ipv4Address GetSkdcWifiAddr() const;
};

} // namespace apps
} // namespace uav

#endif // UAV_UAV_APP_H
