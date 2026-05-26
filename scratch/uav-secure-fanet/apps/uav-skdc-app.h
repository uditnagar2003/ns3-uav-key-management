/**
 * apps/uav-skdc-app.h
 * Module 36 - SKDC Application
 *
 * SKDC RESPONSIBILITIES (per project spec):
 *   - Generate local CRT master encryption key
 *   - Generate UAV slave decryption keys
 *   - Manage multicast cluster domain
 *   - Broadcast MT_K to UAV cluster
 *   - Manage join/leave rekeying
 *   - Handle secure UAV handover
 *   - Manage TEK synchronization
 *
 * Each SKDC manages one cluster (0,1,2).
 * SKDC communicates with:
 *   - KDC via CSMA (receives TEK)
 *   - UAVs via WiFi adhoc (broadcasts MT_K)
 *
 * PORTS:
 *   Listen: 9001 (SKDC_PORT) on CSMA for KDC
 *   Send:   9200 (MTK_PORT)  on WiFi to UAVs
 */

#ifndef UAV_SKDC_APP_H
#define UAV_SKDC_APP_H

#include "ns3/application.h"
#include "ns3/netanim-module.h"
#include "crypto/uav-handover-protocol.h"
#include <unordered_map>
#include "ns3/netanim-module.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"

#include "headers/uav-packet-enums.h"
#include "headers/uav-mtk-packet.h"
#include "headers/uav-rekey-packet.h"
#include "routing/uav-topology.h"
#include "crypto/uav-crypto-params.h"
#include "crypto/uav-crt-manager.h"
#include "crypto/uav-aes.h"
#include "crypto/uav-hmac.h"
#include "crypto/uav-replay.h"
#include "utils/uav-types.h"
#include "utils/uav-error.h"

#include <array>
#include <vector>
#include <unordered_set>

namespace uav {
namespace apps {

// ===========================================================================
// SkdcState - SKDC operational state
// ===========================================================================
struct SkdcState {
    utils::u32          cluster_id     = 0;
    utils::u32          rekey_version  = 1;
    crypto::AesGcmKey   current_tek    = {};
    crypto::HmacKey     hmac_key       = {};
    crypto::BigInt      mt_k;
    crypto::BigInt      n_group;
    crypto::BigInt      e_mk;
    bool                tek_received   = false;
    std::unordered_set<utils::u32> members;
};

// ===========================================================================
// SkdcApplication - NS-3 Application
// ===========================================================================
class SkdcApplication : public ns3::Application {
public:
    static ns3::TypeId GetTypeId();

    SkdcApplication();
    ~SkdcApplication() override;

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    void SetClusterId(utils::u32 cluster_id);

    // Handover protocol
    void ReceiveSlaveKeyFwd(ns3::Ptr<ns3::Socket> s);
    void SendJoinAccept(uint32_t uav_id,
                        uint32_t new_idx,
                        const crypto::SlaveKeyBlob& blob);
    void ReceiveKeyAck(ns3::Ptr<ns3::Socket> s);

    /// Set NetAnim pointer for data packet visualization
    void SetAnimPtr(
        ns3::AnimationInterface*       anim,
        const routing::TopologyResult* topo,
        uint32_t                       uavs_per_cluster) {
        m_anim_ptr      = anim;
        m_anim_topo     = topo;
        m_uavs_per_clus = uavs_per_cluster;
    }

    /// Set NetAnim pointer for data packet visualization


    void SetTopology(
        const routing::TopologyResult* topo);

    void SetCryptoParams(
        const crypto::CryptoParamsFile* params);

    // -----------------------------------------------------------------------
    // SKDC operations
    // -----------------------------------------------------------------------

    /// Broadcast MT_K to all UAVs in cluster
    void BroadcastMtk();

    /// Process UAV join request
    void ProcessJoin(utils::u32 uav_id,
                     utils::u32 uav_index);

    /// Process UAV leave
    void ProcessLeave(utils::u32 uav_id);

    /// Update TEK from KDC
    void UpdateTek(const crypto::AesGcmKey& tek);

    /// Trigger rekey broadcast
    void TriggerRekey(packet::RekeyReason reason);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    const SkdcState& GetState() const {
        return m_state;
    }
    utils::u64 GetMtkBroadcastCount() const {
        return m_mtk_count;
    }
    utils::u64 GetRekeyCount() const {
        return m_rekey_count;
    }
    utils::u64 GetDataRxCount() const {
        return m_data_rx_count;
    }
    utils::u32 GetMemberCount() const {
        return static_cast<utils::u32>(
            m_state.members.size());
    }

protected:
    void StartApplication() override;
    void StopApplication()  override;

private:
    utils::u32 m_cluster_id = 0;

    const routing::TopologyResult*  m_topo   = nullptr;
    const crypto::CryptoParamsFile* m_params = nullptr;

    SkdcState m_state;

    // Sockets
    ns3::Ptr<ns3::Socket> m_csma_socket;    // recv from KDC
    ns3::Ptr<ns3::Socket> m_wifi_socket;    // send to UAVs
    ns3::Ptr<ns3::Socket> m_data_socket;    // recv DATA from UAVs (port 9100)
    ns3::Ptr<ns3::Socket> m_forward_socket;  // forward telemetry to KDC (9300)
    ns3::Ptr<ns3::Socket> m_slave_fwd_socket; // recv SLAVE_FWD from KDC (9051)
    ns3::Ptr<ns3::Socket> m_ack_socket;       // recv KEY_ACK from UAV (9053)
    ns3::Ptr<ns3::Socket> m_join_acc_socket;  // send JOIN_ACCEPT to UAV (9052)
    crypto::GlobalKey     m_gk{};             // Global Bootstrap Key

    // Pending handover: uav_id → (blob, new_index)
    struct PendingHO {
        crypto::SlaveKeyBlob blob;
        uint32_t new_index = 0;
    };
    std::unordered_map<uint32_t, PendingHO> m_pending_ho;
    ns3::Ipv4Address      m_kdc_csma_addr;  // KDC CSMA address

    // NetAnim pointer for data packet visualization
    ns3::AnimationInterface*       m_anim_ptr       = nullptr;
    const routing::TopologyResult* m_anim_topo      = nullptr;
    uint32_t                       m_uavs_per_clus  = 6;

    // NetAnim pointer for data packet visualization


    // Sequence counter
    crypto::SequenceCounter m_seq;

    // Stats
    utils::u64 m_mtk_count      = 0;
    utils::u64 m_rekey_count    = 0;
    utils::u64 m_data_rx_count  = 0;

    // Internal
    void InitializeState();
    void ScheduleInitialBroadcast();
    void SchedulePeriodicBroadcast();
    void PeriodicBroadcast();
    void ReceiveFromKdc(
        ns3::Ptr<ns3::Socket> socket);
    void ReceiveDataFromUav(
        ns3::Ptr<ns3::Socket> socket);
    ns3::Ipv4Address GetWifiAddress() const;
};

} // namespace apps
} // namespace uav

#endif // UAV_SKDC_APP_H
