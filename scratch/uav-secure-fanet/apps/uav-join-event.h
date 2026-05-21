/**
 * apps/uav-join-event.h
 * Module 41 - Join Security Event
 *
 * JOIN FLOW (per project spec):
 *   1. UAV sends JOIN_PACKET to nearest SKDC
 *   2. SKDC authenticates UAV (HMAC verify)
 *   3. SKDC generates UAV slave decryption key
 *   4. SKDC assigns multicast membership
 *   5. SKDC sends MT_K to new UAV
 *   6. SKDC distributes current TEK
 *   7. Existing UAVs: TEK unchanged, MT_K updated
 *
 * JOIN_PACKET contains:
 *   - UAV identity
 *   - nonce
 *   - timestamp
 *   - requested SKDC
 *   - HMAC signature
 *
 * Algorithm 3 (JoKeyUpdate) is invoked here.
 */

#ifndef UAV_JOIN_EVENT_H
#define UAV_JOIN_EVENT_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "apps/uav-multicast-manager.h"
#include "apps/uav-mtk-distribution.h"
#include "apps/uav-tek-manager.h"
#include "headers/uav-join-packet.h"
#include "headers/uav-auth-packet.h"
#include "routing/uav-topology.h"
#include "crypto/uav-replay.h"
#include "utils/uav-types.h"
#include "utils/uav-time-utils.h"

#include <functional>
#include <vector>
#include <unordered_map>

namespace uav {
namespace apps {

// ===========================================================================
// JoinRecord - result of a join event
// ===========================================================================
struct JoinRecord {
    utils::u32  uav_id       = 0;
    utils::u32  uav_index    = 0;
    utils::u32  cluster_id   = 0;
    double      time_s       = 0.0;
    bool        authenticated= false;
    bool        joined        = false;
    bool        tek_received  = false;
    double      latency_ms    = 0.0;
};

// ===========================================================================
// JoinEventManager - Module 41
// ===========================================================================
class JoinEventManager {
public:
    using JoinCallback =
        std::function<void(const JoinRecord&)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    JoinEventManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params,
        MulticastManager*               mc_mgr,
        MtkDistributionManager*         dist_mgr,
        TekManager*                     tek_mgr);

    // -----------------------------------------------------------------------
    // Join processing
    // -----------------------------------------------------------------------

    /// Process a UAV join request
    /// Returns true if join successful
    bool ProcessJoin(
        utils::u32          uav_id,
        utils::u32          uav_index,
        utils::u32          cluster_id,
        SkdcApplication*    skdc,
        UavApplication*     uav_app);

    /// Send JOIN_PACKET from UAV to SKDC
    packet::JoinPacket BuildJoinPacket(
        utils::u32 uav_id,
        utils::u32 uav_index,
        utils::u32 cluster_id,
        const crypto::HmacKey& hmac_key);

    /// Authenticate JOIN_PACKET at SKDC
    bool AuthenticateJoin(
        const packet::JoinPacket& pkt,
        const crypto::HmacKey& hmac_key);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalJoins()    const {
        return m_total_joins;
    }
    utils::u64 GetFailedJoins()   const {
        return m_failed_joins;
    }
    double GetAvgJoinLatency()    const;

    const std::vector<JoinRecord>& GetHistory() const {
        return m_history;
    }

    void SetJoinCallback(JoinCallback cb) {
        m_join_cb = cb;
    }

    void PrintJoinStats() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;
    MulticastManager*               m_mc_mgr;
    MtkDistributionManager*         m_dist_mgr;
    TekManager*                     m_tek_mgr;

    std::vector<JoinRecord>  m_history;
    JoinCallback             m_join_cb;
    utils::u64               m_total_joins  = 0;
    utils::u64               m_failed_joins = 0;

    crypto::ReplayCache      m_replay_cache;
};

} // namespace apps
} // namespace uav

#endif // UAV_JOIN_EVENT_H
