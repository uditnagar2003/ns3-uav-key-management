/**
 * visualization/uav-event-annotations.h
 * Module 52 — Event Annotations
 *
 * Uses real NetAnim APIs:
 *   AddNodeCounter(name, UINT32_COUNTER) → counter ID
 *   UpdateNodeCounter(counterID, nodeId, value) → update
 *
 * Annotates in NetAnim:
 *   - Per-node security event counters (compromise, rekey, join, leave)
 *   - Per-SKDC rekey counter
 *   - Per-UAV handover counter
 *   - Jammer detection counter on jammer node
 *
 * Uses SecurityEventType from utils/uav-types.h
 */

#ifndef UAV_EVENT_ANNOTATIONS_H
#define UAV_EVENT_ANNOTATIONS_H

#include "visualization/uav-netanim.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"
#include "ns3/netanim-module.h"

#include <array>
#include <vector>
#include <string>
#include <unordered_map>

namespace uav {
namespace visualization {

// ===========================================================================
// EventAnnotationManager — Module 52
// ===========================================================================
class EventAnnotationManager {
public:
    EventAnnotationManager(
        const routing::TopologyResult* topo,
        NetAnimManager*                netanim);

    /**
     * Initialize — registers all node counters with AnimationInterface.
     * Must be called after NetAnimManager::Initialize().
     */
    void Initialize();

    // -----------------------------------------------------------------------
    // Security event annotations
    // Call these when security events occur — updates NetAnim counters.
    // -----------------------------------------------------------------------

    void OnCompromise   (utils::u32 uav_id);
    void OnRekey        (utils::u32 skdc_id);
    void OnJoin         (utils::u32 uav_id);
    void OnLeave        (utils::u32 uav_id);
    void OnHandover     (utils::u32 uav_id);
    void OnJammerDetect (utils::u32 affected_uavs);
    void OnHmacFailure  (utils::u32 uav_id);
    void OnTekRotation  (utils::u32 skdc_id);

    // -----------------------------------------------------------------------
    // Generic event annotation
    // -----------------------------------------------------------------------
    void OnSecurityEvent(
        utils::SecurityEventType event_type,
        utils::u32               node_id,
        bool                     is_uav = true);

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalAnnotations() const {
        return m_total_annotations;
    }
    void PrintStats() const;

private:
    const routing::TopologyResult* m_topo;
    NetAnimManager*                m_netanim;
    bool                           m_initialized = false;

    // NetAnim counter IDs (registered once in Initialize)
    uint32_t m_counter_compromise   = 0;
    uint32_t m_counter_rekey        = 0;
    uint32_t m_counter_join         = 0;
    uint32_t m_counter_leave        = 0;
    uint32_t m_counter_handover     = 0;
    uint32_t m_counter_jammer       = 0;
    uint32_t m_counter_hmac_fail    = 0;
    uint32_t m_counter_tek_rotation = 0;

    // Per-node running counts
    std::array<uint32_t, 18> m_uav_compromise_count{};
    std::array<uint32_t, 18> m_uav_handover_count{};
    std::array<uint32_t, 18> m_uav_join_count{};
    std::array<uint32_t, 3>  m_skdc_rekey_count{};
    std::array<uint32_t, 3>  m_skdc_tek_count{};

    utils::u64 m_total_annotations = 0;

    // Helper — safe UpdateNodeCounter
    void UpdateCounter(uint32_t counter_id,
                       uint32_t node_id,
                       double   value);
};

} // namespace visualization
} // namespace uav

#endif // UAV_EVENT_ANNOTATIONS_H
