/**
 * visualization/uav-node-color.h
 * Module 50 — Node Coloring Manager
 *
 * Extends NetAnimManager (Module 48) with:
 *   - Per-node color state tracking
 *   - Automatic hooks to security event callbacks
 *   - Cluster membership color coding
 *   - Color change history for metrics
 *
 * Color scheme (per project spec):
 *   KDC             = red     (255,   0,   0)
 *   SKDC            = orange  (255, 165,   0)
 *   UAV normal      = green   (  0, 255,   0)
 *   UAV compromised = black   (  0,   0,   0)
 *   UAV handover    = yellow  (255, 255,   0)
 *   UAV jammed      = red     (255,   0,   0)
 *   Jammer          = purple  (128,   0, 128)
 */

#ifndef UAV_NODE_COLOR_H
#define UAV_NODE_COLOR_H

#include "visualization/uav-netanim.h"
#include "apps/uav-compromise-detector.h"
#include "apps/uav-jammer-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <array>
#include <vector>
#include <string>

namespace uav {
namespace visualization {

// ===========================================================================
// UavColorState — current visual state of one UAV
// ===========================================================================
enum class UavColorState : uint8_t {
    NORMAL       = 0,  ///< green  — active, in cluster
    COMPROMISED  = 1,  ///< black  — revoked
    HANDOVER     = 2,  ///< yellow — switching cluster
    JAMMED       = 3,  ///< red    — SINR below threshold
    DISCONNECTED = 4   ///< grey   — offline
};

static inline const char* UavColorStateStr(UavColorState s)
{
    switch (s) {
    case UavColorState::NORMAL:       return "NORMAL";
    case UavColorState::COMPROMISED:  return "COMPROMISED";
    case UavColorState::HANDOVER:     return "HANDOVER";
    case UavColorState::JAMMED:       return "JAMMED";
    case UavColorState::DISCONNECTED: return "DISCONNECTED";
    default:                          return "UNKNOWN";
    }
}

// ===========================================================================
// ColorChangeRecord — one recorded color change
// ===========================================================================
struct ColorChangeRecord {
    double        time_s   = 0.0;
    utils::u32    uav_id   = 0;
    UavColorState old_state;
    UavColorState new_state;
};

// ===========================================================================
// NodeColorManager — Module 50
// ===========================================================================
class NodeColorManager {
public:
    /**
     * Construction
     * @param topo    Topology
     * @param netanim NetAnimManager to apply colors to
     */
    NodeColorManager(
        const routing::TopologyResult* topo,
        NetAnimManager*                netanim);

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * Initialize — sets initial colors for all nodes,
     * registers periodic jammer color update.
     */
    void Initialize();

    // -----------------------------------------------------------------------
    // Manual state changes
    // -----------------------------------------------------------------------
    void SetUavCompromised(utils::u32 uav_id);
    void SetUavHandover(utils::u32 uav_id);
    void SetUavNormal(utils::u32 uav_id);
    void SetUavJammed(utils::u32 uav_id);
    void SetUavDisconnected(utils::u32 uav_id);

    // -----------------------------------------------------------------------
    // Automatic hooks — connect to existing managers
    // -----------------------------------------------------------------------

    /**
     * HookCompromiseDetector — registers callback so
     * CompromiseDetector events automatically update colors.
     */
    void HookCompromiseDetector(
        apps::CompromiseDetector* detector);

    /**
     * HookJammerManager — registers periodic scan callback
     * to color jammed UAVs red during attack.
     * @param jammer_mgr   JammerManager
     * @param interval_s   How often to refresh (default 1s)
     */
    void HookJammerManager(
        apps::JammerManager* jammer_mgr,
        double interval_s = 1.0);

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------
    UavColorState GetUavState(utils::u32 uav_id) const;
    utils::u32    GetCompromisedCount() const;
    utils::u32    GetJammedCount()      const;

    const std::vector<ColorChangeRecord>& GetHistory()
        const { return m_history; }

    void PrintColorStats() const;

private:
    const routing::TopologyResult* m_topo;
    NetAnimManager*                m_netanim;

    // Per-UAV color state (18 UAVs)
    std::array<UavColorState, 18>  m_uav_states;

    std::vector<ColorChangeRecord> m_history;
    apps::JammerManager*           m_jammer_mgr  = nullptr;
    double                         m_jammer_interval = 1.0;

    void ApplyColor(utils::u32 uav_id,
                    UavColorState new_state);

    void JammerColorUpdateCallback();
};

} // namespace visualization
} // namespace uav

#endif // UAV_NODE_COLOR_H
