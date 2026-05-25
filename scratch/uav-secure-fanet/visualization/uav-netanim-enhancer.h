/**
 * visualization/uav-netanim-enhancer.h
 * NetAnim Enhancement — research-grade visualization
 *
 * Extends existing NetAnimManager with:
 *   - Dynamic UAV labels (speed, cluster, SINR)
 *   - Link color coding by packet type
 *   - Rekey flash effect
 *   - Handover color transition
 *   - Jammer interference visualization
 *   - Mobility position callbacks
 *   - Timeline event annotations
 *   - Cluster color coding (C0=green, C1=orange, C2=cyan)
 */

#ifndef UAV_NETANIM_ENHANCER_H
#define UAV_NETANIM_ENHANCER_H

#include "visualization/uav-netanim.h"
#include "visualization/uav-node-color.h"
#include "visualization/uav-packet-viz.h"
#include "visualization/uav-event-annotations.h"
#include "apps/uav-rekey-manager.h"
#include "apps/uav-jammer-manager.h"
#include "apps/uav-multicast-manager.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"
#include "ns3/netanim-module.h"
#include "ns3/mobility-module.h"

#include <string>
#include <array>
#include <vector>
#include <sstream>
#include <iomanip>

namespace uav {
namespace visualization {

// ===========================================================================
// Cluster color scheme (per spec)
// ===========================================================================
struct ClusterNodeColor { uint8_t r, g, b; };

constexpr ClusterNodeColor CLUSTER_NODE_COLORS[3] = {
    {  0, 200,  80},   // C0 = green
    {255, 140,   0},   // C1 = orange
    {  0, 200, 200},   // C2 = cyan
};

// ===========================================================================
// NetAnimEnhancer
// ===========================================================================
class NetAnimEnhancer {
public:
    NetAnimEnhancer(
        const routing::TopologyResult* topo,
        NetAnimManager*                netanim,
        NodeColorManager*              color_mgr,
        PacketVizManager*              pkt_viz,
        EventAnnotationManager*        evt_ann);

    /**
     * Initialize — apply all enhancements after
     * NetAnimManager::Initialize() has been called.
     */
    void Initialize();

    /**
     * SchedulePeriodicLabelUpdate — updates UAV labels
     * every interval_s with speed + cluster + SINR.
     */
    void SchedulePeriodicLabelUpdate(double interval_s = 1.0);

    // -----------------------------------------------------------------------
    // Security event visualizations
    // -----------------------------------------------------------------------
    void OnRekeyEvent(utils::u32 cluster_id,
                      utils::u32 tek_version,
                      apps::RekeyReason reason);

    void OnHandoverEvent(utils::u32 uav_id,
                         utils::u32 old_cluster,
                         utils::u32 new_cluster);

    void OnJoinEvent(utils::u32 uav_id,
                     utils::u32 cluster_id);

    void OnLeaveEvent(utils::u32 uav_id,
                      utils::u32 cluster_id);

    void OnCompromiseEvent(utils::u32 uav_id);

    void OnJammerEvent(utils::u32 affected_count,
                       double sinr_db);

    void OnMtkBroadcast(utils::u32 skdc_id,
                        utils::u32 cluster_id,
                        utils::u32 version);

    // -----------------------------------------------------------------------
    // Hook managers for automatic event visualization
    // -----------------------------------------------------------------------
    void HookRekeyManager(apps::RekeyManager* rekey_mgr);
    void HookJammerManager(apps::JammerManager* jammer_mgr,
                           double interval_s = 2.0);
    void HookMulticastManager(
        apps::MulticastManager* mc_mgr);

    // -----------------------------------------------------------------------
    // SKDC description updates
    // -----------------------------------------------------------------------
    void UpdateSkdcStatus(utils::u32 skdc_id,
                          utils::u32 member_count,
                          utils::u32 tek_version);

private:
    const routing::TopologyResult* m_topo;
    NetAnimManager*                m_netanim;
    NodeColorManager*              m_color_mgr;
    PacketVizManager*              m_pkt_viz;
    EventAnnotationManager*        m_evt_ann;

    apps::JammerManager*           m_jammer_mgr = nullptr;
    apps::MulticastManager*        m_mc_mgr     = nullptr;

    double m_label_interval   = 1.0;
    double m_jammer_interval  = 2.0;

    // Per-UAV state for labels
    std::array<utils::u32, 18> m_uav_cluster{};
    std::array<double,     18> m_uav_sinr{};
    std::array<utils::u32, 18> m_uav_rekey_count{};

    void ApplyClusterColors();
    void ApplyInitialDescriptions();
    void SetGroundNodePositions();

    void LabelUpdateCallback();
    void JammerScanCallback();

    std::string MakeUavLabel(utils::u32 uav_id) const;
    std::string MakeSkdcLabel(utils::u32 skdc_id,
                               utils::u32 members,
                               utils::u32 version) const;

    ns3::AnimationInterface* Anim() const {
        return m_netanim ? m_netanim->GetAnim() : nullptr;
    }
};

} // namespace visualization
} // namespace uav

#endif // UAV_NETANIM_ENHANCER_H
