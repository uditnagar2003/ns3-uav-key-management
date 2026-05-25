/**
 * visualization/uav-netanim-enhancer.cc
 * NetAnim Enhancement Implementation
 */

#include "visualization/uav-netanim-enhancer.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <cmath>

NS_LOG_COMPONENT_DEFINE("UavNetAnimEnhancer");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
NetAnimEnhancer::NetAnimEnhancer(
    const routing::TopologyResult* topo,
    NetAnimManager*                netanim,
    NodeColorManager*              color_mgr,
    PacketVizManager*              pkt_viz,
    EventAnnotationManager*        evt_ann)
    : m_topo(topo)
    , m_netanim(netanim)
    , m_color_mgr(color_mgr)
    , m_pkt_viz(pkt_viz)
    , m_evt_ann(evt_ann)
{
    m_uav_cluster.fill(0);
    m_uav_sinr.fill(0.0);
    m_uav_rekey_count.fill(0);

    // Initialize cluster assignment
    for (uint32_t i = 0; i < 18; ++i)
        m_uav_cluster[i] = i / 6;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: constructed");
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
void NetAnimEnhancer::Initialize()
{
    if (!Anim()) return;

    ApplyClusterColors();
    ApplyInitialDescriptions();
    SetGroundNodePositions();

    // Backbone link labels
    auto* a = Anim();
    for (uint32_t i = 0;
         i < m_topo->skdc_nodes.GetN(); ++i) {
        a->UpdateLinkDescription(
            m_topo->kdc_node.Get(0),
            m_topo->skdc_nodes.Get(i),
            "CSMA|KDC-SKDC" + std::to_string(i));
    }

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: initialized");
}

// ---------------------------------------------------------------------------
// ApplyClusterColors — C0=green, C1=orange, C2=cyan
// ---------------------------------------------------------------------------
void NetAnimEnhancer::ApplyClusterColors()
{
    auto* a = Anim();
    if (!a) return;

    for (uint32_t i = 0;
         i < m_topo->uav_nodes.GetN(); ++i) {
        uint32_t c = m_uav_cluster[i];
        if (c >= 3) continue;
        auto& col = CLUSTER_NODE_COLORS[c];
        a->UpdateNodeColor(
            m_topo->uav_nodes.Get(i),
            col.r, col.g, col.b);
    }
}

// ---------------------------------------------------------------------------
// ApplyInitialDescriptions
// ---------------------------------------------------------------------------
void NetAnimEnhancer::ApplyInitialDescriptions()
{
    auto* a = Anim();
    if (!a) return;

    // KDC
    a->UpdateNodeDescription(
        m_topo->kdc_node.Get(0),
        "KDC\nHierarchical Root");
    a->UpdateNodeSize(
        m_topo->kdc_node.Get(0), 4.0, 4.0);

    // SKDCs
    for (uint32_t i = 0;
         i < m_topo->skdc_nodes.GetN(); ++i) {
        a->UpdateNodeDescription(
            m_topo->skdc_nodes.Get(i),
            "SKDC-C" + std::to_string(i)
            + "\nMembers:6\nTEK_v:1");
        a->UpdateNodeSize(
            m_topo->skdc_nodes.Get(i), 3.0, 3.0);
    }

    // UAVs
    for (uint32_t i = 0;
         i < m_topo->uav_nodes.GetN(); ++i) {
        a->UpdateNodeDescription(
            m_topo->uav_nodes.Get(i),
            MakeUavLabel(i));
        a->UpdateNodeSize(
            m_topo->uav_nodes.Get(i), 1.5, 1.5);
    }

    // Jammer
    if (m_topo->jammer_node.GetN() > 0) {
        a->UpdateNodeColor(
            m_topo->jammer_node.Get(0),
            128, 0, 128);  // purple
        a->UpdateNodeDescription(
            m_topo->jammer_node.Get(0),
            "JAMMER\n30dBm");
        a->UpdateNodeSize(
            m_topo->jammer_node.Get(0), 2.5, 2.5);
    }
}

// ---------------------------------------------------------------------------
// SetGroundNodePositions
// ---------------------------------------------------------------------------
void NetAnimEnhancer::SetGroundNodePositions()
{
    // KDC at center
    AnimationInterface::SetConstantPosition(
        m_topo->kdc_node.Get(0), 750.0, 50.0, 0.0);

    // SKDCs at cluster center X positions
    double skdc_x[3] = {250.0, 750.0, 1250.0};
    for (uint32_t i = 0;
         i < m_topo->skdc_nodes.GetN(); ++i) {
        AnimationInterface::SetConstantPosition(
            m_topo->skdc_nodes.Get(i),
            skdc_x[i], 150.0, 0.0);
    }
}

// ---------------------------------------------------------------------------
// MakeUavLabel
// ---------------------------------------------------------------------------
std::string NetAnimEnhancer::MakeUavLabel(
    utils::u32 uav_id) const
{
    std::ostringstream oss;
    oss << "UAV-" << uav_id;
    if (uav_id < 18) {
        oss << "\nC" << m_uav_cluster[uav_id];
        if (m_uav_sinr[uav_id] != 0.0) {
            oss << "\nSINR:"
                << std::fixed << std::setprecision(1)
                << m_uav_sinr[uav_id] << "dB";
        }
        if (m_uav_rekey_count[uav_id] > 0) {
            oss << "\nRK:"
                << m_uav_rekey_count[uav_id];
        }
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// MakeSkdcLabel
// ---------------------------------------------------------------------------
std::string NetAnimEnhancer::MakeSkdcLabel(
    utils::u32 skdc_id,
    utils::u32 members,
    utils::u32 version) const
{
    std::ostringstream oss;
    oss << "SKDC-C" << skdc_id
        << "\nMembers:" << members
        << "\nTEK_v:" << version;
    return oss.str();
}

// ---------------------------------------------------------------------------
// SchedulePeriodicLabelUpdate
// ---------------------------------------------------------------------------
void NetAnimEnhancer::SchedulePeriodicLabelUpdate(
    double interval_s)
{
    m_label_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &NetAnimEnhancer::LabelUpdateCallback, this);
}

void NetAnimEnhancer::LabelUpdateCallback()
{
    auto* a = Anim();
    if (a) {
        // Update UAV labels with position + cluster
        for (uint32_t i = 0;
             i < m_topo->uav_nodes.GetN(); ++i) {
            a->UpdateNodeDescription(
                m_topo->uav_nodes.Get(i),
                MakeUavLabel(i));
        }
    }
    Simulator::Schedule(
        Seconds(m_label_interval),
        &NetAnimEnhancer::LabelUpdateCallback, this);
}

// ---------------------------------------------------------------------------
// HookRekeyManager
// ---------------------------------------------------------------------------
void NetAnimEnhancer::HookRekeyManager(
    apps::RekeyManager* rekey_mgr)
{
    if (!rekey_mgr) return;
    rekey_mgr->SetRekeyCallback(
        [this](const apps::RekeyEvent& ev) {
            OnRekeyEvent(
                ev.cluster_id,
                0,  // version not in event
                ev.reason);
        });
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: hooked RekeyManager");
}

// ---------------------------------------------------------------------------
// HookJammerManager
// ---------------------------------------------------------------------------
void NetAnimEnhancer::HookJammerManager(
    apps::JammerManager* jammer_mgr,
    double interval_s)
{
    m_jammer_mgr     = jammer_mgr;
    m_jammer_interval = interval_s;
    Simulator::Schedule(
        Seconds(interval_s),
        &NetAnimEnhancer::JammerScanCallback, this);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: hooked JammerManager");
}

void NetAnimEnhancer::JammerScanCallback()
{
    if (!m_jammer_mgr) return;
    auto* a = Anim();

    uint32_t jammed = 0;
    double   min_sinr = 999.0;

    for (uint32_t i = 0; i < 18; ++i) {
        double sinr = m_jammer_mgr->ComputeSinr(i);
        m_uav_sinr[i] = sinr;
        bool   is_jammed = m_jammer_mgr->IsJammed(i);

        if (is_jammed) {
            ++jammed;
            if (sinr < min_sinr) min_sinr = sinr;
            // Red for jammed UAVs
            if (a && i < m_topo->uav_nodes.GetN()) {
                a->UpdateNodeColor(
                    m_topo->uav_nodes.Get(i),
                    255, 0, 0);
                a->UpdateNodeDescription(
                    m_topo->uav_nodes.Get(i),
                    "UAV-" + std::to_string(i)
                    + "\nJAMMED\nSINR:"
                    + std::to_string((int)sinr)
                    + "dB");
            }
            if (m_color_mgr)
                m_color_mgr->SetUavJammed(i);
        } else {
            // Restore cluster color
            if (a && i < m_topo->uav_nodes.GetN()) {
                uint32_t c = m_uav_cluster[i];
                if (c < 3) {
                    auto& col = CLUSTER_NODE_COLORS[c];
                    a->UpdateNodeColor(
                        m_topo->uav_nodes.Get(i),
                        col.r, col.g, col.b);
                }
                a->UpdateNodeDescription(
                    m_topo->uav_nodes.Get(i),
                    MakeUavLabel(i));
            }
            if (m_color_mgr)
                m_color_mgr->SetUavNormal(i);
        }
    }

    if (jammed > 0 && a &&
        m_topo->jammer_node.GetN() > 0) {
        a->UpdateNodeDescription(
            m_topo->jammer_node.Get(0),
            "JAMMER\nAffects:" +
            std::to_string(jammed) +
            "\nMinSINR:" +
            std::to_string((int)min_sinr) + "dB");
    }

    Simulator::Schedule(
        Seconds(m_jammer_interval),
        &NetAnimEnhancer::JammerScanCallback, this);
}

// ---------------------------------------------------------------------------
// OnRekeyEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnRekeyEvent(
    utils::u32 cluster_id,
    utils::u32 tek_version,
    apps::RekeyReason reason)
{
    auto* a = Anim();
    if (!a) return;

    // Update SKDC label
    if (cluster_id < m_topo->skdc_nodes.GetN()) {
        std::string label = "SKDC-C"
            + std::to_string(cluster_id)
            + "\nREKEY!"
            + "\nReason:"
            + std::string(
                apps::RekeyReasonStr(reason));
        a->UpdateNodeDescription(
            m_topo->skdc_nodes.Get(cluster_id),
            label);
        // Orange flash on SKDC
        a->UpdateNodeColor(
            m_topo->skdc_nodes.Get(cluster_id),
            255, 0, 0);  // red flash
    }

    // Update link labels for cluster UAVs
    if (m_pkt_viz)
        m_pkt_viz->OnRekeyBroadcast(
            cluster_id, cluster_id);

    // Update counter
    uint32_t base = cluster_id * 6;
    for (uint32_t i = 0; i < 6; ++i) {
        uint32_t uid = base + i;
        if (uid < 18) {
            ++m_uav_rekey_count[uid];
            if (uid < m_topo->uav_nodes.GetN()) {
                a->UpdateNodeDescription(
                    m_topo->uav_nodes.Get(uid),
                    MakeUavLabel(uid));
            }
        }
    }

    if (m_evt_ann) m_evt_ann->OnRekey(cluster_id);

    // Schedule restore of SKDC color after 1s
    Simulator::Schedule(Seconds(1.0),
        [this, cluster_id]() {
            auto* a2 = Anim();
            if (!a2) return;
            if (cluster_id <
                m_topo->skdc_nodes.GetN()) {
                a2->UpdateNodeColor(
                    m_topo->skdc_nodes.Get(
                        cluster_id),
                    255, 140, 0);  // orange
            }
        });

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: REKEY C" << cluster_id);
}

// ---------------------------------------------------------------------------
// OnHandoverEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnHandoverEvent(
    utils::u32 uav_id,
    utils::u32 old_cluster,
    utils::u32 new_cluster)
{
    auto* a = Anim();

    // Update cluster tracking
    if (uav_id < 18)
        m_uav_cluster[uav_id] = new_cluster;

    // Yellow during handover
    if (m_color_mgr)
        m_color_mgr->SetUavHandover(uav_id);

    if (a && uav_id < m_topo->uav_nodes.GetN()) {
        a->UpdateNodeDescription(
            m_topo->uav_nodes.Get(uav_id),
            "UAV-" + std::to_string(uav_id)
            + "\nHANDOVER\nC"
            + std::to_string(old_cluster)
            + "→C"
            + std::to_string(new_cluster));
    }

    if (m_pkt_viz)
        m_pkt_viz->OnHandover(
            uav_id, old_cluster, new_cluster);
    if (m_evt_ann)
        m_evt_ann->OnHandover(uav_id);

    // Restore new cluster color after 2s
    Simulator::Schedule(Seconds(2.0),
        [this, uav_id, new_cluster]() {
            auto* a2 = Anim();
            if (m_color_mgr)
                m_color_mgr->SetUavNormal(uav_id);
            if (a2 &&
                uav_id < m_topo->uav_nodes.GetN()
                && new_cluster < 3) {
                auto& col =
                    CLUSTER_NODE_COLORS[new_cluster];
                a2->UpdateNodeColor(
                    m_topo->uav_nodes.Get(uav_id),
                    col.r, col.g, col.b);
                a2->UpdateNodeDescription(
                    m_topo->uav_nodes.Get(uav_id),
                    MakeUavLabel(uav_id));
            }
        });

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimEnhancer: HANDOVER UAV" << uav_id
        << " C" << old_cluster
        << "→C" << new_cluster);
}

// ---------------------------------------------------------------------------
// OnJoinEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnJoinEvent(
    utils::u32 uav_id,
    utils::u32 cluster_id)
{
    auto* a = Anim();
    if (a && uav_id < m_topo->uav_nodes.GetN()) {
        a->UpdateNodeDescription(
            m_topo->uav_nodes.Get(uav_id),
            "UAV-" + std::to_string(uav_id)
            + "\nJOIN_REQ\nC"
            + std::to_string(cluster_id));
    }
    if (m_pkt_viz)
        m_pkt_viz->OnJoinRequest(uav_id, cluster_id);
    if (m_evt_ann)
        m_evt_ann->OnJoin(uav_id);
}

// ---------------------------------------------------------------------------
// OnLeaveEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnLeaveEvent(
    utils::u32 uav_id,
    utils::u32 cluster_id)
{
    auto* a = Anim();
    if (a && uav_id < m_topo->uav_nodes.GetN()) {
        a->UpdateNodeDescription(
            m_topo->uav_nodes.Get(uav_id),
            "UAV-" + std::to_string(uav_id)
            + "\nLEFT_C"
            + std::to_string(cluster_id));
        // Grey for left UAV
        a->UpdateNodeColor(
            m_topo->uav_nodes.Get(uav_id),
            128, 128, 128);
    }
    if (m_evt_ann) m_evt_ann->OnLeave(uav_id);

    // Restore color after 3s
    Simulator::Schedule(Seconds(3.0),
        [this, uav_id]() {
            uint32_t c = m_uav_cluster[uav_id];
            auto* a2 = Anim();
            if (a2 &&
                uav_id < m_topo->uav_nodes.GetN()
                && c < 3) {
                auto& col = CLUSTER_NODE_COLORS[c];
                a2->UpdateNodeColor(
                    m_topo->uav_nodes.Get(uav_id),
                    col.r, col.g, col.b);
            }
        });
}

// ---------------------------------------------------------------------------
// OnCompromiseEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnCompromiseEvent(
    utils::u32 uav_id)
{
    if (m_color_mgr)
        m_color_mgr->SetUavCompromised(uav_id);
    auto* a = Anim();
    if (a && uav_id < m_topo->uav_nodes.GetN()) {
        a->UpdateNodeDescription(
            m_topo->uav_nodes.Get(uav_id),
            "UAV-" + std::to_string(uav_id)
            + "\nCOMPROMISED\nREVOKED");
    }
    if (m_evt_ann) m_evt_ann->OnCompromise(uav_id);
}

// ---------------------------------------------------------------------------
// OnJammerEvent
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnJammerEvent(
    utils::u32 affected_count,
    double sinr_db)
{
    auto* a = Anim();
    if (a && m_topo->jammer_node.GetN() > 0) {
        a->UpdateNodeDescription(
            m_topo->jammer_node.Get(0),
            "JAMMER\nAffects:"
            + std::to_string(affected_count)
            + "\nSINR:"
            + std::to_string((int)sinr_db) + "dB");
    }
    if (m_evt_ann)
        m_evt_ann->OnJammerDetect(affected_count);
}

// ---------------------------------------------------------------------------
// OnMtkBroadcast
// ---------------------------------------------------------------------------
void NetAnimEnhancer::OnMtkBroadcast(
    utils::u32 skdc_id,
    utils::u32 cluster_id,
    utils::u32 version)
{
    auto* a = Anim();
    if (a && skdc_id < m_topo->skdc_nodes.GetN()) {
        // Blue links for MTK distribution
        uint32_t base = cluster_id * 6;
        for (uint32_t i = 0; i < 6; ++i) {
            uint32_t uid = base + i;
            if (uid < m_topo->uav_nodes.GetN()) {
                a->UpdateLinkDescription(
                    m_topo->skdc_nodes.Get(skdc_id),
                    m_topo->uav_nodes.Get(uid),
                    "[MTK_v" + std::to_string(version)
                    + "]");
            }
        }
        a->UpdateNodeDescription(
            m_topo->skdc_nodes.Get(skdc_id),
            "SKDC-C" + std::to_string(skdc_id)
            + "\nMTK_BROADCAST\nv="
            + std::to_string(version));
    }
    if (m_pkt_viz)
        m_pkt_viz->OnMtkBroadcast(
            skdc_id, cluster_id, version);
}

// ---------------------------------------------------------------------------
// UpdateSkdcStatus
// ---------------------------------------------------------------------------
void NetAnimEnhancer::UpdateSkdcStatus(
    utils::u32 skdc_id,
    utils::u32 member_count,
    utils::u32 tek_version)
{
    auto* a = Anim();
    if (a && skdc_id < m_topo->skdc_nodes.GetN()) {
        a->UpdateNodeDescription(
            m_topo->skdc_nodes.Get(skdc_id),
            MakeSkdcLabel(skdc_id,
                          member_count,
                          tek_version));
        // Restore orange color
        a->UpdateNodeColor(
            m_topo->skdc_nodes.Get(skdc_id),
            255, 140, 0);
    }
}

} // namespace visualization
} // namespace uav
