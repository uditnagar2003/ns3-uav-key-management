/**
 * visualization/uav-event-annotations.cc
 * Module 52 — Event Annotations
 */

#include "visualization/uav-event-annotations.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>

NS_LOG_COMPONENT_DEFINE("UavEventAnnotations");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
EventAnnotationManager::EventAnnotationManager(
    const routing::TopologyResult* topo,
    NetAnimManager*                netanim)
    : m_topo(topo)
    , m_netanim(netanim)
{
    m_uav_compromise_count.fill(0);
    m_uav_handover_count.fill(0);
    m_uav_join_count.fill(0);
    m_skdc_rekey_count.fill(0);
    m_skdc_tek_count.fill(0);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "EventAnnotationManager: constructed");
}

// ---------------------------------------------------------------------------
// Initialize — register counters with AnimationInterface
// ---------------------------------------------------------------------------
void EventAnnotationManager::Initialize()
{
    if (!m_netanim || !m_netanim->IsEnabled()) return;
    auto* anim = m_netanim->GetAnim();
    if (!anim) return;

    // Register one counter per event type
    // CounterType::UINT32_COUNTER — integer counts
    m_counter_compromise =
        anim->AddNodeCounter("Compromised",
            AnimationInterface::UINT32_COUNTER);

    m_counter_rekey =
        anim->AddNodeCounter("Rekeys",
            AnimationInterface::UINT32_COUNTER);

    m_counter_join =
        anim->AddNodeCounter("Joins",
            AnimationInterface::UINT32_COUNTER);

    m_counter_leave =
        anim->AddNodeCounter("Leaves",
            AnimationInterface::UINT32_COUNTER);

    m_counter_handover =
        anim->AddNodeCounter("Handovers",
            AnimationInterface::UINT32_COUNTER);

    m_counter_jammer =
        anim->AddNodeCounter("JammerHits",
            AnimationInterface::UINT32_COUNTER);

    m_counter_hmac_fail =
        anim->AddNodeCounter("HmacFail",
            AnimationInterface::UINT32_COUNTER);

    m_counter_tek_rotation =
        anim->AddNodeCounter("TekRotations",
            AnimationInterface::UINT32_COUNTER);

    m_initialized = true;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "EventAnnotationManager: initialized"
        " 8 counters registered");
}

// ---------------------------------------------------------------------------
// UpdateCounter — safe wrapper
// ---------------------------------------------------------------------------
void EventAnnotationManager::UpdateCounter(
    uint32_t counter_id,
    uint32_t node_id,
    double   value)
{
    if (!m_initialized) return;
    auto* anim = m_netanim->GetAnim();
    if (!anim) return;
    anim->UpdateNodeCounter(counter_id, node_id, value);
    ++m_total_annotations;
}

// ---------------------------------------------------------------------------
// Security event handlers
// ---------------------------------------------------------------------------
void EventAnnotationManager::OnCompromise(
    utils::u32 uav_id)
{
    if (uav_id >= 18) return;
    ++m_uav_compromise_count[uav_id];

    uint32_t ns3_id =
        m_topo->uav_nodes.Get(uav_id)->GetId();
    UpdateCounter(m_counter_compromise, ns3_id,
        m_uav_compromise_count[uav_id]);

    UAV_LOG_WARN(uav::log::channels::SYSTEM,
        "EventAnnotation: UAV" << uav_id
        << " COMPROMISE count="
        << m_uav_compromise_count[uav_id]);
}

void EventAnnotationManager::OnRekey(
    utils::u32 skdc_id)
{
    if (skdc_id >= 3) return;
    ++m_skdc_rekey_count[skdc_id];

    uint32_t ns3_id =
        m_topo->skdc_nodes.Get(skdc_id)->GetId();
    UpdateCounter(m_counter_rekey, ns3_id,
        m_skdc_rekey_count[skdc_id]);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "EventAnnotation: SKDC" << skdc_id
        << " REKEY count="
        << m_skdc_rekey_count[skdc_id]);
}

void EventAnnotationManager::OnJoin(
    utils::u32 uav_id)
{
    if (uav_id >= 18) return;
    ++m_uav_join_count[uav_id];

    uint32_t ns3_id =
        m_topo->uav_nodes.Get(uav_id)->GetId();
    UpdateCounter(m_counter_join, ns3_id,
        m_uav_join_count[uav_id]);
}

void EventAnnotationManager::OnLeave(
    utils::u32 uav_id)
{
    if (uav_id >= 18) return;
    uint32_t ns3_id =
        m_topo->uav_nodes.Get(uav_id)->GetId();
    UpdateCounter(m_counter_leave, ns3_id, 1.0);
}

void EventAnnotationManager::OnHandover(
    utils::u32 uav_id)
{
    if (uav_id >= 18) return;
    ++m_uav_handover_count[uav_id];

    uint32_t ns3_id =
        m_topo->uav_nodes.Get(uav_id)->GetId();
    UpdateCounter(m_counter_handover, ns3_id,
        m_uav_handover_count[uav_id]);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "EventAnnotation: UAV" << uav_id
        << " HANDOVER count="
        << m_uav_handover_count[uav_id]);
}

void EventAnnotationManager::OnJammerDetect(
    utils::u32 affected_uavs)
{
    // Annotate on jammer node
    if (m_topo->jammer_node.GetN() == 0) return;
    uint32_t ns3_id =
        m_topo->jammer_node.Get(0)->GetId();
    UpdateCounter(m_counter_jammer,
        ns3_id,
        static_cast<double>(affected_uavs));

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "EventAnnotation: JAMMER affected="
        << affected_uavs);
}

void EventAnnotationManager::OnHmacFailure(
    utils::u32 uav_id)
{
    if (uav_id >= 18) return;
    uint32_t ns3_id =
        m_topo->uav_nodes.Get(uav_id)->GetId();
    UpdateCounter(m_counter_hmac_fail, ns3_id, 1.0);
}

void EventAnnotationManager::OnTekRotation(
    utils::u32 skdc_id)
{
    if (skdc_id >= 3) return;
    ++m_skdc_tek_count[skdc_id];

    uint32_t ns3_id =
        m_topo->skdc_nodes.Get(skdc_id)->GetId();
    UpdateCounter(m_counter_tek_rotation, ns3_id,
        m_skdc_tek_count[skdc_id]);
}

// ---------------------------------------------------------------------------
// OnSecurityEvent — generic dispatcher
// ---------------------------------------------------------------------------
void EventAnnotationManager::OnSecurityEvent(
    utils::SecurityEventType event_type,
    utils::u32               node_id,
    bool                     is_uav)
{
    switch (event_type) {
    case utils::SecurityEventType::JOIN:
        if (is_uav) OnJoin(node_id);
        break;
    case utils::SecurityEventType::LEAVE:
        if (is_uav) OnLeave(node_id);
        break;
    case utils::SecurityEventType::REKEY:
        if (!is_uav) OnRekey(node_id);
        break;
    case utils::SecurityEventType::HANDOVER_START:
    case utils::SecurityEventType::HANDOVER_COMPLETE:
        if (is_uav) OnHandover(node_id);
        break;
    case utils::SecurityEventType::COMPROMISE:
    case utils::SecurityEventType::HMAC_FAILURE:
    case utils::SecurityEventType::AUTH_FAILURE:
        if (is_uav) OnCompromise(node_id);
        break;
    case utils::SecurityEventType::TEK_ROTATION:
        if (!is_uav) OnTekRotation(node_id);
        break;
    case utils::SecurityEventType::JAMMER_DETECTED:
        OnJammerDetect(node_id);
        break;
    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// PrintStats
// ---------------------------------------------------------------------------
void EventAnnotationManager::PrintStats() const
{
    std::cout << "\n=== EventAnnotationManager Stats ===\n";
    std::cout << "  Total annotations: "
              << m_total_annotations << "\n";
    std::cout << "  Per-UAV compromises:\n";
    for (uint32_t i = 0; i < 18; ++i) {
        if (m_uav_compromise_count[i] > 0)
            std::cout << "    UAV" << i << ": "
                << m_uav_compromise_count[i] << "\n";
    }
    std::cout << "  Per-SKDC rekeys:\n";
    for (uint32_t i = 0; i < 3; ++i) {
        std::cout << "    SKDC" << i << ": "
            << m_skdc_rekey_count[i] << "\n";
    }
    std::cout << "  Per-UAV handovers:\n";
    for (uint32_t i = 0; i < 18; ++i) {
        if (m_uav_handover_count[i] > 0)
            std::cout << "    UAV" << i << ": "
                << m_uav_handover_count[i] << "\n";
    }
}

} // namespace visualization
} // namespace uav
