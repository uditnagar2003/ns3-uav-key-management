/**
 * visualization/uav-node-color.cc
 * Module 50 — Node Coloring Manager
 */

#include "visualization/uav-node-color.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavNodeColor");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
NodeColorManager::NodeColorManager(
    const routing::TopologyResult* topo,
    NetAnimManager*                netanim)
    : m_topo(topo)
    , m_netanim(netanim)
{
    m_uav_states.fill(UavColorState::NORMAL);
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NodeColorManager: constructed 18 UAVs");
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
void NodeColorManager::Initialize()
{
    if (!m_netanim || !m_netanim->IsEnabled()) return;

    // Initial colors already applied by NetAnimManager::Initialize()
    // Reset all UAV states to NORMAL
    m_uav_states.fill(UavColorState::NORMAL);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NodeColorManager: initialized"
        " all UAVs set to NORMAL(green)");
}

// ---------------------------------------------------------------------------
// ApplyColor — core color update
// ---------------------------------------------------------------------------
void NodeColorManager::ApplyColor(
    utils::u32    uav_id,
    UavColorState new_state)
{
    if (uav_id >= 18) return;

    UavColorState old_state = m_uav_states[uav_id];
    if (old_state == new_state) return;

    // Record change
    ColorChangeRecord rec;
    rec.time_s   = Simulator::Now().GetSeconds();
    rec.uav_id   = uav_id;
    rec.old_state = old_state;
    rec.new_state = new_state;
    m_history.push_back(rec);

    m_uav_states[uav_id] = new_state;

    // Apply to NetAnim
    if (!m_netanim) return;

    switch (new_state) {
    case UavColorState::NORMAL:
        m_netanim->MarkNormal(uav_id);
        break;
    case UavColorState::COMPROMISED:
        m_netanim->MarkCompromised(uav_id);
        break;
    case UavColorState::HANDOVER:
        m_netanim->MarkHandover(uav_id);
        break;
    case UavColorState::JAMMED:
        // Red for jammed
        if (m_netanim->GetAnim()) {
            m_netanim->GetAnim()->UpdateNodeColor(
                m_topo->uav_nodes.Get(uav_id),
                255, 0, 0);
            std::ostringstream oss;
            oss << "UAV" << uav_id << "_JAMMED";
            m_netanim->GetAnim()->UpdateNodeDescription(
                m_topo->uav_nodes.Get(uav_id),
                oss.str());
        }
        break;
    case UavColorState::DISCONNECTED:
        // Grey for disconnected
        if (m_netanim->GetAnim()) {
            m_netanim->GetAnim()->UpdateNodeColor(
                m_topo->uav_nodes.Get(uav_id),
                128, 128, 128);
            std::ostringstream oss;
            oss << "UAV" << uav_id << "_DISC";
            m_netanim->GetAnim()->UpdateNodeDescription(
                m_topo->uav_nodes.Get(uav_id),
                oss.str());
        }
        break;
    }

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NodeColorManager: UAV" << uav_id
        << " " << UavColorStateStr(old_state)
        << " → " << UavColorStateStr(new_state));
}

// ---------------------------------------------------------------------------
// Manual state changes
// ---------------------------------------------------------------------------
void NodeColorManager::SetUavCompromised(utils::u32 uav_id)
{
    ApplyColor(uav_id, UavColorState::COMPROMISED);
}

void NodeColorManager::SetUavHandover(utils::u32 uav_id)
{
    ApplyColor(uav_id, UavColorState::HANDOVER);
}

void NodeColorManager::SetUavNormal(utils::u32 uav_id)
{
    ApplyColor(uav_id, UavColorState::NORMAL);
}

void NodeColorManager::SetUavJammed(utils::u32 uav_id)
{
    ApplyColor(uav_id, UavColorState::JAMMED);
}

void NodeColorManager::SetUavDisconnected(utils::u32 uav_id)
{
    ApplyColor(uav_id, UavColorState::DISCONNECTED);
}

// ---------------------------------------------------------------------------
// HookCompromiseDetector
// ---------------------------------------------------------------------------
void NodeColorManager::HookCompromiseDetector(
    apps::CompromiseDetector* detector)
{
    if (!detector) return;

    detector->SetCallback(
        [this](const apps::CompromiseEvent& ev) {
            SetUavCompromised(ev.uav_id);
            UAV_LOG_WARN(uav::log::channels::SYSTEM,
                "NodeColorManager: UAV"
                << ev.uav_id
                << " compromised → BLACK");
        });

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NodeColorManager: hooked CompromiseDetector");
}

// ---------------------------------------------------------------------------
// HookJammerManager
// ---------------------------------------------------------------------------
void NodeColorManager::HookJammerManager(
    apps::JammerManager* jammer_mgr,
    double interval_s)
{
    if (!jammer_mgr) return;
    m_jammer_mgr      = jammer_mgr;
    m_jammer_interval = interval_s;

    Simulator::Schedule(
        Seconds(interval_s),
        &NodeColorManager::JammerColorUpdateCallback,
        this);

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NodeColorManager: hooked JammerManager"
        " interval=" << interval_s << "s");
}

void NodeColorManager::JammerColorUpdateCallback()
{
    if (!m_jammer_mgr) return;

    for (uint32_t i = 0; i < 18; ++i) {
        bool jammed = m_jammer_mgr->IsJammed(i);

        // Only update if state needs to change
        // Don't override COMPROMISED with JAMMED
        if (jammed &&
            m_uav_states[i] == UavColorState::NORMAL)
        {
            ApplyColor(i, UavColorState::JAMMED);
        }
        else if (!jammed &&
                 m_uav_states[i] == UavColorState::JAMMED)
        {
            ApplyColor(i, UavColorState::NORMAL);
        }
    }

    Simulator::Schedule(
        Seconds(m_jammer_interval),
        &NodeColorManager::JammerColorUpdateCallback,
        this);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
UavColorState NodeColorManager::GetUavState(
    utils::u32 uav_id) const
{
    if (uav_id >= 18) return UavColorState::NORMAL;
    return m_uav_states[uav_id];
}

utils::u32 NodeColorManager::GetCompromisedCount() const
{
    utils::u32 count = 0;
    for (const auto& s : m_uav_states)
        if (s == UavColorState::COMPROMISED) ++count;
    return count;
}

utils::u32 NodeColorManager::GetJammedCount() const
{
    utils::u32 count = 0;
    for (const auto& s : m_uav_states)
        if (s == UavColorState::JAMMED) ++count;
    return count;
}

void NodeColorManager::PrintColorStats() const
{
    std::cout << "\n=== NodeColorManager Stats ===\n";
    std::cout << "  Compromised UAVs: "
              << GetCompromisedCount() << "\n";
    std::cout << "  Jammed UAVs:      "
              << GetJammedCount()      << "\n";
    std::cout << "  Color changes:    "
              << m_history.size()      << "\n";

    std::cout << "  Per-UAV state:\n";
    for (uint32_t i = 0; i < 18; ++i) {
        if (m_uav_states[i] != UavColorState::NORMAL) {
            std::cout << "    UAV" << i << ": "
                << UavColorStateStr(m_uav_states[i])
                << "\n";
        }
    }

    std::cout << "  History:\n";
    for (const auto& r : m_history) {
        std::cout << "    t=" << r.time_s
            << "s UAV" << r.uav_id
            << " " << UavColorStateStr(r.old_state)
            << "→" << UavColorStateStr(r.new_state)
            << "\n";
    }
}

} // namespace visualization
} // namespace uav
