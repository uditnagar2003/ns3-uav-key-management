/**
 * visualization/uav-netanim.cc
 * Module 48 — NetAnim Integration
 */

#include "visualization/uav-netanim.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <sstream>
#include <iostream>

NS_LOG_COMPONENT_DEFINE("UavNetAnim");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
NetAnimManager::NetAnimManager(
    const routing::TopologyResult* topo,
    const std::string& output_dir)
    : m_topo(topo)
    , m_output_dir(output_dir)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimManager: constructed output=" << output_dir);
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
void NetAnimManager::Initialize()
{
    if (!m_enabled) {
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "NetAnimManager: disabled, skipping");
        return;
    }

    // Binary runs from ns-3 root — use absolute path
    std::string path = m_output_dir;
    if (path.empty() || path[0] != '/') {
        // Make absolute relative to project scratch dir
        path = std::string(
            "/home/udit/ns-allinone-3.43/ns-3.43"
            "/scratch/uav-secure-fanet/") + m_output_dir;
    }
    path += "/uav-fanet-anim.xml";

    // Create AnimationInterface — this registers with the simulator
    m_anim = std::make_unique<AnimationInterface>(path);

    // 100 ms poll interval per project spec
    m_anim->SetMobilityPollInterval(MilliSeconds(100));

    // Enable packet metadata for packet visualization
    m_anim->EnablePacketMetadata(true);

    // Apply initial visual state
    ApplyInitialColors();
    ApplyInitialDescriptions();
    ApplyInitialSizes();

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimManager: initialized output=" << path
        << " nodes=" << m_topo->all_nodes.GetN());

    std::cout << "[NetAnim] Output: " << path << "\n";
    std::cout << "[NetAnim] Nodes: "
              << m_topo->all_nodes.GetN() << "\n";
}

// ---------------------------------------------------------------------------
// ApplyInitialColors
// ---------------------------------------------------------------------------
void NetAnimManager::ApplyInitialColors()
{
    // KDC — red
    m_anim->UpdateNodeColor(
        m_topo->kdc_node.Get(0),
        COLOR_KDC.r, COLOR_KDC.g, COLOR_KDC.b);

    // SKDCs — orange
    for (uint32_t i = 0; i < m_topo->skdc_nodes.GetN(); ++i) {
        m_anim->UpdateNodeColor(
            m_topo->skdc_nodes.Get(i),
            COLOR_SKDC.r, COLOR_SKDC.g, COLOR_SKDC.b);
    }

    // UAVs — green
    for (uint32_t i = 0; i < m_topo->uav_nodes.GetN(); ++i) {
        m_anim->UpdateNodeColor(
            m_topo->uav_nodes.Get(i),
            COLOR_UAV.r, COLOR_UAV.g, COLOR_UAV.b);
    }

    // Jammer — purple
    if (m_topo->jammer_node.GetN() > 0) {
        m_anim->UpdateNodeColor(
            m_topo->jammer_node.Get(0),
            COLOR_JAMMER.r, COLOR_JAMMER.g, COLOR_JAMMER.b);
    }

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnimManager: initial colors applied");
}

// ---------------------------------------------------------------------------
// ApplyInitialDescriptions
// ---------------------------------------------------------------------------
void NetAnimManager::ApplyInitialDescriptions()
{
    // KDC
    m_anim->UpdateNodeDescription(
        m_topo->kdc_node.Get(0), "KDC");

    // SKDCs
    for (uint32_t i = 0; i < m_topo->skdc_nodes.GetN(); ++i) {
        std::ostringstream oss;
        oss << "SKDC" << i;
        m_anim->UpdateNodeDescription(
            m_topo->skdc_nodes.Get(i), oss.str());
    }

    // UAVs
    for (uint32_t i = 0; i < m_topo->uav_nodes.GetN(); ++i) {
        std::ostringstream oss;
        oss << "UAV" << i << "_C" << (i / 6);
        m_anim->UpdateNodeDescription(
            m_topo->uav_nodes.Get(i), oss.str());
    }

    // Jammer
    if (m_topo->jammer_node.GetN() > 0) {
        m_anim->UpdateNodeDescription(
            m_topo->jammer_node.Get(0), "JAMMER");
    }
}

// ---------------------------------------------------------------------------
// ApplyInitialSizes
// ---------------------------------------------------------------------------
void NetAnimManager::ApplyInitialSizes()
{
    // KDC — largest
    m_anim->UpdateNodeSize(
        m_topo->kdc_node.Get(0), 3.0, 3.0);

    // SKDCs — medium
    for (uint32_t i = 0; i < m_topo->skdc_nodes.GetN(); ++i) {
        m_anim->UpdateNodeSize(
            m_topo->skdc_nodes.Get(i), 2.0, 2.0);
    }

    // UAVs — normal
    for (uint32_t i = 0; i < m_topo->uav_nodes.GetN(); ++i) {
        m_anim->UpdateNodeSize(
            m_topo->uav_nodes.Get(i), 1.0, 1.0);
    }

    // Jammer — medium
    if (m_topo->jammer_node.GetN() > 0) {
        m_anim->UpdateNodeSize(
            m_topo->jammer_node.Get(0), 2.0, 2.0);
    }
}

// ---------------------------------------------------------------------------
// Runtime updates
// ---------------------------------------------------------------------------
void NetAnimManager::MarkCompromised(utils::u32 uav_id)
{
    if (!m_anim || uav_id >= m_topo->uav_nodes.GetN()) return;
    m_anim->UpdateNodeColor(
        m_topo->uav_nodes.Get(uav_id),
        COLOR_COMPROMISED.r,
        COLOR_COMPROMISED.g,
        COLOR_COMPROMISED.b);

    std::ostringstream oss;
    oss << "UAV" << uav_id << "_COMPROMISED";
    m_anim->UpdateNodeDescription(
        m_topo->uav_nodes.Get(uav_id), oss.str());

    UAV_LOG_WARN(uav::log::channels::SYSTEM,
        "NetAnim: UAV" << uav_id << " marked COMPROMISED");
}

void NetAnimManager::MarkNormal(utils::u32 uav_id)
{
    if (!m_anim || uav_id >= m_topo->uav_nodes.GetN()) return;
    m_anim->UpdateNodeColor(
        m_topo->uav_nodes.Get(uav_id),
        COLOR_UAV.r, COLOR_UAV.g, COLOR_UAV.b);

    std::ostringstream oss;
    oss << "UAV" << uav_id << "_C" << (uav_id / 6);
    m_anim->UpdateNodeDescription(
        m_topo->uav_nodes.Get(uav_id), oss.str());
}

void NetAnimManager::MarkHandover(utils::u32 uav_id)
{
    if (!m_anim || uav_id >= m_topo->uav_nodes.GetN()) return;
    // Yellow for handover
    m_anim->UpdateNodeColor(
        m_topo->uav_nodes.Get(uav_id), 255, 255, 0);

    std::ostringstream oss;
    oss << "UAV" << uav_id << "_HANDOVER";
    m_anim->UpdateNodeDescription(
        m_topo->uav_nodes.Get(uav_id), oss.str());

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "NetAnim: UAV" << uav_id << " marked HANDOVER");
}

void NetAnimManager::UpdateUavDescription(
    utils::u32 uav_id,
    const std::string& descr)
{
    if (!m_anim || uav_id >= m_topo->uav_nodes.GetN()) return;
    m_anim->UpdateNodeDescription(
        m_topo->uav_nodes.Get(uav_id), descr);
}

void NetAnimManager::UpdateSkdcDescription(
    utils::u32 skdc_id,
    const std::string& descr)
{
    if (!m_anim || skdc_id >= m_topo->skdc_nodes.GetN()) return;
    m_anim->UpdateNodeDescription(
        m_topo->skdc_nodes.Get(skdc_id), descr);
}

} // namespace visualization
} // namespace uav
