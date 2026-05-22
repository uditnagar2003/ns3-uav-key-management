/**
 * visualization/uav-packet-viz.cc
 * Module 51 — Packet Visualization
 */

#include "visualization/uav-packet-viz.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("UavPacketViz");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
PacketVizManager::PacketVizManager(
    const routing::TopologyResult* topo,
    NetAnimManager*                netanim)
    : m_topo(topo)
    , m_netanim(netanim)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketVizManager: constructed");
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
void PacketVizManager::Initialize()
{
    if (!m_netanim || !m_netanim->IsEnabled()) return;
    if (!m_netanim->GetAnim()) return;

    // Set initial backbone link descriptions
    auto kdc = m_topo->kdc_node.Get(0);
    for (uint32_t i = 0; i < m_topo->skdc_nodes.GetN(); ++i) {
        auto skdc = m_topo->skdc_nodes.Get(i);
        std::ostringstream oss;
        oss << "KDC-SKDC" << i;
        UpdateLink(kdc, skdc, oss.str());
    }

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketVizManager: initialized"
        " backbone links labeled");
}

// ---------------------------------------------------------------------------
// UpdateLink
// ---------------------------------------------------------------------------
void PacketVizManager::UpdateLink(
    Ptr<Node>          from,
    Ptr<Node>          to,
    const std::string& label)
{
    if (!m_netanim || !m_netanim->GetAnim()) return;
    m_netanim->GetAnim()->UpdateLinkDescription(
        from, to, label);
}

// ---------------------------------------------------------------------------
// Helper accessors
// ---------------------------------------------------------------------------
Ptr<Node> PacketVizManager::GetSkdcNode(
    utils::u32 skdc_id) const
{
    if (skdc_id >= m_topo->skdc_nodes.GetN())
        return nullptr;
    return m_topo->skdc_nodes.Get(skdc_id);
}

Ptr<Node> PacketVizManager::GetUavNode(
    utils::u32 uav_id) const
{
    if (uav_id >= m_topo->uav_nodes.GetN())
        return nullptr;
    return m_topo->uav_nodes.Get(uav_id);
}

// ---------------------------------------------------------------------------
// RecordEvent
// ---------------------------------------------------------------------------
void PacketVizManager::RecordEvent(
    uav::packet::PacketType pkt_type,
    utils::u32          src_id,
    utils::u32          dst_id,
    const std::string&  label)
{
    PacketVizRecord rec;
    rec.time_s   = Simulator::Now().GetSeconds();
    rec.pkt_type = pkt_type;
    rec.src_id   = src_id;
    rec.dst_id   = dst_id;
    rec.label    = label;
    m_history.push_back(rec);
    ++m_total_events;
}

// ---------------------------------------------------------------------------
// OnMtkBroadcast
// ---------------------------------------------------------------------------
void PacketVizManager::OnMtkBroadcast(
    utils::u32 skdc_id,
    utils::u32 cluster_id,
    utils::u32 version)
{
    auto skdc = GetSkdcNode(skdc_id);
    if (!skdc) return;

    // Label SKDC→each cluster UAV link
    uint32_t base = cluster_id * 6;
    std::ostringstream label;
    label << "MTK_v" << version;

    for (uint32_t i = 0; i < 6; ++i) {
        auto uav = GetUavNode(base + i);
        if (uav) UpdateLink(skdc, uav, label.str());
    }

    RecordEvent(uav::packet::PacketType::MTK_PACKET,
                skdc_id, cluster_id, label.str());
    ++m_mtk_events;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketViz: MTK broadcast C" << cluster_id
        << " v" << version);
}

// ---------------------------------------------------------------------------
// OnRekeyBroadcast
// ---------------------------------------------------------------------------
void PacketVizManager::OnRekeyBroadcast(
    utils::u32 skdc_id,
    utils::u32 cluster_id)
{
    auto skdc = GetSkdcNode(skdc_id);
    if (!skdc) return;

    uint32_t base = cluster_id * 6;
    std::string label = "REKEY";

    for (uint32_t i = 0; i < 6; ++i) {
        auto uav = GetUavNode(base + i);
        if (uav) UpdateLink(skdc, uav, label);
    }

    RecordEvent(uav::packet::PacketType::REKEY_PACKET,
                skdc_id, cluster_id, label);
    ++m_rekey_events;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketViz: REKEY broadcast C" << cluster_id);
}

// ---------------------------------------------------------------------------
// OnJoinRequest
// ---------------------------------------------------------------------------
void PacketVizManager::OnJoinRequest(
    utils::u32 uav_id,
    utils::u32 skdc_id)
{
    auto uav  = GetUavNode(uav_id);
    auto skdc = GetSkdcNode(skdc_id);
    if (!uav || !skdc) return;

    std::ostringstream label;
    label << "JOIN_UAV" << uav_id;
    UpdateLink(uav, skdc, label.str());

    RecordEvent(uav::packet::PacketType::JOIN_PACKET,
                uav_id, skdc_id, label.str());

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketViz: JOIN UAV" << uav_id
        << "→SKDC" << skdc_id);
}

// ---------------------------------------------------------------------------
// OnDataPacket
// ---------------------------------------------------------------------------
void PacketVizManager::OnDataPacket(
    utils::u32 uav_id,
    utils::u32 skdc_id)
{
    auto uav  = GetUavNode(uav_id);
    auto skdc = GetSkdcNode(skdc_id);
    if (!uav || !skdc) return;

    std::ostringstream label;
    label << "DATA_UAV" << uav_id;
    UpdateLink(uav, skdc, label.str());

    RecordEvent(uav::packet::PacketType::DATA_PACKET,
                uav_id, skdc_id, label.str());
    ++m_data_events;
}

// ---------------------------------------------------------------------------
// OnHandover
// ---------------------------------------------------------------------------
void PacketVizManager::OnHandover(
    utils::u32 uav_id,
    utils::u32 old_skdc_id,
    utils::u32 new_skdc_id)
{
    auto uav      = GetUavNode(uav_id);
    auto old_skdc = GetSkdcNode(old_skdc_id);
    auto new_skdc = GetSkdcNode(new_skdc_id);

    std::ostringstream label;
    label << "HO_UAV" << uav_id;

    if (uav && old_skdc)
        UpdateLink(uav, old_skdc, label.str() + "_LEAVE");
    if (uav && new_skdc)
        UpdateLink(uav, new_skdc, label.str() + "_JOIN");

    RecordEvent(uav::packet::PacketType::HANDOVER_PACKET,
                uav_id, new_skdc_id, label.str());

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PacketViz: HANDOVER UAV" << uav_id
        << " SKDC" << old_skdc_id
        << "→SKDC" << new_skdc_id);
}

// ---------------------------------------------------------------------------
// ClearAllLinks
// ---------------------------------------------------------------------------
void PacketVizManager::ClearAllLinks()
{
    if (!m_netanim || !m_netanim->GetAnim()) return;

    // Clear UAV↔SKDC links
    for (uint32_t c = 0; c < 3; ++c) {
        auto skdc = GetSkdcNode(c);
        if (!skdc) continue;
        uint32_t base = c * 6;
        for (uint32_t i = 0; i < 6; ++i) {
            auto uav = GetUavNode(base + i);
            if (uav) UpdateLink(skdc, uav, "");
        }
    }
}

// ---------------------------------------------------------------------------
// PrintStats
// ---------------------------------------------------------------------------
void PacketVizManager::PrintStats() const
{
    std::cout << "\n=== PacketVizManager Stats ===\n";
    std::cout << "  Total events: " << m_total_events << "\n";
    std::cout << "  MTK events:   " << m_mtk_events   << "\n";
    std::cout << "  Rekey events: " << m_rekey_events << "\n";
    std::cout << "  Data events:  " << m_data_events  << "\n";
    std::cout << "  History:\n";
    for (const auto& r : m_history) {
        std::cout << "    t=" << r.time_s
            << "s " << r.label << "\n";
    }
}

} // namespace visualization
} // namespace uav
