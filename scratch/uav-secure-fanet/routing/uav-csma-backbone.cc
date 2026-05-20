/**
 * routing/uav-csma-backbone.cc
 */

#include "uav-csma-backbone.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-routing-table-entry.h"

#include <iostream>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("UavCsmaBackbone");

using namespace ns3;

namespace uav {
namespace routing {

// ===========================================================================
// Constructor
// ===========================================================================
CsmaBackboneManager::CsmaBackboneManager(
    const TopologyResult& topo)
    : m_topo(topo)
{
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "CsmaBackboneManager: initialized "
        "KDC@" << GetKdcAddress()
        << " SKDCs: "
        << GetSkdcAddress(0) << ", "
        << GetSkdcAddress(1) << ", "
        << GetSkdcAddress(2));
}

// ===========================================================================
// Address queries
// ===========================================================================
Ipv4Address CsmaBackboneManager::GetKdcAddress() const {
    // CSMA interface 0 = KDC
    return m_topo.csma_interfaces.GetAddress(0);
}

Ipv4Address CsmaBackboneManager::GetSkdcAddress(
    utils::u32 cluster) const
{
    if (cluster >= 3) {
        UAV_THROW(utils::ConfigException,
            "CsmaBackbone: invalid cluster "
            + std::to_string(cluster));
    }
    // CSMA interfaces: [0]=KDC, [1]=SKDC0, [2]=SKDC1, [3]=SKDC2
    return m_topo.csma_interfaces.GetAddress(cluster + 1);
}

std::vector<Ipv4Address>
CsmaBackboneManager::GetAllSkdcAddresses() const
{
    return {
        GetSkdcAddress(0),
        GetSkdcAddress(1),
        GetSkdcAddress(2)
    };
}

// ===========================================================================
// Static routing
// All nodes are on same CSMA segment — no routing needed
// but we verify connectivity
// ===========================================================================
void CsmaBackboneManager::ConfigureStaticRoutes() {
    // All ground nodes share the same CSMA segment
    // Direct connectivity — no additional routing required
    // OLSR handles WiFi routing separately

    NS_LOG_INFO("CsmaBackbone: Static routes verified "
        "(single CSMA segment)");

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "CsmaBackboneManager::ConfigureStaticRoutes: "
        "KDC=" << GetKdcAddress()
        << " SKDC0=" << GetSkdcAddress(0)
        << " SKDC1=" << GetSkdcAddress(1)
        << " SKDC2=" << GetSkdcAddress(2));
}

// ===========================================================================
// Next hop (all on same segment → direct)
// ===========================================================================
Ipv4Address CsmaBackboneManager::GetNextHop(
    Ipv4Address src, Ipv4Address dst) const
{
    (void)src;
    // On CSMA, all nodes are directly reachable
    return dst;
}

// ===========================================================================
// Backbone operations
// ===========================================================================
void CsmaBackboneManager::NotifyTekSync(
    utils::u32 cluster)
{
    ++m_stats.tek_syncs;
    ++m_stats.kdc_to_skdc_pkts;

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "CsmaBackbone: TEK sync KDC→SKDC"
        << cluster
        << " addr=" << GetSkdcAddress(cluster));
}

void CsmaBackboneManager::RelayHandover(
    utils::u32 old_cluster,
    utils::u32 new_cluster)
{
    ++m_stats.handover_relays;
    ++m_stats.skdc_to_skdc_pkts;

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "CsmaBackbone: Handover relay "
        "SKDC" << old_cluster
        << "→KDC→SKDC" << new_cluster);
}

bool CsmaBackboneManager::IsLinkActive(
    utils::u32 cluster) const
{
    // CSMA backbone is always active in this model
    (void)cluster;
    return true;
}

// ===========================================================================
// Stats and info
// ===========================================================================
void CsmaBackboneManager::PrintStats() const {
    std::cout << "\n=== CSMA Backbone Statistics ===\n";
    std::cout << "  KDC→SKDC packets:   "
              << m_stats.kdc_to_skdc_pkts << "\n";
    std::cout << "  SKDC→KDC packets:   "
              << m_stats.skdc_to_kdc_pkts << "\n";
    std::cout << "  SKDC→SKDC relays:   "
              << m_stats.skdc_to_skdc_pkts << "\n";
    std::cout << "  Handover relays:    "
              << m_stats.handover_relays << "\n";
    std::cout << "  TEK syncs:          "
              << m_stats.tek_syncs << "\n";
    std::cout << "  Avg latency:        "
              << m_stats.avg_latency_ms << " ms\n";
}

void CsmaBackboneManager::PrintTopology() const {
    std::cout << "\n=== CSMA Backbone Topology ===\n";
    std::cout << "  KDC    : "
              << GetKdcAddress() << "\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        std::cout << "  SKDC" << c << "  : "
                  << GetSkdcAddress(c)
                  << " [cluster " << c << "]\n";
    }
    std::cout << "  DataRate: "
              << BANDWIDTH_MBPS << " Mbps\n";
    std::cout << "  Latency:  "
              << LINK_LATENCY_MS << " ms\n";
    std::cout << "  Links:    ";
    for (utils::u32 c = 0; c < 3; ++c) {
        std::cout << (IsLinkActive(c) ? "UP" : "DOWN");
        if (c < 2) std::cout << "/";
    }
    std::cout << "\n";
}

} // namespace routing
} // namespace uav
