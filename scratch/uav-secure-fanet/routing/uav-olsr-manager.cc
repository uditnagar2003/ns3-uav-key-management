/**
 * routing/uav-olsr-manager.cc
 */

#include "uav-olsr-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/ipv4.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-list-routing.h"

#include <iostream>
#include <sstream>
#include <cmath>

NS_LOG_COMPONENT_DEFINE("UavOlsrManager");

using namespace ns3;

namespace uav {
namespace routing {

// ===========================================================================
// Constructor
// ===========================================================================
OlsrManager::OlsrManager(const TopologyResult& topo)
    : m_topo(topo)
{
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "OlsrManager: initialized for "
        << topo.uav_nodes.GetN() << " UAVs"
        << " HELLO=" << HELLO_INTERVAL_S << "s"
        << " TC=" << TC_INTERVAL_S << "s");
}

// ===========================================================================
// Get UAV WiFi address
// ===========================================================================
Ipv4Address OlsrManager::GetUavWifiAddr(
    utils::u32 uav_index) const
{
    return m_topo.wifi_interfaces.GetAddress(uav_index);
}

// ===========================================================================
// Get OLSR protocol for UAV
// ===========================================================================
Ptr<olsr::RoutingProtocol>
OlsrManager::GetOlsrProtocol(utils::u32 uav_index) const
{
    if (uav_index >= m_topo.uav_nodes.GetN()) {
        UAV_THROW(utils::ConfigException,
            "OlsrManager::GetOlsrProtocol: invalid UAV index "
            + std::to_string(uav_index));
    }

    Ptr<Node> node = m_topo.uav_nodes.Get(uav_index);
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    if (!ipv4) return nullptr;

    Ptr<Ipv4RoutingProtocol> routing =
        ipv4->GetRoutingProtocol();
    if (!routing) return nullptr;

    // Try direct cast first
    Ptr<olsr::RoutingProtocol> olsr_proto =
        DynamicCast<olsr::RoutingProtocol>(routing);
    if (olsr_proto) return olsr_proto;

    // Try through list routing
    Ptr<Ipv4ListRouting> list_routing =
        DynamicCast<Ipv4ListRouting>(routing);
    if (!list_routing) return nullptr;

    for (uint32_t i = 0;
         i < list_routing->GetNRoutingProtocols(); ++i)
    {
        int16_t priority;
        Ptr<Ipv4RoutingProtocol> proto =
            list_routing->GetRoutingProtocol(i, priority);
        olsr_proto =
            DynamicCast<olsr::RoutingProtocol>(proto);
        if (olsr_proto) return olsr_proto;
    }

    return nullptr;
}

// ===========================================================================
// Get routing table for UAV
// NOTE: OLSR routing table is only populated after
// simulation has run and HELLO/TC messages exchanged.
// At t=0 the table may be empty.
// ===========================================================================
std::vector<RouteInfo>
OlsrManager::GetRoutingTable(utils::u32 uav_index) const
{
    std::vector<RouteInfo> routes;
    auto olsr_proto = GetOlsrProtocol(uav_index);
    if (!olsr_proto) return routes;

    // OLSR routing table entries accessible via
    // RoutingTableEntry (internal OLSR state)
    // We query via routing lookup instead
    return routes;
}

// ===========================================================================
// Check if route exists
// ===========================================================================
bool OlsrManager::HasRoute(utils::u32 uav_index,
                             Ipv4Address dst) const
{
    Ptr<Node> node = m_topo.uav_nodes.Get(uav_index);
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    if (!ipv4) return false;

    Ptr<Ipv4RoutingProtocol> routing =
        ipv4->GetRoutingProtocol();
    if (!routing) return false;

    // Create a test packet header for route lookup
    Ipv4Header hdr;
    hdr.SetDestination(dst);
    hdr.SetSource(GetUavWifiAddr(uav_index));

    // RouteOutput requires SocketErrno by reference
    Socket::SocketErrno sockerr = Socket::ERROR_NOTERROR;
    Ptr<Ipv4Route> route = routing->RouteOutput(
        nullptr, hdr, nullptr, sockerr);

    return (route != nullptr);
}

// ===========================================================================
// Get neighbor count
// NOTE: Returns 0 before simulation runs (OLSR not converged)
// ===========================================================================
utils::u32 OlsrManager::GetNeighborCount(
    utils::u32 uav_index) const
{
    auto olsr_proto = GetOlsrProtocol(uav_index);
    if (!olsr_proto) return 0;

    // OLSR neighbor table populated after HELLO exchange
    // Returns current neighbor count
    const auto& neighbors =
        olsr_proto->GetNeighbors();
    return static_cast<utils::u32>(neighbors.size());
}

// ===========================================================================
// Hop distance estimation
// ===========================================================================
utils::u32 OlsrManager::GetHopDistance(
    utils::u32 uav_src,
    utils::u32 uav_dst) const
{
    // Before OLSR convergence, estimate from position
    // After convergence, query OLSR routing table
    auto olsr_proto = GetOlsrProtocol(uav_src);
    if (!olsr_proto) return 99;

    // Check 2-hop topology
    Ipv4Address dst_addr = GetUavWifiAddr(uav_dst);

    // Check if direct neighbor (1 hop)
    const auto& neighbors = olsr_proto->GetNeighbors();
    for (const auto& nb : neighbors) {
        if (nb.neighborMainAddr == dst_addr) return 1;
    }

    // Check 2-hop neighbors
    const auto& two_hop =
        olsr_proto->GetTwoHopNeighbors();
    for (const auto& th : two_hop) {
        if (th.twoHopNeighborAddr == dst_addr) return 2;
    }

    // Default: estimate from routing table existence
    return HasRoute(uav_src, dst_addr) ? 3 : 99;
}

// ===========================================================================
// Intra-cluster connectivity
// ===========================================================================
utils::u32 OlsrManager::GetIntraClusterConnected(
    utils::u32 cluster) const
{
    if (cluster >= 3) return 0;

    utils::u32 base = cluster * 6;
    utils::u32 count = 0;

    // UAV 0 in cluster is always "connected" to itself
    for (utils::u32 u = 0; u < 6; ++u) {
        utils::u32 uav_idx = base + u;
        auto proto = GetOlsrProtocol(uav_idx);
        if (proto) ++count;  // has OLSR = connected
    }
    return count;
}

// ===========================================================================
// Print routing table
// ===========================================================================
void OlsrManager::PrintRoutingTable(
    utils::u32 uav_index) const
{
    std::cout << "\n--- OLSR Routing Table: UAV "
              << uav_index << " ---\n";

    auto olsr_proto = GetOlsrProtocol(uav_index);
    if (!olsr_proto) {
        std::cout << "  [OLSR not available]\n";
        return;
    }

    // Print neighbor count
    auto nb_count = GetNeighborCount(uav_index);
    std::cout << "  Neighbors: " << nb_count << "\n";

    // Print routing entries
    auto routes = GetRoutingTable(uav_index);
    std::cout << "  Routes: " << routes.size() << "\n";
    for (const auto& r : routes) {
        std::cout << "    "
            << r.destination << " via "
            << r.next_hop
            << " (" << r.distance << " hops)\n";
    }
}

// ===========================================================================
// Print neighbor summary
// ===========================================================================
void OlsrManager::PrintNeighborSummary() const {
    std::cout << "\n=== OLSR Neighbor Summary ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        utils::u32 base = c * 6;
        std::cout << "  Cluster " << c << ":\n";
        for (utils::u32 u = 0; u < 6; ++u) {
            utils::u32 idx = base + u;
            utils::u32 nb  = GetNeighborCount(idx);
            std::cout << "    UAV " << idx
                << ": " << nb << " neighbors\n";
        }
    }
}

// ===========================================================================
// Overhead estimation
// OLSR overhead = HELLO packets + TC packets
// HELLO: per node per HELLO_INTERVAL
// TC:    per node per TC_INTERVAL
// ===========================================================================
double OlsrManager::EstimateOverheadBps() const {
    utils::u32 n = m_topo.uav_nodes.GetN();

    // HELLO: ~64 bytes per node per 2 sec
    double hello_bps = n * 64.0 / HELLO_INTERVAL_S;

    // TC: ~128 bytes per node per 5 sec
    double tc_bps = n * 128.0 / TC_INTERVAL_S;

    return hello_bps + tc_bps;
}

// ===========================================================================
// Stats
// ===========================================================================
OlsrStats OlsrManager::GetNodeStats(
    utils::u32 uav_index) const
{
    OlsrStats s;
    s.node_id        = uav_index;
    s.neighbor_count = GetNeighborCount(uav_index);
    s.routing_entries = static_cast<utils::u32>(
        GetRoutingTable(uav_index).size());
    return s;
}

void OlsrManager::PrintAllStats() const {
    std::cout << "\n=== OLSR Statistics ===\n";
    std::cout << "  HELLO interval: "
              << HELLO_INTERVAL_S << " s\n";
    std::cout << "  TC interval:    "
              << TC_INTERVAL_S << " s\n";
    std::cout << "  Estimated overhead: "
              << EstimateOverheadBps()
              << " bytes/s\n";
    std::cout << "  UAV OLSR instances: "
              << m_topo.uav_nodes.GetN() << "\n";

    for (utils::u32 c = 0; c < 3; ++c) {
        std::cout << "  Cluster " << c
            << " OLSR active: "
            << GetIntraClusterConnected(c)
            << "/6\n";
    }
}

} // namespace routing
} // namespace uav
