/**
 * routing/uav-olsr-manager.h
 *
 * OLSR Routing Integration Manager
 *
 * Manages OLSR routing for UAV swarm:
 *   - OLSR parameter configuration
 *   - Routing table queries
 *   - Route existence checks
 *   - Per-node routing stats
 *   - Routing overhead tracking
 *
 * OLSR SPEC (per project):
 *   HELLO interval : 2 seconds
 *   TC interval    : 5 seconds
 *   Routing        : OLSR only (no static on WiFi nodes)
 *
 * OLSR is used ONLY for routing.
 * Security handled at application layer.
 */

#ifndef UAV_OLSR_MANAGER_H
#define UAV_OLSR_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-module.h"
#include "ns3/olsr-routing-protocol.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <string>
#include <vector>
#include <unordered_map>

namespace uav {
namespace routing {

// ===========================================================================
// OlsrStats — per-node OLSR statistics
// ===========================================================================
struct OlsrStats {
    utils::u32  node_id          = 0;
    utils::u32  neighbor_count   = 0;
    utils::u32  routing_entries  = 0;
    utils::u64  hello_sent       = 0;
    utils::u64  tc_sent          = 0;
    utils::u64  hello_recv       = 0;
    utils::u64  tc_recv          = 0;
    double      routing_overhead = 0.0;  // bytes/sec
};

// ===========================================================================
// RouteInfo — single routing table entry
// ===========================================================================
struct RouteInfo {
    ns3::Ipv4Address destination;
    ns3::Ipv4Address next_hop;
    utils::u32       interface_idx;
    utils::u32       distance;       // hops
};

// ===========================================================================
// OlsrManager
// ===========================================================================
class OlsrManager {
public:
    static constexpr double HELLO_INTERVAL_S = 2.0;
    static constexpr double TC_INTERVAL_S    = 5.0;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit OlsrManager(const TopologyResult& topo);

    // -----------------------------------------------------------------------
    // OLSR protocol access
    // -----------------------------------------------------------------------

    /// Get OLSR routing protocol for a UAV node
    ns3::Ptr<ns3::olsr::RoutingProtocol>
    GetOlsrProtocol(utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Routing table queries
    // -----------------------------------------------------------------------

    /// Get all routing entries for a UAV
    std::vector<RouteInfo> GetRoutingTable(
        utils::u32 uav_index) const;

    /// Check if route exists from UAV to IP
    bool HasRoute(utils::u32 uav_index,
                  ns3::Ipv4Address dst) const;

    /// Get neighbor count for UAV
    utils::u32 GetNeighborCount(
        utils::u32 uav_index) const;

    /// Get hop distance from uav_src to uav_dst
    utils::u32 GetHopDistance(utils::u32 uav_src,
                               utils::u32 uav_dst) const;

    // -----------------------------------------------------------------------
    // Cluster routing
    // -----------------------------------------------------------------------

    /// Get intra-cluster connected UAV count for cluster c
    utils::u32 GetIntraClusterConnected(
        utils::u32 cluster) const;

    /// Print routing table for UAV
    void PrintRoutingTable(utils::u32 uav_index) const;

    /// Print all neighbor tables
    void PrintNeighborSummary() const;

    // -----------------------------------------------------------------------
    // Overhead tracking
    // -----------------------------------------------------------------------

    /// Estimate OLSR overhead (bytes/sec) based on topology
    double EstimateOverheadBps() const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    OlsrStats GetNodeStats(utils::u32 uav_index) const;
    void PrintAllStats() const;

private:
    const TopologyResult& m_topo;

    /// Get IPv4 address of WiFi interface for UAV
    ns3::Ipv4Address GetUavWifiAddr(
        utils::u32 uav_index) const;
};

} // namespace routing
} // namespace uav

#endif // UAV_OLSR_MANAGER_H
