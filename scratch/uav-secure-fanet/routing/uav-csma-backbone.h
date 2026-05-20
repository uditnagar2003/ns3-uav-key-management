/**
 * routing/uav-csma-backbone.h
 *
 * CSMA KDC Backbone Manager
 *
 * Manages the wired CSMA backbone connecting:
 *   KDC (Node 0) ←→ SKDC0 (Node 1)
 *   KDC (Node 0) ←→ SKDC1 (Node 2)
 *   KDC (Node 0) ←→ SKDC2 (Node 3)
 *
 * RESPONSIBILITIES:
 *   - KDC ↔ SKDC secure channel management
 *   - TEK synchronization routing
 *   - Handover relay (old SKDC → KDC → new SKDC)
 *   - Backbone link quality monitoring
 *   - Static routing between KDC and SKDCs
 *
 * CSMA SPEC:
 *   DataRate : 100 Mbps
 *   Delay    : 1 ms
 *   MTU      : 1500 bytes
 *
 * ADDRESS MAPPING:
 *   KDC   : 192.168.0.1
 *   SKDC0 : 192.168.0.2
 *   SKDC1 : 192.168.0.3
 *   SKDC2 : 192.168.0.4
 */

#ifndef UAV_CSMA_BACKBONE_H
#define UAV_CSMA_BACKBONE_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <functional>
#include <string>
#include <vector>

namespace uav {
namespace routing {

// ===========================================================================
// BackboneStats — CSMA link statistics
// ===========================================================================
struct BackboneStats {
    utils::u64  kdc_to_skdc_pkts  = 0;
    utils::u64  skdc_to_kdc_pkts  = 0;
    utils::u64  skdc_to_skdc_pkts = 0;  // via KDC relay
    utils::u64  handover_relays   = 0;
    utils::u64  tek_syncs         = 0;
    double      avg_latency_ms    = 1.0; // CSMA delay
};

// ===========================================================================
// CsmaBackboneManager
// ===========================================================================
class CsmaBackboneManager {
public:
    // CSMA parameters
    static constexpr double   LINK_LATENCY_MS  = 1.0;
    static constexpr double   BANDWIDTH_MBPS   = 100.0;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit CsmaBackboneManager(const TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Address queries
    // -----------------------------------------------------------------------

    /// Get KDC CSMA IP address
    ns3::Ipv4Address GetKdcAddress() const;

    /// Get SKDC CSMA IP address for cluster
    ns3::Ipv4Address GetSkdcAddress(utils::u32 cluster) const;

    /// Get all SKDC addresses
    std::vector<ns3::Ipv4Address> GetAllSkdcAddresses() const;

    // -----------------------------------------------------------------------
    // Routing helpers
    // -----------------------------------------------------------------------

    /// Configure static routes so KDC can reach all SKDCs
    void ConfigureStaticRoutes();

    /// Get next hop from src to dst on backbone
    ns3::Ipv4Address GetNextHop(ns3::Ipv4Address src,
                                 ns3::Ipv4Address dst) const;

    // -----------------------------------------------------------------------
    // Backbone operations
    // -----------------------------------------------------------------------

    /// Simulate KDC → SKDC TEK sync notification
    void NotifyTekSync(utils::u32 cluster);

    /// Simulate handover relay: old_cluster → KDC → new_cluster
    void RelayHandover(utils::u32 old_cluster,
                       utils::u32 new_cluster);

    /// Check if backbone link is active
    bool IsLinkActive(utils::u32 cluster) const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    const BackboneStats& GetStats() const { return m_stats; }
    void ResetStats() { m_stats = BackboneStats{}; }
    void PrintStats() const;

    // -----------------------------------------------------------------------
    // Info
    // -----------------------------------------------------------------------
    void PrintTopology() const;

private:
    const TopologyResult& m_topo;
    BackboneStats         m_stats;
};

} // namespace routing
} // namespace uav

#endif // UAV_CSMA_BACKBONE_H
