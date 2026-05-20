/**
 * routing/uav-queue-manager.h
 *
 * Queue Management for UAV Secure FANET
 *
 * Per project spec:
 *   Maximum queue size: 100 packets
 *
 * Manages:
 *   - WiFi device queue configuration (100 packets)
 *   - CSMA device queue configuration
 *   - Per-node queue drop tracking
 *   - Queue occupancy monitoring
 *   - Priority queue support for security packets
 *
 * PACKET PRIORITY MAPPING:
 *   CRITICAL (AUTH/HANDOVER) → highest priority
 *   HIGH     (REKEY/MTK/JOIN) → high priority
 *   NORMAL   (DATA)           → normal priority
 */

#ifndef UAV_QUEUE_MANAGER_H
#define UAV_QUEUE_MANAGER_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/queue-disc.h"

#include "uav-topology.h"
#include "uav-types.h"
#include "uav-error.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace uav {
namespace routing {

// ===========================================================================
// QueueStats — per-node queue statistics
// ===========================================================================
struct QueueStats {
    utils::u32  node_id       = 0;
    utils::u32  queue_size    = 0;   // current packets
    utils::u32  max_size      = 100;
    utils::u64  total_enqueued= 0;
    utils::u64  total_dropped = 0;
    double      occupancy_pct = 0.0;
};

// ===========================================================================
// QueueManager
// ===========================================================================
class QueueManager {
public:
    static constexpr utils::u32 MAX_QUEUE_SIZE = 100;
    static constexpr utils::u32 WIFI_QUEUE_SIZE = 100;
    static constexpr utils::u32 CSMA_QUEUE_SIZE = 100;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    explicit QueueManager(const TopologyResult& topo);

    // -----------------------------------------------------------------------
    // Queue configuration
    // -----------------------------------------------------------------------

    /// Configure all WiFi device queues to MAX_QUEUE_SIZE
    void ConfigureWifiQueues();

    /// Configure all CSMA device queues
    void ConfigureCsmaQueues();

    /// Configure all queues (WiFi + CSMA)
    void ConfigureAll();

    // -----------------------------------------------------------------------
    // Queue queries
    // -----------------------------------------------------------------------

    /// Get current queue depth for a node's WiFi device
    utils::u32 GetWifiQueueDepth(utils::u32 uav_index) const;

    /// Get queue stats for a node
    QueueStats GetQueueStats(utils::u32 node_id) const;

    /// Check if queue is near-full (>80% occupancy)
    bool IsQueueNearFull(utils::u32 uav_index) const;

    // -----------------------------------------------------------------------
    // Drop tracking
    // -----------------------------------------------------------------------

    /// Record a packet drop event
    void RecordDrop(utils::u32 node_id);

    /// Get total drops across all nodes
    utils::u64 GetTotalDrops() const;

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    void PrintQueueStats() const;
    std::vector<QueueStats> GetAllStats() const;

private:
    const TopologyResult&                         m_topo;
    std::unordered_map<utils::u32, QueueStats>    m_stats;

    /// Set queue size on a NetDevice
    void SetDeviceQueueSize(
        ns3::Ptr<ns3::NetDevice> dev,
        utils::u32 size);
};

} // namespace routing
} // namespace uav

#endif // UAV_QUEUE_MANAGER_H
