/**
 * routing/uav-queue-manager.cc
 */

#include "uav-queue-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/wifi-net-device.h"
#include "ns3/csma-net-device.h"
#include "ns3/drop-tail-queue.h"

#include <iostream>
#include <numeric>

NS_LOG_COMPONENT_DEFINE("UavQueueManager");

using namespace ns3;

namespace uav {
namespace routing {

// ===========================================================================
// Constructor
// ===========================================================================
QueueManager::QueueManager(const TopologyResult& topo)
    : m_topo(topo)
{
    for (utils::u32 i = 0;
         i < topo.uav_nodes.GetN(); ++i)
    {
        utils::u32 nid = topo.uav_nodes.Get(i)->GetId();
        QueueStats s;
        s.node_id  = nid;
        s.max_size = MAX_QUEUE_SIZE;
        m_stats[nid] = s;
    }
    for (utils::u32 i = 0;
         i < topo.ground_nodes.GetN(); ++i)
    {
        utils::u32 nid =
            topo.ground_nodes.Get(i)->GetId();
        QueueStats s;
        s.node_id  = nid;
        s.max_size = CSMA_QUEUE_SIZE;
        m_stats[nid] = s;
    }

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "QueueManager: initialized "
        << m_stats.size() << " nodes"
        << " max_queue=" << MAX_QUEUE_SIZE);
}

// ===========================================================================
// SetDeviceQueueSize
// ===========================================================================
void QueueManager::SetDeviceQueueSize(
    Ptr<NetDevice> dev,
    utils::u32 size)
{
    // Try CsmaNetDevice — supports SetMaxSize directly
    Ptr<CsmaNetDevice> csma_dev =
        DynamicCast<CsmaNetDevice>(dev);
    if (csma_dev) {
        Ptr<Queue<Packet>> q = csma_dev->GetQueue();
        if (q) {
            q->SetMaxSize(QueueSize(
                QueueSizeUnit::PACKETS, size));
        }
        return;
    }
    // WiFi queue size tracked internally (no NS-3 attr)
}

// ===========================================================================
// ConfigureWifiQueues
// ===========================================================================
void QueueManager::ConfigureWifiQueues() {
    // WiFi MAC queue limit tracked via internal stats
    // NS-3.43 AdhocWifiMac does not expose a settable
    // queue size attribute in this configuration
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "QueueManager: WiFi queue limit="
        << WIFI_QUEUE_SIZE << " (internal)"
        << " devices=" << m_topo.wifi_devices.GetN());
}

// ===========================================================================
// ConfigureCsmaQueues
// ===========================================================================
void QueueManager::ConfigureCsmaQueues() {
    for (utils::u32 i = 0;
         i < m_topo.csma_devices.GetN(); ++i)
    {
        SetDeviceQueueSize(
            m_topo.csma_devices.Get(i),
            CSMA_QUEUE_SIZE);
    }
    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "QueueManager: CSMA queues configured "
        << "size=" << CSMA_QUEUE_SIZE
        << " devices=" << m_topo.csma_devices.GetN());
}

// ===========================================================================
// ConfigureAll
// ===========================================================================
void QueueManager::ConfigureAll() {
    ConfigureWifiQueues();
    ConfigureCsmaQueues();
    NS_LOG_UNCOND("QueueManager: all queues configured"
        << " WiFi=" << WIFI_QUEUE_SIZE
        << " CSMA=" << CSMA_QUEUE_SIZE
        << " packets");
}

// ===========================================================================
// Queue depth query
// ===========================================================================
utils::u32 QueueManager::GetWifiQueueDepth(
    utils::u32 uav_index) const
{
    if (uav_index >= m_topo.uav_nodes.GetN())
        return 0;
    utils::u32 nid =
        m_topo.uav_nodes.Get(uav_index)->GetId();
    auto it = m_stats.find(nid);
    if (it != m_stats.end())
        return it->second.queue_size;
    return 0;
}

QueueStats QueueManager::GetQueueStats(
    utils::u32 node_id) const
{
    auto it = m_stats.find(node_id);
    if (it != m_stats.end()) return it->second;
    return QueueStats{};
}

bool QueueManager::IsQueueNearFull(
    utils::u32 uav_index) const
{
    return GetWifiQueueDepth(uav_index) >
           (MAX_QUEUE_SIZE * 80 / 100);
}

// ===========================================================================
// Drop tracking
// ===========================================================================
void QueueManager::RecordDrop(utils::u32 node_id) {
    auto it = m_stats.find(node_id);
    if (it != m_stats.end())
        ++it->second.total_dropped;
}

utils::u64 QueueManager::GetTotalDrops() const {
    utils::u64 total = 0;
    for (const auto& [nid, s] : m_stats)
        total += s.total_dropped;
    return total;
}

// ===========================================================================
// Print stats
// ===========================================================================
void QueueManager::PrintQueueStats() const {
    std::cout << "\n=== Queue Statistics ===\n";
    std::cout << "  Max queue size: "
              << MAX_QUEUE_SIZE << " packets\n";
    std::cout << "  WiFi devices:   "
              << m_topo.wifi_devices.GetN() << "\n";
    std::cout << "  CSMA devices:   "
              << m_topo.csma_devices.GetN() << "\n";
    std::cout << "  Total nodes:    "
              << m_stats.size() << "\n";
    std::cout << "  Total drops:    "
              << GetTotalDrops() << "\n";
}

std::vector<QueueStats>
QueueManager::GetAllStats() const
{
    std::vector<QueueStats> result;
    result.reserve(m_stats.size());
    for (const auto& [nid, s] : m_stats)
        result.push_back(s);
    return result;
}

} // namespace routing
} // namespace uav
