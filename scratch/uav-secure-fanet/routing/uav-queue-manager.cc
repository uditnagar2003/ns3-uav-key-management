/**
 * routing/uav-queue-manager.cc
 */

#include "uav-queue-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include "ns3/wifi-net-device.h"
#include "ns3/csma-net-device.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/wifi-mac-queue.h"

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
    // Initialize stats for all UAV nodes
    for (utils::u32 i = 0;
         i < topo.uav_nodes.GetN(); ++i)
    {
        utils::u32 nid = topo.uav_nodes.Get(i)->GetId();
        QueueStats s;
        s.node_id  = nid;
        s.max_size = MAX_QUEUE_SIZE;
        m_stats[nid] = s;
    }

    // Initialize stats for ground nodes
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
// Set queue size on a NetDevice
// ===========================================================================
void QueueManager::SetDeviceQueueSize(
    Ptr<NetDevice> dev,
    utils::u32 size)
{
    // Try WifiNetDevice
    Ptr<WifiNetDevice> wifi_dev =
        DynamicCast<WifiNetDevice>(dev);
    if (wifi_dev) {
        Ptr<WifiMac> mac = wifi_dev->GetMac();
        if (mac) {
            // Set MAC queue size via attribute
            // WifiMacQueue is accessible through
            // the MAC layer
            mac->SetAttribute("BE_MaxQueueSize",
                QueueSizeValue(QueueSize(
                    QueueSizeUnit::PACKETS, size)));
            mac->SetAttribute("BK_MaxQueueSize",
                QueueSizeValue(QueueSize(
                    QueueSizeUnit::PACKETS, size)));
            mac->SetAttribute("VI_MaxQueueSize",
                QueueSizeValue(QueueSize(
                    QueueSizeUnit::PACKETS, size)));
            mac->SetAttribute("VO_MaxQueueSize",
                QueueSizeValue(QueueSize(
                    QueueSizeUnit::PACKETS, size)));
        }
        return;
    }

    // Try CsmaNetDevice
    Ptr<CsmaNetDevice> csma_dev =
        DynamicCast<CsmaNetDevice>(dev);
    if (csma_dev) {
        Ptr<Queue<Packet>> q = csma_dev->GetQueue();
        if (q) {
            q->SetMaxSize(QueueSize(
                QueueSizeUnit::PACKETS, size));
        }
    }
}

// ===========================================================================
// Configure WiFi queues
// ===========================================================================
void QueueManager::ConfigureWifiQueues() {
    for (utils::u32 i = 0;
         i < m_topo.wifi_devices.GetN(); ++i)
    {
        SetDeviceQueueSize(
            m_topo.wifi_devices.Get(i),
            WIFI_QUEUE_SIZE);
    }

    UAV_LOG_INFO(uav::log::channels::ROUTING,
        "QueueManager: WiFi queues configured "
        << "size=" << WIFI_QUEUE_SIZE
        << " devices=" << m_topo.wifi_devices.GetN());
}

// ===========================================================================
// Configure CSMA queues
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
// Configure all queues
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

    Ptr<Node> node = m_topo.uav_nodes.Get(uav_index);
    for (utils::u32 i = 0;
         i < node->GetNDevices(); ++i)
    {
        Ptr<WifiNetDevice> wifi_dev =
            DynamicCast<WifiNetDevice>(
                node->GetDevice(i));
        if (wifi_dev) {
            // Queue depth not directly queryable
            // Return from stats
            utils::u32 nid = node->GetId();
            auto it = m_stats.find(nid);
            if (it != m_stats.end())
                return it->second.queue_size;
        }
    }
    return 0;
}

// ===========================================================================
// Queue stats
// ===========================================================================
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
    utils::u32 depth =
        GetWifiQueueDepth(uav_index);
    return depth > (MAX_QUEUE_SIZE * 80 / 100);
}

// ===========================================================================
// Drop tracking
// ===========================================================================
void QueueManager::RecordDrop(utils::u32 node_id) {
    auto it = m_stats.find(node_id);
    if (it != m_stats.end()) {
        ++it->second.total_dropped;
    }
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
