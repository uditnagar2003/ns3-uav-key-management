/**
 * REKEY_LATENCY_FIX.h
 * 
 * Patch for: scratch/uav-secure-fanet/apps/SkdcApplication.h/.cc
 * 
 * Problem: rekey latency hardcoded to 0.05ms
 * Fix: measure actual time from SKDC broadcast → last UAV receipt
 * 
 * Integration:
 *   - Add RekeyTracker to SkdcApplication
 *   - Call RekeyTracker::OnRekeySent() in TriggerRekey()
 *   - Call RekeyTracker::OnUavAck() in HandleAckPacket()
 *   - Wire MetricsManager::RecordRekeyLatency() on completion
 */

#pragma once

#include "ns3/simulator.h"
#include <map>
#include <set>
#include <functional>
#include <fstream>

namespace ns3 {
namespace fanet {

/**
 * Tracks one rekey event: sent time + per-UAV receipt times.
 * Computes true end-to-end latency when all UAVs have ACKed.
 */
struct RekeyTrackEntry {
    double       sendTime_s;        ///< Simulator time when SKDC broadcast REKEY
    uint32_t     clusterId;
    uint32_t     tekVersion;
    std::string  triggerType;       ///< "PERIODIC" | "HANDOVER" | "KDC_INIT" | "LEAVE"
    uint32_t     expectedAcks;      ///< How many UAVs must ACK (= cluster size)
    
    std::map<uint32_t, double> uavRecvTime;  ///< uavId → recv time (seconds)
    bool         completed = false;
    
    /** True latency = last recv - send, in milliseconds */
    double ComputeLatencyMs() const {
        if (uavRecvTime.empty()) return -1.0;
        double lastRecv = 0.0;
        for (auto& [uid, t] : uavRecvTime)
            lastRecv = std::max(lastRecv, t);
        return (lastRecv - sendTime_s) * 1000.0;
    }
    
    /** Message cost in bytes = packet_size * member_count */
    uint32_t MessageCostBytes(uint32_t rekeyPacketSize = 512) const {
        return rekeyPacketSize * expectedAcks;
    }
};

/**
 * RekeyLatencyTracker
 * 
 * Add one instance per SKDC. Handles multi-cluster tracking.
 * Calls completion callback when all UAVs in a cluster have ACKed.
 */
class RekeyLatencyTracker {
public:
    using CompletionCb = std::function<void(const RekeyTrackEntry&)>;
    
    explicit RekeyLatencyTracker(const std::string& logPath)
        : m_logPath(logPath)
    {
        m_ofs.open(logPath, std::ios::out);
        if (m_ofs.is_open()) {
            m_ofs << "time_s,cluster_id,trigger,latency_ms,"
                  << "tek_version,members,msg_cost_bytes\n";
        }
    }
    
    ~RekeyLatencyTracker() {
        if (m_ofs.is_open()) m_ofs.close();
    }
    
    /** Call when SKDC sends REKEY broadcast */
    void OnRekeySent(uint32_t tekVersion, uint32_t clusterId,
                     uint32_t clusterSize, const std::string& trigger)
    {
        RekeyTrackEntry entry;
        entry.sendTime_s    = Simulator::Now().GetSeconds();
        entry.clusterId     = clusterId;
        entry.tekVersion    = tekVersion;
        entry.triggerType   = trigger;
        entry.expectedAcks  = clusterSize;
        m_pending[tekVersion] = entry;
    }
    
    /**
     * Call when a UAV successfully receives and verifies REKEY packet.
     * In practice: call from UavApplication when REKEY decryption succeeds
     * and UAV sends implicit ACK or data packet back.
     * 
     * For simulations without explicit ACK: call from the SKDC's
     * packet Rx callback (if using unicast ACK) or schedule with
     * estimated propagation delay.
     */
    void OnUavReceived(uint32_t tekVersion, uint32_t uavId) {
        auto it = m_pending.find(tekVersion);
        if (it == m_pending.end()) return;
        
        auto& entry = it->second;
        if (entry.completed) return;
        
        entry.uavRecvTime[uavId] = Simulator::Now().GetSeconds();
        
        // Check if all expected UAVs have received
        if (entry.uavRecvTime.size() >= entry.expectedAcks) {
            entry.completed = true;
            double latency = entry.ComputeLatencyMs();
            
            // Write to CSV
            if (m_ofs.is_open()) {
                m_ofs << entry.sendTime_s << ","
                      << entry.clusterId << ","
                      << entry.triggerType << ","
                      << latency << ","
                      << entry.tekVersion << ","
                      << entry.expectedAcks << ","
                      << entry.MessageCostBytes() << "\n";
                m_ofs.flush();
            }
            
            std::cout << "RekeyLatencyTracker: TEK=" << tekVersion
                << " cluster=" << entry.clusterId
                << " trigger=" << entry.triggerType
                << " latency=" << latency << "ms"
                << " members=" << entry.expectedAcks << std::endl;
            
            if (m_completionCb) m_completionCb(entry);
            m_pending.erase(it);
        }
    }
    
    /**
     * Timeout handler: if not all UAVs ACK within timeout,
     * record partial completion (counts packet loss).
     * Schedule with Simulator::Schedule(timeout, ...).
     */
    void OnTimeout(uint32_t tekVersion) {
        auto it = m_pending.find(tekVersion);
        if (it == m_pending.end()) return;
        
        auto& entry = it->second;
        if (entry.completed) return;
        
        uint32_t received = entry.uavRecvTime.size();
        uint32_t lost     = entry.expectedAcks - received;
        double latency    = (received > 0) ? entry.ComputeLatencyMs() : -1.0;
        
        std::cout << "[WARN] " << "RekeyLatencyTracker TIMEOUT: TEK=" << tekVersion
            << " received=" << received << "/" << entry.expectedAcks
            << " lost=" << lost << std::endl;
        
        // Write partial result with negative latency to flag timeout
        if (m_ofs.is_open()) {
            m_ofs << entry.sendTime_s << ","
                  << entry.clusterId << ","
                  << entry.triggerType << "_TIMEOUT" << ","
                  << latency << ","
                  << entry.tekVersion << ","
                  << entry.expectedAcks << ","
                  << entry.MessageCostBytes() << "\n";
            m_ofs.flush();
        }
        
        entry.completed = true;
        m_pending.erase(it);
    }
    
    void SetCompletionCallback(CompletionCb cb) { m_completionCb = cb; }
    
    size_t PendingCount() const { return m_pending.size(); }

private:
    std::string              m_logPath;
    std::ofstream            m_ofs;
    std::map<uint32_t, RekeyTrackEntry> m_pending;
    CompletionCb             m_completionCb;
};

/**
 * HOW TO INTEGRATE IN SkdcApplication.h:
 * 
 *   // Add member:
 *   std::unique_ptr<RekeyLatencyTracker> m_rekeyTracker;
 *
 * HOW TO INTEGRATE IN SkdcApplication.cc:
 *
 *   // In StartApplication():
 *   m_rekeyTracker = std::make_unique<RekeyLatencyTracker>(
 *       "output/rekey_perf/metrics/rekey_latency_full.csv");
 *
 *   // In TriggerRekey(clusterId, trigger):
 *   m_rekeyTracker->OnRekeySent(m_tekVersion, clusterId,
 *       m_clusterMembers[clusterId].size(), trigger);
 *   // Schedule timeout:
 *   Simulator::Schedule(Seconds(5.0), [this, tek=m_tekVersion]() {
 *       m_rekeyTracker->OnTimeout(tek);
 *   });
 *
 * HOW TO INTEGRATE IN UavApplication.cc:
 *
 *   // When REKEY packet successfully decrypted:
 *   // Option A: UAV sends explicit ACK back to SKDC
 *   // Option B: SKDC intercepts first DATA packet from UAV after rekey
 *   //           as implicit ACK (simpler)
 *   //
 *   // For Option B, in SkdcApplication::HandleIncomingData():
 *   if (m_pendingRekeyAck.count(uavId)) {
 *       uint32_t tekVer = m_pendingRekeyAck[uavId];
 *       m_rekeyTracker->OnUavReceived(tekVer, uavId);
 *       m_pendingRekeyAck.erase(uavId);
 *   }
 */

} // namespace fanet
} // namespace ns3
