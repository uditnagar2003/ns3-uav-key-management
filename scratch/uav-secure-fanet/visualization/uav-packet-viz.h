/**
 * visualization/uav-packet-viz.h
 * Module 51 — Packet Visualization
 *
 * Uses existing infrastructure:
 *   - headers/uav-packet-enums.h  → PacketType enum
 *   - headers/uav-packet-manager.h → PacketManager callbacks
 *   - AnimationInterface::UpdateLinkDescription() → link labels
 *   - AnimationInterface::EnablePacketMetadata() → already enabled
 *
 * Visualizes in NetAnim:
 *   - Link labels showing packet type on each active link
 *   - MTK_PACKET:   SKDC → UAV cluster (broadcast)
 *   - REKEY_PACKET: SKDC → all cluster UAVs
 *   - JOIN_PACKET:  UAV  → SKDC
 *   - DATA_PACKET:  UAV  → SKDC
 *   - HANDOVER:     UAV  → old SKDC + new SKDC
 */

#ifndef UAV_PACKET_VIZ_H
#define UAV_PACKET_VIZ_H

#include "visualization/uav-netanim.h"
#include "headers/uav-packet-enums.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <string>
#include <vector>
#include <array>

namespace uav {
namespace visualization {

// ===========================================================================
// PacketVizRecord — one recorded packet visualization event
// ===========================================================================
struct PacketVizRecord {
    double          time_s    = 0.0;
    uav::packet::PacketType  pkt_type;
    utils::u32      src_id    = 0;
    utils::u32      dst_id    = 0;
    std::string     label;
};

// ===========================================================================
// PacketVizManager — Module 51
// ===========================================================================
class PacketVizManager {
public:
    PacketVizManager(
        const routing::TopologyResult* topo,
        NetAnimManager*                netanim);

    /**
     * Initialize — sets up initial link descriptions.
     */
    void Initialize();

    // -----------------------------------------------------------------------
    // Packet event notifications
    // Call these when packets are sent to update NetAnim link labels.
    // -----------------------------------------------------------------------

    /// MTK broadcast from SKDC to cluster UAVs
    void OnMtkBroadcast(utils::u32 skdc_id,
                        utils::u32 cluster_id,
                        utils::u32 version);

    /// Rekey broadcast from SKDC to cluster
    void OnRekeyBroadcast(utils::u32 skdc_id,
                          utils::u32 cluster_id);

    /// Join request from UAV to SKDC
    void OnJoinRequest(utils::u32 uav_id,
                       utils::u32 skdc_id);

    /// Data packet from UAV to SKDC
    void OnDataPacket(utils::u32 uav_id,
                      utils::u32 skdc_id);

    /// Handover notification
    void OnHandover(utils::u32 uav_id,
                    utils::u32 old_skdc_id,
                    utils::u32 new_skdc_id);

    /// Clear all link descriptions
    void ClearAllLinks();

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalEvents()  const { return m_total_events;  }
    utils::u64 GetMtkEvents()    const { return m_mtk_events;    }
    utils::u64 GetRekeyEvents()  const { return m_rekey_events;  }
    utils::u64 GetDataEvents()   const { return m_data_events;   }

    const std::vector<PacketVizRecord>& GetHistory()
        const { return m_history; }

    void PrintStats() const;

private:
    const routing::TopologyResult* m_topo;
    NetAnimManager*                m_netanim;

    std::vector<PacketVizRecord>   m_history;
    utils::u64  m_total_events  = 0;
    utils::u64  m_mtk_events    = 0;
    utils::u64  m_rekey_events  = 0;
    utils::u64  m_data_events   = 0;

    /// Update link label between two NS-3 nodes
    void UpdateLink(
        ns3::Ptr<ns3::Node> from,
        ns3::Ptr<ns3::Node> to,
        const std::string&  label);

    /// Get SKDC node pointer
    ns3::Ptr<ns3::Node> GetSkdcNode(utils::u32 skdc_id) const;

    /// Get UAV node pointer
    ns3::Ptr<ns3::Node> GetUavNode(utils::u32 uav_id) const;

    void RecordEvent(
        uav::packet::PacketType pkt_type,
        utils::u32 src_id,
        utils::u32 dst_id,
        const std::string& label);
};

} // namespace visualization
} // namespace uav

#endif // UAV_PACKET_VIZ_H
