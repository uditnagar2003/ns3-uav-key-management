#ifndef UAV_JAMMER_ERROR_MODEL_H
#define UAV_JAMMER_ERROR_MODEL_H

#include "ns3/error-model.h"
#include "ns3/packet.h"
#include "apps/uav-jammer-manager.h"
#include "utils/uav-types.h"

namespace uav {
namespace apps {

/**
 * JammerErrorModel
 * Installed on each UAV's WiFi NetDevice receive path.
 * Drops packets probabilistically based on SINR from JammerManager.
 */
class JammerErrorModel : public ns3::ErrorModel {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid =
            ns3::TypeId("uav::apps::JammerErrorModel")
            .SetParent<ns3::ErrorModel>()
            .SetGroupName("UavSecureFanet")
            .AddConstructor<JammerErrorModel>();
        return tid;
    }

    JammerErrorModel() = default;

    void SetJammerManager(JammerManager* mgr) {
        m_jammer_mgr = mgr;
    }
    void SetUavIndex(utils::u32 idx) {
        m_uav_index = idx;
    }
    utils::u64 GetDropCount() const {
        return m_drop_count;
    }

private:
    bool DoCorrupt(ns3::Ptr<ns3::Packet> pkt) override {
        if (!m_jammer_mgr) return false;

        bool drop = m_jammer_mgr->ShouldDrop(
            m_uav_index,
            static_cast<utils::u32>(
                ns3::Simulator::Now().GetNanoSeconds()));

        if (drop) {
            ++m_drop_count;
            NS_LOG_UNCOND("[JAMMER_DROP] t="
                << ns3::Simulator::Now().GetSeconds()
                << "s uav=" << m_uav_index
                << " drop_prob="
                << m_jammer_mgr->GetDropProbability(m_uav_index)
                << " total_drops=" << m_drop_count);
        }
        return drop;
    }

    void DoReset() override {
        m_drop_count = 0;
    }

    JammerManager*  m_jammer_mgr = nullptr;
    utils::u32      m_uav_index  = 0;
    utils::u64      m_drop_count = 0;
};

} // namespace apps
} // namespace uav

#endif // UAV_JAMMER_ERROR_MODEL_H
