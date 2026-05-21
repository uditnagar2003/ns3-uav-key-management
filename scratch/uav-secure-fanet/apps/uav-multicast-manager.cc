/**
 * apps/uav-multicast-manager.cc
 * Module 38 - Multicast Manager
 */

#include "apps/uav-multicast-manager.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>

NS_LOG_COMPONENT_DEFINE("UavMulticastManager");

using namespace ns3;

namespace uav {
namespace apps {

// ===========================================================================
// Constructor
// ===========================================================================
MulticastManager::MulticastManager(
    const routing::TopologyResult*  topo,
    const crypto::CryptoParamsFile* params)
    : m_topo(topo)
    , m_params(params)
{
    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MulticastManager: constructed");
}

// ===========================================================================
// Initialize - load from crypto_params.json
// ===========================================================================
void MulticastManager::Initialize() {
    if (!m_params) return;

    for (utils::u32 c = 0; c < 3; ++c) {
        if (c >= m_params->clusters.size()) break;

        const auto& cp = m_params->clusters[c];
        auto& g = m_groups[c];

        g.cluster_id = c;
        g.mt_k       = cp.MT_K;
        g.n_group    = cp.N_group;
        g.e_mk       = cp.e_MK;
        g.version    = 1;
        g.active     = true;

        // Build MKeyGen result for CRT operations
        m_mkg[c].eM      = cp.eM;
        m_mkg[c].n_total = cp.n_total;
        m_mkg[c].slaves  = cp.slave_keys;

        // Initialize members: UAVs 0-5 per cluster
        utils::u32 base = c * 6;
        for (utils::u32 u = 0; u < 6; ++u) {
            g.members.insert(base + u);
        }

        UAV_LOG_INFO(uav::log::channels::PACKET,
            "MulticastManager: cluster " << c
            << " initialized"
            << " members=" << g.members.size()
            << " version=" << g.version);
    }
}

// ===========================================================================
// AddMember - JoKeyUpdate (Algorithm 3)
// ===========================================================================
bool MulticastManager::AddMember(
    utils::u32 cluster_id,
    utils::u32 uav_index,
    utils::u32 uav_id)
{
    if (cluster_id >= 3) return false;
    auto& g = m_groups[cluster_id];

    if (g.IsMember(uav_index)) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "MulticastManager: UAV " << uav_id
            << " already member of cluster "
            << cluster_id);
        return false;
    }

    // Build current MToken for JoKeyUpdate
    crypto::MTokenResult current;
    current.MT_K         = g.mt_k;
    current.e_MK         = g.e_mk;
    current.T            = m_params->clusters[
        cluster_id].tek_int;
    current.N_group      = g.n_group;
    current.cluster_id   = cluster_id;
    current.version      = g.version;
    for (auto m : g.members)
        current.user_indices.push_back(m);

    // Run JoKeyUpdate
    auto result = crypto::CrtManager::JoKeyUpdate(
        m_mkg[cluster_id], current, uav_index);

    // Update group
    g.members.insert(uav_index);
    g.version  = result.version;
    g.mt_k     = result.MT_K;
    g.n_group  = result.N_group;
    g.e_mk     = result.e_MK;

    ++m_joins;
    ++m_rekeys;

    RecordEvent(MembershipEvent::Type::JOIN,
        uav_id, uav_index, cluster_id);
    DoRekey(cluster_id, result);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MulticastManager: UAV " << uav_id
        << " joined cluster " << cluster_id
        << " members=" << g.members.size()
        << " version=" << g.version);

    return true;
}

// ===========================================================================
// RemoveMember - LeKeyUpdate (Algorithm 5)
// ===========================================================================
bool MulticastManager::RemoveMember(
    utils::u32 cluster_id,
    utils::u32 uav_index,
    utils::u32 uav_id)
{
    if (cluster_id >= 3) return false;
    auto& g = m_groups[cluster_id];

    if (!g.IsMember(uav_index)) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "MulticastManager: UAV " << uav_id
            << " not member of cluster "
            << cluster_id);
        return false;
    }

    // Build current MToken
    crypto::MTokenResult current;
    current.MT_K         = g.mt_k;
    current.e_MK         = g.e_mk;
    current.T            = m_params->clusters[
        cluster_id].tek_int;
    current.N_group      = g.n_group;
    current.cluster_id   = cluster_id;
    current.version      = g.version;
    for (auto m : g.members)
        current.user_indices.push_back(m);

    // Run LeKeyUpdate
    auto result = crypto::CrtManager::LeKeyUpdate(
        m_mkg[cluster_id], current, uav_index);

    // Update group
    g.members.erase(uav_index);
    g.version  = result.version;
    g.mt_k     = result.MT_K;
    g.n_group  = result.N_group;
    g.e_mk     = result.e_MK;

    ++m_leaves;
    ++m_rekeys;

    RecordEvent(MembershipEvent::Type::LEAVE,
        uav_id, uav_index, cluster_id);
    DoRekey(cluster_id, result);

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MulticastManager: UAV " << uav_id
        << " left cluster " << cluster_id
        << " members=" << g.members.size()
        << " version=" << g.version);

    return true;
}

// ===========================================================================
// HandoverMember
// ===========================================================================
bool MulticastManager::HandoverMember(
    utils::u32 old_cluster,
    utils::u32 new_cluster,
    utils::u32 uav_index,
    utils::u32 uav_id)
{
    if (old_cluster >= 3 || new_cluster >= 3)
        return false;
    if (old_cluster == new_cluster)
        return false;

    UAV_LOG_INFO(uav::log::channels::PACKET,
        "MulticastManager: handover UAV "
        << uav_id
        << " cluster " << old_cluster
        << " -> " << new_cluster);

    // Leave old cluster
    bool left = RemoveMember(
        old_cluster, uav_index, uav_id);

    // New index in new cluster
    // Assign next available slot
    utils::u32 new_index =
        new_cluster * 6 +
        static_cast<utils::u32>(
            m_groups[new_cluster].members.size());

    // Join new cluster
    bool joined = AddMember(
        new_cluster, new_index, uav_id);

    RecordEvent(MembershipEvent::Type::HANDOVER,
        uav_id, uav_index, old_cluster);

    return left && joined;
}

// ===========================================================================
// Queries
// ===========================================================================
const MulticastGroupInfo& MulticastManager::GetGroup(
    utils::u32 cluster_id) const
{
    static MulticastGroupInfo empty;
    if (cluster_id >= 3) return empty;
    return m_groups[cluster_id];
}

bool MulticastManager::IsMember(
    utils::u32 cluster_id,
    utils::u32 uav_index) const
{
    if (cluster_id >= 3) return false;
    return m_groups[cluster_id].IsMember(uav_index);
}

utils::u32 MulticastManager::GetGroupSize(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0;
    return m_groups[cluster_id].Size();
}

std::vector<utils::u32> MulticastManager::GetMembers(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return {};
    const auto& g = m_groups[cluster_id];
    return std::vector<utils::u32>(
        g.members.begin(), g.members.end());
}

const crypto::BigInt& MulticastManager::GetMtk(
    utils::u32 cluster_id) const
{
    static crypto::BigInt empty;
    if (cluster_id >= 3) return empty;
    return m_groups[cluster_id].mt_k;
}

utils::u32 MulticastManager::GetVersion(
    utils::u32 cluster_id) const
{
    if (cluster_id >= 3) return 0;
    return m_groups[cluster_id].version;
}

// ===========================================================================
// DoRekey - fire callback with new MT_K
// ===========================================================================
void MulticastManager::DoRekey(
    utils::u32 cluster_id,
    const crypto::MTokenResult& result)
{
    if (m_rekey_cb) {
        m_rekey_cb(cluster_id,
                   result.MT_K,
                   result.version);
    }
}

// ===========================================================================
// RecordEvent
// ===========================================================================
void MulticastManager::RecordEvent(
    MembershipEvent::Type type,
    utils::u32 uav_id,
    utils::u32 uav_index,
    utils::u32 cluster_id)
{
    MembershipEvent ev;
    ev.type       = type;
    ev.uav_id     = uav_id;
    ev.uav_index  = uav_index;
    ev.cluster_id = cluster_id;
    ev.time_s     = Simulator::Now().GetSeconds();
    m_events.push_back(ev);
}

// ===========================================================================
// Print
// ===========================================================================
void MulticastManager::PrintGroupSummary() const {
    std::cout << "\n=== Multicast Group Summary ===\n";
    for (utils::u32 c = 0; c < 3; ++c) {
        const auto& g = m_groups[c];
        std::cout << "  Cluster " << c
            << ": members=" << g.members.size()
            << " version=" << g.version
            << " active=" << g.active
            << "\n    Members: ";
        for (auto m : g.members)
            std::cout << m << " ";
        std::cout << "\n";
    }
    std::cout << "  Joins:  " << m_joins  << "\n";
    std::cout << "  Leaves: " << m_leaves << "\n";
    std::cout << "  Rekeys: " << m_rekeys << "\n";
}

void MulticastManager::PrintEventHistory() const {
    std::cout << "\n=== Membership Events ===\n";
    for (const auto& ev : m_events) {
        std::string type_str;
        switch (ev.type) {
        case MembershipEvent::Type::JOIN:
            type_str = "JOIN"; break;
        case MembershipEvent::Type::LEAVE:
            type_str = "LEAVE"; break;
        case MembershipEvent::Type::HANDOVER:
            type_str = "HANDOVER"; break;
        }
        std::cout << "  t=" << ev.time_s
            << "s " << type_str
            << " UAV" << ev.uav_id
            << " cluster=" << ev.cluster_id
            << "\n";
    }
}

} // namespace apps
} // namespace uav
