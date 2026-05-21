/**
 * apps/uav-multicast-manager.h
 * Module 38 - Multicast Manager
 *
 * Manages multicast group membership for UAV clusters.
 * Per project spec:
 *   - UAV multicast groups mapped to clusters
 *   - Membership tracked per SKDC
 *   - Join/Leave updates trigger CRT rekeying
 *   - Selective decryptability enforced via MT_K
 *
 * This manager coordinates between:
 *   - SKDCApplication (broadcasts MT_K)
 *   - UavApplication  (slave decryption)
 *   - CrtManager      (JoKeyUpdate/LeKeyUpdate)
 */

#ifndef UAV_MULTICAST_MANAGER_H
#define UAV_MULTICAST_MANAGER_H

#include "apps/uav-skdc-app.h"
#include "apps/uav-uav-app.h"
#include "crypto/uav-crt-manager.h"
#include "crypto/uav-crypto-params.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-error.h"

#include <array>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <string>

namespace uav {
namespace apps {

// ===========================================================================
// MulticastGroupInfo - per-cluster multicast group
// ===========================================================================
struct MulticastGroupInfo {
    utils::u32                      cluster_id  = 0;
    std::unordered_set<utils::u32>  members;      // UAV indices
    utils::u32                      version     = 1;
    crypto::BigInt                  mt_k;
    crypto::BigInt                  n_group;
    crypto::BigInt                  e_mk;
    bool                            active      = false;

    bool IsMember(utils::u32 uav_index) const {
        return members.count(uav_index) > 0;
    }
    utils::u32 Size() const {
        return static_cast<utils::u32>(members.size());
    }
};

// ===========================================================================
// MembershipEvent - join/leave event record
// ===========================================================================
struct MembershipEvent {
    enum class Type { JOIN, LEAVE, HANDOVER };
    Type        type       = Type::JOIN;
    utils::u32  uav_id     = 0;
    utils::u32  uav_index  = 0;
    utils::u32  cluster_id = 0;
    double      time_s     = 0.0;
};

// ===========================================================================
// MulticastManager - Module 38
// ===========================================================================
class MulticastManager {
public:
    using RekeyCallback =
        std::function<void(utils::u32 cluster,
                           const crypto::BigInt& mt_k,
                           utils::u32 version)>;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    MulticastManager(
        const routing::TopologyResult*  topo,
        const crypto::CryptoParamsFile* params);

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize all 3 cluster groups from crypto params
    void Initialize();

    // -----------------------------------------------------------------------
    // Membership management
    // -----------------------------------------------------------------------

    /// Add UAV to multicast group (JoKeyUpdate)
    bool AddMember(utils::u32 cluster_id,
                   utils::u32 uav_index,
                   utils::u32 uav_id);

    /// Remove UAV from multicast group (LeKeyUpdate)
    bool RemoveMember(utils::u32 cluster_id,
                      utils::u32 uav_index,
                      utils::u32 uav_id);

    /// Move UAV between clusters (handover)
    bool HandoverMember(utils::u32 old_cluster,
                        utils::u32 new_cluster,
                        utils::u32 uav_index,
                        utils::u32 uav_id);

    // -----------------------------------------------------------------------
    // Group queries
    // -----------------------------------------------------------------------

    const MulticastGroupInfo& GetGroup(
        utils::u32 cluster_id) const;

    bool IsMember(utils::u32 cluster_id,
                  utils::u32 uav_index) const;

    utils::u32 GetGroupSize(
        utils::u32 cluster_id) const;

    std::vector<utils::u32> GetMembers(
        utils::u32 cluster_id) const;

    // -----------------------------------------------------------------------
    // MT_K access
    // -----------------------------------------------------------------------
    const crypto::BigInt& GetMtk(
        utils::u32 cluster_id) const;

    utils::u32 GetVersion(
        utils::u32 cluster_id) const;

    // -----------------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------------
    void SetRekeyCallback(RekeyCallback cb) {
        m_rekey_cb = cb;
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    utils::u64 GetTotalJoins()  const { return m_joins;  }
    utils::u64 GetTotalLeaves() const { return m_leaves; }
    utils::u64 GetTotalRekeys() const { return m_rekeys; }

    void PrintGroupSummary() const;
    void PrintEventHistory() const;

private:
    const routing::TopologyResult*  m_topo;
    const crypto::CryptoParamsFile* m_params;

    std::array<MulticastGroupInfo, 3>  m_groups;
    std::array<crypto::MKeyGenResult, 3> m_mkg;

    std::vector<MembershipEvent>  m_events;
    RekeyCallback                 m_rekey_cb;

    utils::u64 m_joins  = 0;
    utils::u64 m_leaves = 0;
    utils::u64 m_rekeys = 0;

    void DoRekey(utils::u32 cluster_id,
                 const crypto::MTokenResult& result);

    void RecordEvent(MembershipEvent::Type type,
                     utils::u32 uav_id,
                     utils::u32 uav_index,
                     utils::u32 cluster_id);
};

} // namespace apps
} // namespace uav

#endif // UAV_MULTICAST_MANAGER_H
