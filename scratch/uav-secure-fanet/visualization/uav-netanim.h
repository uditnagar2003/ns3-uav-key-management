/**
 * visualization/uav-netanim.h
 * Module 48 — NetAnim Integration
 *
 * Node color scheme (per project spec):
 *   KDC             = red     (255, 0,   0  )
 *   SKDC            = orange  (255, 165, 0  )
 *   UAV normal      = green   (0,   255, 0  )
 *   UAV compromised = black   (0,   0,   0  )
 *   Jammer          = purple  (128, 0,   128)
 *
 * NetAnim update interval: 100 ms (per project spec)
 *
 * Output file: output/uav-fanet-anim.xml
 */

#ifndef UAV_NETANIM_H
#define UAV_NETANIM_H

#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"
#include "ns3/netanim-module.h"

#include <string>
#include <vector>
#include <array>

namespace uav {
namespace visualization {

// ===========================================================================
// Node color constants (per project spec)
// ===========================================================================
struct NodeColor {
    uint8_t r, g, b;
};

constexpr NodeColor COLOR_KDC         = {255,   0,   0}; // red
constexpr NodeColor COLOR_SKDC        = {255, 165,   0}; // orange
constexpr NodeColor COLOR_UAV         = {  0, 255,   0}; // green
constexpr NodeColor COLOR_COMPROMISED = {  0,   0,   0}; // black
constexpr NodeColor COLOR_JAMMER      = {128,   0, 128}; // purple

// ===========================================================================
// NetAnimManager — Module 48
// ===========================================================================
class NetAnimManager {
public:
    /**
     * Construction — does NOT start animation yet.
     * Call Initialize() after topology is built.
     *
     * @param topo       Topology built by TopologyBuilder
     * @param output_dir Directory for output files (e.g. "output")
     */
    NetAnimManager(
        const routing::TopologyResult* topo,
        const std::string& output_dir = "output");

    ~NetAnimManager() = default;

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * Initialize — creates AnimationInterface, sets node colors,
     * descriptions, sizes, and enables packet metadata.
     * Call once after topology is built, before Simulator::Run().
     */
    void Initialize();

    /**
     * SetEnabled — if false, Initialize() is a no-op.
     * Allows disabling NetAnim from config without code changes.
     */
    void SetEnabled(bool enabled) { m_enabled = enabled; }
    bool IsEnabled() const        { return m_enabled; }

    // -----------------------------------------------------------------------
    // Runtime node state updates
    // Call these during simulation to update visual state.
    // -----------------------------------------------------------------------

    /// Mark UAV as compromised (turn black)
    void MarkCompromised(utils::u32 uav_id);

    /// Restore UAV to normal (turn green)
    void MarkNormal(utils::u32 uav_id);

    /// Mark UAV as in handover (turn yellow)
    void MarkHandover(utils::u32 uav_id);

    /// Update UAV description (e.g. show cluster membership)
    void UpdateUavDescription(utils::u32 uav_id,
                               const std::string& descr);

    /// Update SKDC description (e.g. show member count)
    void UpdateSkdcDescription(utils::u32 skdc_id,
                                const std::string& descr);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    ns3::AnimationInterface* GetAnim() { return m_anim.get(); }

private:
    const routing::TopologyResult* m_topo;
    std::string                    m_output_dir;
    bool                           m_enabled = true;

    // Use unique_ptr so AnimationInterface is created on demand
    std::unique_ptr<ns3::AnimationInterface> m_anim;

    void ApplyInitialColors();
    void ApplyInitialDescriptions();
    void ApplyInitialSizes();
};

} // namespace visualization
} // namespace uav

#endif // UAV_NETANIM_H
