/**
 * visualization/uav-pyviz.h
 * Module 49 — PyViz Integration
 *
 * PyViz STATUS on this system:
 *   - NS-3 Python bindings: NOT built
 *   - PyViz Python module:  NOT available
 *   - PyViz C++ source:     EXISTS (src/visualizer/model/pyviz.h)
 *
 * PyViz requires NS-3 Python bindings to be built with:
 *   cmake -DNS3_ENABLE_PYTHON_BINDINGS=ON ...
 *
 * This module provides:
 *   1. Runtime availability check
 *   2. Graceful fallback to NetAnim when unavailable
 *   3. PyViz enable/disable via CommandLine flag --pyviz
 *   4. Instructions to enable PyViz when needed
 *
 * HOW TO ENABLE PYVIZ (when Python bindings are built):
 *   cd ~/ns-allinone-3.43/ns-3.43
 *   ./ns3 run "uav-secure-fanet --pyviz=true"
 *   OR
 *   ./ns3 run uav-secure-fanet --vis
 */

#ifndef UAV_PYVIZ_H
#define UAV_PYVIZ_H

#include "visualization/uav-netanim.h"
#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include "ns3/core-module.h"

#include <string>

namespace uav {
namespace visualization {

// ===========================================================================
// PyVizAvailability — runtime check result
// ===========================================================================
enum class PyVizAvailability {
    AVAILABLE,          ///< Python bindings built, PyViz usable
    NO_PYTHON_BINDINGS, ///< NS-3 Python bindings not built
    DISABLED_BY_USER,   ///< User passed --pyviz=false
    FALLBACK_NETANIM    ///< Using NetAnim instead
};

static inline const char* PyVizAvailabilityStr(
    PyVizAvailability a)
{
    switch (a) {
    case PyVizAvailability::AVAILABLE:
        return "AVAILABLE";
    case PyVizAvailability::NO_PYTHON_BINDINGS:
        return "NO_PYTHON_BINDINGS";
    case PyVizAvailability::DISABLED_BY_USER:
        return "DISABLED_BY_USER";
    case PyVizAvailability::FALLBACK_NETANIM:
        return "FALLBACK_NETANIM";
    default:
        return "UNKNOWN";
    }
}

// ===========================================================================
// PyVizManager — Module 49
// ===========================================================================
class PyVizManager {
public:
    /**
     * Construction
     * @param topo       Topology result
     * @param netanim    Existing NetAnimManager (fallback)
     * @param enable     Whether to attempt PyViz (default false)
     */
    PyVizManager(
        const routing::TopologyResult* topo,
        NetAnimManager*                netanim,
        bool                           enable = false);

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * Initialize — checks PyViz availability and configures
     * accordingly. Falls back to NetAnim if unavailable.
     */
    void Initialize();

    /**
     * SetEnabled — enable/disable PyViz attempt.
     * Can be called before Initialize().
     */
    void SetEnabled(bool enabled) { m_pyviz_requested = enabled; }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    PyVizAvailability GetAvailability() const {
        return m_availability;
    }

    bool IsPyVizActive()   const {
        return m_availability == PyVizAvailability::AVAILABLE;
    }
    bool IsNetAnimActive() const {
        return m_netanim && m_netanim->IsEnabled();
    }

    /// Print status summary
    void PrintStatus() const;

    /// Print instructions to enable PyViz
    static void PrintEnableInstructions();

private:
    const routing::TopologyResult* m_topo;
    NetAnimManager*                m_netanim;
    bool                           m_pyviz_requested;
    PyVizAvailability              m_availability;

    /// Check if PyViz is actually usable on this system
    static bool CheckPyVizAvailable();
};

} // namespace visualization
} // namespace uav

#endif // UAV_PYVIZ_H
