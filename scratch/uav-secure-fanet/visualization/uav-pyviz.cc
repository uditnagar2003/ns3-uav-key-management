/**
 * visualization/uav-pyviz.cc
 * Module 49 — PyViz Integration
 */

#include "visualization/uav-pyviz.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <cstdlib>

NS_LOG_COMPONENT_DEFINE("UavPyViz");

using namespace ns3;

namespace uav {
namespace visualization {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
PyVizManager::PyVizManager(
    const routing::TopologyResult* topo,
    NetAnimManager*                netanim,
    bool                           enable)
    : m_topo(topo)
    , m_netanim(netanim)
    , m_pyviz_requested(enable)
    , m_availability(PyVizAvailability::FALLBACK_NETANIM)
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PyVizManager: constructed"
        " requested=" << enable);
}

// ---------------------------------------------------------------------------
// CheckPyVizAvailable — runtime detection
// ---------------------------------------------------------------------------
bool PyVizManager::CheckPyVizAvailable()
{
    // Check 1: try importing ns.visualizer Python module
    int ret = std::system(
        "python3 -c 'import ns.visualizer' "
        ">/dev/null 2>&1");
    if (ret != 0) {
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "PyViz: ns.visualizer Python module not available");
        return false;
    }

    // Check 2: NS-3 Python bindings exist
    ret = std::system(
        "python3 -c 'import ns.core' "
        ">/dev/null 2>&1");
    if (ret != 0) {
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "PyViz: ns.core Python bindings not available");
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
void PyVizManager::Initialize()
{
    if (!m_pyviz_requested) {
        m_availability = PyVizAvailability::DISABLED_BY_USER;
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "PyVizManager: PyViz not requested"
            " — using NetAnim");

        // Ensure NetAnim is active as fallback
        if (m_netanim && !m_netanim->IsEnabled()) {
            m_netanim->SetEnabled(true);
        }
        return;
    }

    // Check runtime availability
    bool available = CheckPyVizAvailable();

    if (available) {
        m_availability = PyVizAvailability::AVAILABLE;
        UAV_LOG_INFO(uav::log::channels::SYSTEM,
            "PyVizManager: PyViz AVAILABLE"
            " — live visualization active");
        std::cout << "[PyViz] Live visualization ACTIVE\n";
        std::cout << "[PyViz] Run with: ./ns3 run "
                     "uav-secure-fanet --vis\n";
    } else {
        m_availability = PyVizAvailability::NO_PYTHON_BINDINGS;
        UAV_LOG_WARN(uav::log::channels::SYSTEM,
            "PyVizManager: PyViz NOT available"
            " — falling back to NetAnim");

        std::cout << "[PyViz] NOT available on this system\n";
        std::cout << "[PyViz] Falling back to NetAnim\n";
        PrintEnableInstructions();

        // Activate NetAnim as fallback
        if (m_netanim) {
            m_netanim->SetEnabled(true);
            UAV_LOG_INFO(uav::log::channels::SYSTEM,
                "PyVizManager: NetAnim fallback activated");
        }
    }
}

// ---------------------------------------------------------------------------
// PrintStatus
// ---------------------------------------------------------------------------
void PyVizManager::PrintStatus() const
{
    std::cout << "\n=== PyViz Status ===\n";
    std::cout << "  Requested:    "
              << (m_pyviz_requested ? "YES" : "NO") << "\n";
    std::cout << "  Availability: "
              << PyVizAvailabilityStr(m_availability) << "\n";
    std::cout << "  PyViz active: "
              << (IsPyVizActive() ? "YES" : "NO") << "\n";
    std::cout << "  NetAnim active: "
              << (IsNetAnimActive() ? "YES" : "NO") << "\n";
}

// ---------------------------------------------------------------------------
// PrintEnableInstructions
// ---------------------------------------------------------------------------
void PyVizManager::PrintEnableInstructions()
{
    std::cout << "\n[PyViz] To enable PyViz visualization:\n";
    std::cout << "  1. Build NS-3 with Python bindings:\n";
    std::cout << "     cd ~/ns-allinone-3.43/ns-3.43\n";
    std::cout << "     cmake -B cmake-cache "
                 "-DNS3_ENABLE_PYTHON_BINDINGS=ON\n";
    std::cout << "     cmake --build cmake-cache -j$(nproc)\n";
    std::cout << "  2. Install Python dependencies:\n";
    std::cout << "     pip3 install PyGObject pygraphviz\n";
    std::cout << "  3. Run with --vis flag:\n";
    std::cout << "     ./ns3 run uav-secure-fanet --vis\n";
    std::cout << "  NOTE: NetAnim XML output is always "
                 "generated as fallback.\n\n";
}

} // namespace visualization
} // namespace uav
