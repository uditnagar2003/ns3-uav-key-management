/**
 * metrics/uav-pcap-export.cc
 * Module 60 — PCAP Export Manager
 */

#include "metrics/uav-pcap-export.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

NS_LOG_COMPONENT_DEFINE("UavPcapExport");

using namespace ns3;

namespace uav {
namespace metrics {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
PcapExportManager::PcapExportManager(
    const routing::TopologyResult* topo,
    const std::string&             pcap_dir,
    routing::TopologyBuilder*      builder)
    : m_topo(topo)
    , m_pcap_dir(pcap_dir)
    , m_builder(builder)
    , m_prefix(pcap_dir + "/uav")
{
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PcapExportManager: constructed"
        " dir=" << pcap_dir);
}

// ---------------------------------------------------------------------------
// Enable
// ---------------------------------------------------------------------------
void PcapExportManager::Enable()
{
    if (!m_builder) {
        UAV_LOG_WARN(uav::log::channels::SYSTEM,
            "PcapExportManager: no builder");
        return;
    }

    // Ensure pcap directory exists
    mkdir(m_pcap_dir.c_str(), 0755);

    // Enable PCAP on all devices via TopologyBuilder
    m_builder->EnablePcap(m_prefix, *m_topo);
    m_enabled = true;

    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PcapExportManager: PCAP enabled"
        " prefix=" << m_prefix
        << " wifi_nodes="
        << m_topo->wifi_nodes.GetN()
        << " csma_nodes="
        << m_topo->ground_nodes.GetN());

    std::cout << "[PCAP] Enabled prefix: "
              << m_prefix << "\n";
    std::cout << "[PCAP] WiFi nodes: "
              << m_topo->wifi_nodes.GetN() << "\n";
    std::cout << "[PCAP] CSMA nodes: "
              << m_topo->ground_nodes.GetN() << "\n";
}

// ---------------------------------------------------------------------------
// GetExpectedFiles
// ---------------------------------------------------------------------------
std::vector<std::string>
PcapExportManager::GetExpectedFiles() const
{
    std::vector<std::string> files;

    // WiFi PCAP: one per wifi node per device
    // wifi_nodes = 18 UAVs + 1 jammer = 19 nodes
    // Each node has 1 wifi device → 19 files
    for (uint32_t i = 0;
         i < m_topo->wifi_nodes.GetN(); ++i)
    {
        std::ostringstream oss;
        oss << m_prefix << "-wifi-"
            << m_topo->wifi_nodes.Get(i)->GetId()
            << "-0.pcap";
        files.push_back(oss.str());
    }

    // CSMA PCAP: KDC + 3 SKDCs = 4 nodes
    for (uint32_t i = 0;
         i < m_topo->ground_nodes.GetN(); ++i)
    {
        std::ostringstream oss;
        oss << m_prefix << "-csma-"
            << m_topo->ground_nodes.Get(i)->GetId()
            << "-0.pcap";
        files.push_back(oss.str());
    }

    return files;
}

// ---------------------------------------------------------------------------
// VerifyFiles
// ---------------------------------------------------------------------------
uint32_t PcapExportManager::VerifyFiles() const
{
    auto files = GetExpectedFiles();
    uint32_t found = 0;
    for (const auto& f : files) {
        std::ifstream ifs(f);
        if (ifs.good()) ++found;
    }
    UAV_LOG_INFO(uav::log::channels::SYSTEM,
        "PcapExportManager: verified "
        << found << "/" << files.size()
        << " PCAP files");
    return found;
}

// ---------------------------------------------------------------------------
// PrintSummary
// ---------------------------------------------------------------------------
void PcapExportManager::PrintSummary() const
{
    std::cout << "\n=== PCAP Export Manager ===\n";
    std::cout << "  Enabled:  " << m_enabled  << "\n";
    std::cout << "  Prefix:   " << m_prefix   << "\n";
    std::cout << "  PCAP dir: " << m_pcap_dir << "\n";

    auto files = GetExpectedFiles();
    std::cout << "  Expected files: "
              << files.size() << "\n";

    uint32_t found = 0;
    for (const auto& f : files) {
        struct stat st;
        if (stat(f.c_str(), &st) == 0) {
            ++found;
            std::cout << "  [OK] "
                << f.substr(m_pcap_dir.size() + 1)
                << " (" << st.st_size << "B)\n";
        }
    }
    std::cout << "  Found: " << found
              << "/" << files.size() << "\n";
}

} // namespace metrics
} // namespace uav
