/**
 * metrics/uav-pcap-export.h
 * Module 60 — PCAP Export Manager
 *
 * Uses existing TopologyBuilder::EnablePcap() API:
 *   EnablePcap(prefix, topo)
 *     → prefix-wifi-N-M.pcap  (all WiFi devices)
 *     → prefix-csma-N-M.pcap  (all CSMA devices)
 *
 * Per project spec outputs:
 *   pcap/uav-wifi-N-M.pcap   — UAV WiFi traces
 *   pcap/uav-csma-N-M.pcap   — KDC/SKDC CSMA traces
 *
 * PCAP files are generated during Simulator::Run()
 * automatically once EnablePcap() is called before run.
 */

#ifndef UAV_PCAP_EXPORT_H
#define UAV_PCAP_EXPORT_H

#include "routing/uav-topology.h"
#include "utils/uav-types.h"
#include "utils/uav-logger.h"
#include "utils/uav-log-channels.h"

#include <string>
#include <vector>

namespace uav {
namespace metrics {

class PcapExportManager {
public:
    /**
     * Construction
     * @param topo       Topology result
     * @param pcap_dir   Directory for PCAP files
     * @param builder    TopologyBuilder (owns EnablePcap)
     */
    PcapExportManager(
        const routing::TopologyResult* topo,
        const std::string&             pcap_dir,
        routing::TopologyBuilder*      builder);

    /**
     * Enable — call BEFORE Simulator::Run().
     * Registers PCAP hooks on all devices.
     * Files written automatically during simulation.
     */
    void Enable();

    /**
     * IsEnabled — whether PCAP was activated.
     */
    bool IsEnabled() const { return m_enabled; }

    /**
     * GetExpectedFiles — list of PCAP files that
     * will be generated (for verification).
     */
    std::vector<std::string> GetExpectedFiles() const;

    /**
     * VerifyFiles — check which PCAP files exist
     * after simulation. Returns count of found files.
     */
    uint32_t VerifyFiles() const;

    /**
     * PrintSummary — print PCAP file list and sizes.
     */
    void PrintSummary() const;

    std::string GetPcapDir()    const { return m_pcap_dir; }
    std::string GetPrefix()     const { return m_prefix;   }

private:
    const routing::TopologyResult* m_topo;
    std::string                    m_pcap_dir;
    routing::TopologyBuilder*      m_builder;
    bool                           m_enabled = false;
    std::string                    m_prefix;
};

} // namespace metrics
} // namespace uav

#endif // UAV_PCAP_EXPORT_H
