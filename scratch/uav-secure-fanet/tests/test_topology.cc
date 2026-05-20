/**
 * tests/test_topology.cc
 * Unit test for Phase 4 Module 24: Network Topology Builder
 *
 * This test runs inside NS-3 and verifies:
 *   - Correct node counts
 *   - CSMA backbone connectivity
 *   - WiFi adhoc installation
 *   - IP address assignment
 *   - Initial node positions
 *
 * BUILD via waf:
 *   cd ~/ns-allinone-3.43/ns-3.43
 *   ./ns3 build
 *
 * RUN:
 *   ./ns3 run scratch/uav-secure-fanet/tests/test_topology
 *
 * STANDALONE COMPILE (for validation without NS-3):
 *   Not applicable — requires NS-3 runtime.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"

// Project headers
#include "routing/uav-topology.h"
#include "utils/uav-logger.h"
#include "crypto/uav-openssl-ctx.h"

#include <iostream>
#include <cstdlib>

using namespace ns3;
using namespace uav;
using namespace uav::routing;

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expr, msg) \
    do { \
        if (!(expr)) { \
            std::cerr << "  FAIL: " << msg << "\n"; \
            ++g_fail; \
        } else { \
            std::cout << "  PASS: " << msg << "\n"; \
            ++g_pass; \
        } \
    } while(0)

} // namespace

int main(int argc, char* argv[]) {
    CommandLine cmd;
    cmd.Parse(argc, argv);

    std::cout << "====================================================\n";
    std::cout << "Phase 4 Module 24 — Network Topology Builder\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    // Suppress NS-3 logging for cleaner output
    LogComponentDisableAll(LOG_LEVEL_ALL);

    OpenSSLInit::Bootstrap();

    // -----------------------------------------------------------------------
    // Build topology
    // -----------------------------------------------------------------------
    TopologyConfig cfg;
    TopologyBuilder builder(cfg);
    TopologyResult topo = builder.Build();

    std::cout << "[ RUN  ] node_counts\n";
    {
        CHECK(topo.all_nodes.GetN()    == 23, "Total nodes = 23");
        CHECK(topo.ground_nodes.GetN() == 4,  "Ground nodes = 4");
        CHECK(topo.kdc_node.GetN()     == 1,  "KDC nodes = 1");
        CHECK(topo.skdc_nodes.GetN()   == 3,  "SKDC nodes = 3");
        CHECK(topo.uav_nodes.GetN()    == 18, "UAV nodes = 18");
        CHECK(topo.jammer_node.GetN()  == 1,  "Jammer nodes = 1");
        CHECK(topo.wifi_nodes.GetN()   == 19, "WiFi nodes = 19");

        for (uint32_t c = 0; c < NUM_CLUSTERS; ++c) {
            CHECK(topo.cluster_nodes[c].GetN() == 6,
                "Cluster " + std::to_string(c) + " = 6 UAVs");
        }
    }
    std::cout << "[ " << (g_fail==0?"PASS":"FAIL")
              << " ] node_counts\n\n";

    int prev_fail = g_fail;
    std::cout << "[ RUN  ] node_ids\n";
    {
        CHECK(TopologyResult::KDC_NODE_ID    == 0,  "KDC=0");
        CHECK(TopologyResult::SKDC0_NODE_ID  == 1,  "SKDC0=1");
        CHECK(TopologyResult::SKDC1_NODE_ID  == 2,  "SKDC1=2");
        CHECK(TopologyResult::SKDC2_NODE_ID  == 3,  "SKDC2=3");
        CHECK(TopologyResult::UAV0_NODE_ID   == 4,  "UAV0=4");
        CHECK(TopologyResult::JAMMER_NODE_ID == 22, "JAMMER=22");
        CHECK(TopologyResult::UavNodeId(0)   == 4,  "UavNodeId(0)=4");
        CHECK(TopologyResult::UavNodeId(17)  == 21, "UavNodeId(17)=21");
        CHECK(TopologyResult::SkdcNodeId(0)  == 1,  "SkdcNodeId(0)=1");
        CHECK(TopologyResult::SkdcNodeId(2)  == 3,  "SkdcNodeId(2)=3");
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] node_ids\n\n";

    prev_fail = g_fail;
    std::cout << "[ RUN  ] devices\n";
    {
        CHECK(topo.csma_devices.GetN()  == 4,
            "CSMA devices = 4");
        CHECK(topo.wifi_devices.GetN()  == 19,
            "WiFi devices = 19");
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] devices\n\n";

    prev_fail = g_fail;
    std::cout << "[ RUN  ] ip_addresses\n";
    {
        CHECK(topo.wifi_interfaces.GetN()  == 19,
            "WiFi interfaces = 19");
        CHECK(topo.csma_interfaces.GetN()  == 4,
            "CSMA interfaces = 4");

        // UAV0 should be in 10.1.1.x subnet
        auto uav0_addr = topo.GetUavWifiAddr(0);
        std::ostringstream oss;
        uav0_addr.Print(oss);
        std::string addr_str = oss.str();
        CHECK(addr_str.substr(0, 7) == "10.1.1.",
            "UAV0 in 10.1.1.x: " + addr_str);

        // SKDC0 should be in 192.168.0.x subnet
        auto skdc0_addr = topo.GetSkdcCsmaAddr(0);
        std::ostringstream oss2;
        skdc0_addr.Print(oss2);
        std::string skdc_str = oss2.str();
        CHECK(skdc_str.substr(0, 11) == "192.168.0.",
            "SKDC0 in 192.168.0.x: " + skdc_str);

        std::cout << "  UAV0  WiFi addr: " << addr_str  << "\n";
        std::cout << "  SKDC0 CSMA addr: " << skdc_str << "\n";
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] ip_addresses\n\n";

    prev_fail = g_fail;
    std::cout << "[ RUN  ] initial_positions\n";
    {
        // Check KDC position
        Ptr<MobilityModel> kdc_mob =
            topo.kdc_node.Get(0)->GetObject<MobilityModel>();
        CHECK(kdc_mob != nullptr, "KDC has mobility model");
        if (kdc_mob) {
            Vector pos = kdc_mob->GetPosition();
            CHECK(pos.x == 750.0 && pos.y == 750.0,
                "KDC at (750,750)");
            std::cout << "  KDC pos: ("
                << pos.x << "," << pos.y << "," << pos.z
                << ")\n";
        }

        // Check UAVs have positions
        for (uint32_t i = 0; i < 18; ++i) {
            Ptr<MobilityModel> mob =
                topo.uav_nodes.Get(i)->GetObject<MobilityModel>();
            CHECK(mob != nullptr,
                "UAV " + std::to_string(i) + " has mobility");
        }

        // Check altitude range
        for (uint32_t i = 0; i < 18; ++i) {
            Ptr<MobilityModel> mob =
                topo.uav_nodes.Get(i)->GetObject<MobilityModel>();
            if (mob) {
                Vector pos = mob->GetPosition();
                CHECK(pos.z >= 50.0 && pos.z <= 200.0,
                    "UAV " + std::to_string(i)
                    + " altitude in [50,200]");
            }
        }
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] initial_positions\n\n";

    prev_fail = g_fail;
    std::cout << "[ RUN  ] cluster_separation\n";
    {
        // Cluster centers should be well separated
        double cx[3] = {250.0, 750.0, 1250.0};
        double cy[3] = {750.0, 250.0, 750.0};

        for (uint32_t c = 0; c < 3; ++c) {
            Ptr<MobilityModel> mob =
                topo.cluster_nodes[c].Get(0)
                    ->GetObject<MobilityModel>();
            if (mob) {
                Vector pos = mob->GetPosition();
                double dx = pos.x - cx[c];
                double dy = pos.y - cy[c];
                double dist = std::sqrt(dx*dx + dy*dy);
                CHECK(dist <= 150.0,
                    "Cluster " + std::to_string(c)
                    + " UAV0 within 150m of center");
                std::cout << "  Cluster " << c
                    << " UAV0: (" << pos.x << ","
                    << pos.y << ") dist="
                    << dist << "m\n";
            }
        }
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] cluster_separation\n\n";

    prev_fail = g_fail;
    std::cout << "[ RUN  ] node_ptrs\n";
    {
        CHECK(topo.GetKdcNode()     != nullptr, "GetKdcNode()");
        CHECK(topo.GetSkdcNode(0)   != nullptr, "GetSkdcNode(0)");
        CHECK(topo.GetSkdcNode(2)   != nullptr, "GetSkdcNode(2)");
        CHECK(topo.GetUavNode(0)    != nullptr, "GetUavNode(0)");
        CHECK(topo.GetUavNode(17)   != nullptr, "GetUavNode(17)");
    }
    std::cout << "[ " << (g_fail==prev_fail?"PASS":"FAIL")
              << " ] node_ptrs\n\n";

    // -----------------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------------
    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    Simulator::Destroy();
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
