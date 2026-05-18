#include "ns3/core-module.h"
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UavSecureFanet");

int main(int argc, char *argv[])
{
    std::cout << "====================================================\n";
    std::cout << " UAV Secure FANET Framework\n";
    std::cout << " Phase 1 Modules 1+2: BUILD VERIFIED\n";
    std::cout << "====================================================\n";

    Simulator::Stop(Seconds(1.0));
    Simulator::Run();
    Simulator::Destroy();

    std::cout << "Simulation completed successfully.\n";
    return 0;
}
