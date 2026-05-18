#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-helper.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/config-store-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ipv4-global-routing-helper.h"

#include <fstream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Mob");

int
main (int argc, char *argv[])
{
    CommandLine cmd;
    cmd.Parse (argc, argv);

    // Create 20 UAV nodes
    NodeContainer c;
    c.Create (20);

    // ---------------- WIFI CONFIGURATION ----------------

    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211b);

    wifi.SetRemoteStationManager (
        "ns3::ConstantRateWifiManager",
        "DataMode", StringValue ("DsssRate11Mbps"),
        "ControlMode", StringValue ("DsssRate11Mbps"));

    WifiMacHelper mac;
    mac.SetType ("ns3::AdhocWifiMac");

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay (
        "ns3::ConstantSpeedPropagationDelayModel");

    wifiChannel.AddPropagationLoss (
        "ns3::FriisPropagationLossModel");

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel (wifiChannel.Create ());

    NetDeviceContainer cDevices;
    cDevices = wifi.Install (wifiPhy, mac, c);

    // ---------------- ROUTING ----------------

    AodvHelper aodv;

    InternetStackHelper internet;
    internet.SetRoutingHelper (aodv);
    internet.Install (c);

    // ---------------- IP ADDRESSING ----------------

    Ipv4AddressHelper ipAddrs;
    ipAddrs.SetBase ("192.168.0.0", "255.255.255.0");

    Ipv4InterfaceContainer cInterfaces;
    cInterfaces = ipAddrs.Assign (cDevices);

    // ---------------- 3D MOBILITY MODEL ----------------

    MobilityHelper mobility;

    mobility.SetMobilityModel (
        "ns3::GaussMarkovMobilityModel",

        "Bounds",
        BoxValue (Box (0, 1000, 0, 1000, 0, 300)),

        "TimeStep",
        TimeValue (Seconds (0.5)),

        "Alpha",
        DoubleValue (0.85),

        "MeanVelocity",
        StringValue (
            "ns3::UniformRandomVariable[Min=20|Max=40]"),

        "MeanDirection",
        StringValue (
            "ns3::UniformRandomVariable[Min=0|Max=6.283185307]"),

        "MeanPitch",
        StringValue (
            "ns3::UniformRandomVariable[Min=-0.1|Max=0.1]"),

        "NormalVelocity",
        StringValue (
            "ns3::NormalRandomVariable[Mean=0.0|Variance=1.0|Bound=10.0]"),

        "NormalDirection",
        StringValue (
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),

        "NormalPitch",
        StringValue (
            "ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]"));

    mobility.SetPositionAllocator (
        "ns3::RandomBoxPositionAllocator",

        "X",
        StringValue (
            "ns3::UniformRandomVariable[Min=0|Max=1000]"),

        "Y",
        StringValue (
            "ns3::UniformRandomVariable[Min=0|Max=1000]"),

        "Z",
        StringValue (
            "ns3::UniformRandomVariable[Min=50|Max=300]"));

    mobility.Install (c);

    // ---------------- UDP ECHO APPLICATION ----------------

    UdpEchoServerHelper echoServer (9);

    ApplicationContainer serverApps =
        echoServer.Install (c.Get (0));

    serverApps.Start (Seconds (1.0));
    serverApps.Stop (Seconds (10.0));

    UdpEchoClientHelper echoClient (
        cInterfaces.GetAddress (0), 9);

    echoClient.SetAttribute (
        "MaxPackets",
        UintegerValue (1));

    echoClient.SetAttribute (
        "Interval",
        TimeValue (Seconds (1.0)));

    echoClient.SetAttribute (
        "PacketSize",
        UintegerValue (1024));

    ApplicationContainer clientApps =
        echoClient.Install (c.Get (1));

    clientApps.Start (Seconds (2.0));
    clientApps.Stop (Seconds (10.0));

    // ---------------- TRACING ----------------

    wifiPhy.EnablePcapAll ("Fanet3D");

    AsciiTraceHelper ascii;
    wifiPhy.EnableAsciiAll (
        ascii.CreateFileStream ("Fanet3D.tr"));

    // ---------------- NETANIM ----------------

    AnimationInterface anim ("Fanet3D.xml");

    // ---------------- SIMULATION ----------------

    Simulator::Stop (Seconds (10.0));

    Simulator::Run ();

    Simulator::Destroy ();

    return 0;
}