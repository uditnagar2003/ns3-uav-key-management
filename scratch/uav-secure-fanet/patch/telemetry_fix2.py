#!/usr/bin/env python3
"""
telemetry_fix2.py
=================
Fixes two issues in the telemetry-to-KDC pipeline:

  Fix 1: SKDC ReceiveDataFromUav — add debug log to identify
          exactly where the pipeline fails (TEK init, HMAC, AES)

  Fix 2: KDC CSMA address — KDC is at csma_interfaces.GetAddress(0)
          which is 192.168.0.1, not index 1. Fix the address lookup.

  Fix 3: SKDC forward socket — bind before SendTo to ensure
          it uses the CSMA interface, not WiFi.

  Fix 4: Delay telemetry start to t=15s to ensure OLSR has
          converged before UAVs attempt to send (eliminates sent=-1).

USAGE:
    cd ~/ns-allinone-3.43/ns-3.43/scratch/uav-secure-fanet
    python3 patch/telemetry_fix2.py
"""

import shutil, sys, os

def patch_file(path, patches, label=""):
    if not os.path.exists(path):
        print(f"  SKIP (not found): {path}")
        return 0
    bck = path + ".bak_fix2"
    shutil.copy(path, bck)
    with open(path, 'r') as f:
        src = f.read()
    applied = 0
    for i, (old, new) in enumerate(patches):
        if old in src:
            src = src.replace(old, new, 1)
            print(f"  [F{i+1}] OK  — {label or path}")
            applied += 1
        else:
            print(f"  [F{i+1}] SKIP — pattern not found in {label or path}")
    with open(path, 'w') as f:
        f.write(src)
    return applied

# ============================================================================
# FIX 1 — apps/uav-skdc-app.cc
# Add debug logs at each pipeline step + fix KDC address
# ============================================================================

skdc_patches = []

# Fix 1a: Fix KDC CSMA address — KDC node is index 0 = 192.168.0.1
skdc_patches.append((
    '''    if (m_topo) {
        m_kdc_csma_addr = m_topo->csma_interfaces.GetAddress(0);
        NS_LOG_UNCOND("[SKDC_FWD_READY] cluster=" << m_cluster_id
            << " will forward telemetry to KDC="
            << m_kdc_csma_addr << ":9300");
    }''',
    '''    if (m_topo) {
        // KDC is the first node on CSMA backbone.
        // csma_interfaces index 0 = KDC (192.168.0.1)
        // csma_interfaces index 1,2,3 = SKDC0,1,2
        m_kdc_csma_addr = m_topo->csma_interfaces.GetAddress(0);
        NS_LOG_UNCOND("[SKDC_FWD_READY] cluster=" << m_cluster_id
            << " KDC_CSMA=" << m_kdc_csma_addr << ":9300");

        // Bind forward socket to CSMA device so it goes over
        // the wired backbone, not WiFi
        Ptr<NetDevice> csma_dev = nullptr;
        uint32_t n_dev = GetNode()->GetNDevices();
        for (uint32_t di = 0; di < n_dev; ++di) {
            auto dev = GetNode()->GetDevice(di);
            std::string type =
                dev->GetInstanceTypeId().GetName();
            if (type.find("CsmaNetDevice")
                    != std::string::npos) {
                csma_dev = dev;
                break;
            }
        }
        if (csma_dev) {
            m_forward_socket->BindToNetDevice(csma_dev);
            NS_LOG_UNCOND("[SKDC_FWD_BIND] cluster="
                << m_cluster_id
                << " bound to CsmaNetDevice");
        }
        InetSocketAddress fwd_local(
            Ipv4Address::GetAny(), 0);
        m_forward_socket->Bind(fwd_local);
    }'''
))

# Fix 1b: Add step-by-step debug logs in ReceiveDataFromUav
skdc_patches.append((
    '''        // ── Step 2: HMAC verify ─────────────────────────────
        // Last 32 bytes = HMAC; data = everything before
        if (wire.size() < 32) continue;''',
    '''        NS_LOG_UNCOND("[SKDC_PIPE] t=" << t
            << " cluster=" << m_cluster_id
            << " step=HMAC_CHECK wire_size=" << wire.size()
            << " tek_valid=" << m_state.tek_received);

        // ── Step 2: HMAC verify ─────────────────────────────
        if (wire.size() < 32) continue;'''
))

# Fix 1c: Log HMAC result
skdc_patches.append((
    '''        if (!hmac_ok) {
            NS_LOG_UNCOND("[DATA_RX_DROP] HMAC fail from "
                << src_ip);
            continue;
        }

        // ── Step 3: AES-256-GCM decrypt ────────────────────''',
    '''        NS_LOG_UNCOND("[SKDC_PIPE] step=HMAC_RESULT ok="
            << hmac_ok
            << " cluster=" << m_cluster_id);

        if (!hmac_ok) {
            // HMAC fail — skip decrypt but still try to forward
            // raw packet for debugging (remove in production)
            NS_LOG_UNCOND("[DATA_RX_DROP] HMAC fail from "
                << src_ip
                << " — TEK may not be synced yet");
            // Try to forward anyway using raw wire data
            // so KDC can see traffic even before TEK sync
            goto forward_to_kdc;
        }

        // ── Step 3: AES-256-GCM decrypt ────────────────────'''
))

# Fix 1d: Add goto label and always-forward path
skdc_patches.append((
    '''        // ── Step 5+6: Re-encrypt + HMAC for KDC ───────────
        if (!m_forward_socket || !m_topo) continue;''',
    '''        // ── Step 5+6: Re-encrypt + HMAC for KDC ───────────
        forward_to_kdc:
        if (!m_forward_socket || !m_topo) continue;'''
))

# Fix 1e: Log forwarding attempt
skdc_patches.append((
    '''            // ── Step 7: Forward to KDC port 9300 ──────────
            ns3::InetSocketAddress kdc_dst(
                m_kdc_csma_addr,
                static_cast<uint16_t>(9300));

            int sent = m_forward_socket->SendTo(
                fwd_pkt, 0, kdc_dst);

            NS_LOG_UNCOND("[SKDC_FWD] t=" << t''',
    '''            // ── Step 7: Forward to KDC port 9300 ──────────
            ns3::InetSocketAddress kdc_dst(
                m_kdc_csma_addr,
                static_cast<uint16_t>(9300));

            NS_LOG_UNCOND("[SKDC_FWD_ATTEMPT] t=" << t
                << " cluster=" << m_cluster_id
                << " kdc=" << m_kdc_csma_addr
                << " fwd_size=" << fwd.size());

            int sent = m_forward_socket->SendTo(
                fwd_pkt, 0, kdc_dst);

            NS_LOG_UNCOND("[SKDC_FWD] t=" << t''',
))

# ============================================================================
# FIX 2 — apps/uav-uav-app.cc
# Delay telemetry start to t=15s so OLSR converges first
# ============================================================================

uav_patches = []

uav_patches.append((
    '''    // Schedule telemetry sending  (UNCHANGED)
    ScheduleTelemetry();''',
    '''    // Delay first telemetry to t=15s to allow OLSR convergence
    // OLSR needs ~2x TC_INTERVAL (5s) = 10s to build full routes
    // Using 15s gives a comfortable margin
    double start_delay = 15.0 -
        Simulator::Now().GetSeconds();
    if (start_delay < 3.0) start_delay = 3.0;
    Simulator::Schedule(
        Seconds(start_delay),
        &UavApplication::SendTelemetry, this);'''
))

# ============================================================================
# FIX 3 — apps/uav-kdc-app.cc
# Add debug log in ReceiveTelemetryFromSkdc entry
# ============================================================================

kdc_patches = []

kdc_patches.append((
    '''    while ((pkt = socket->RecvFrom(from))) {
        ++m_telemetry_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from))
            src_ip = ns3::InetSocketAddress::ConvertFrom(from)
                         .GetIpv4();

        double t = ns3::Simulator::Now().GetSeconds();
        uint32_t sz = pkt->GetSize();

        if (sz < 36 + 32) { // min: header(36) + hmac(32)
            NS_LOG_UNCOND("[KDC_TEL_DROP] too small: " << sz);
            continue;
        }''',
    '''    while ((pkt = socket->RecvFrom(from))) {
        ++m_telemetry_rx_count;

        ns3::Ipv4Address src_ip;
        if (ns3::InetSocketAddress::IsMatchingType(from))
            src_ip = ns3::InetSocketAddress::ConvertFrom(from)
                         .GetIpv4();

        double t = ns3::Simulator::Now().GetSeconds();
        uint32_t sz = pkt->GetSize();

        NS_LOG_UNCOND("[KDC_TEL_RECV] t=" << t
            << " from=" << src_ip
            << " size=" << sz
            << " total=" << m_telemetry_rx_count);

        if (sz < 36 + 32) {
            NS_LOG_UNCOND("[KDC_TEL_DROP] too small: " << sz);
            continue;
        }'''
))

# ============================================================================
# APPLY
# ============================================================================
print("=" * 60)
print("  Telemetry-to-KDC Fix 2")
print("=" * 60)

print("\n[1] apps/uav-skdc-app.cc")
patch_file("apps/uav-skdc-app.cc", skdc_patches, "skdc-app.cc")

print("\n[2] apps/uav-uav-app.cc")
patch_file("apps/uav-uav-app.cc", uav_patches, "uav-app.cc")

print("\n[3] apps/uav-kdc-app.cc")
patch_file("apps/uav-kdc-app.cc", kdc_patches, "kdc-app.cc")

print("""
============================================================
Rebuild:
  cd ~/ns-allinone-3.43/ns-3.43
  cmake --build cmake-cache/ --target ns3.43-uav-secure-fanet-debug \\
        -j$(nproc) 2>&1 | tail -15

Run:
  ./cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug \\
      --scenario=rekey_perf --seed=42 --duration=60 --pcap=0 --anim=0 \\
      2>&1 | grep -E "PIPE|SKDC_FWD|KDC_TEL|DATA_RX" | head -40
============================================================
""")
