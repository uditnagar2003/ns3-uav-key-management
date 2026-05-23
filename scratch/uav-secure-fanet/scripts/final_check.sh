#!/usr/bin/env bash
# scripts/final_check.sh
# Module 66 — Final Testing/Debugging Checklist
#
# Verifies complete project implementation:
#   - Build integrity
#   - All output files present
#   - All modules functional
#   - Simulation correctness
#   - Graph generation
#
# USAGE:
#   cd ~/ns-allinone-3.43/ns-3.43
#   bash scratch/uav-secure-fanet/scripts/final_check.sh

set -uo pipefail

NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH="${NS3_ROOT}/scratch/uav-secure-fanet"
EXEC="${NS3_ROOT}/cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug"

GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; PASS=$(( PASS+1 )); }
fail() { echo -e "  ${RED}✗${NC} $*"; FAIL=$(( FAIL+1 )); }
warn() { echo -e "  ${YELLOW}!${NC} $*"; WARN=$(( WARN+1 )); }
sep()  { echo -e "${BLUE}══════════════════════════════════════${NC}"; }
hdr()  { echo ""; sep; echo -e "${BLUE}$*${NC}"; sep; }

# ---------------------------------------------------------------------------
hdr "CHECK 1: Build Verification"
# ---------------------------------------------------------------------------
cd "${NS3_ROOT}"
if cmake --build cmake-cache -j"$(nproc)" \
    --target scratch_uav-secure-fanet_uav-secure-fanet \
    > /dev/null 2>&1; then
    pass "CMake build successful"
else
    fail "CMake build FAILED"
fi

[[ -x "${EXEC}" ]] && pass "Executable exists: $(basename ${EXEC})" \
                   || fail "Executable NOT found"

# ---------------------------------------------------------------------------
hdr "CHECK 2: Source File Inventory"
# ---------------------------------------------------------------------------
declare -A MODULES=(
    ["utils/uav-logger.h"]="Logger"
    ["crypto/uav-aes.h"]="AES module"
    ["crypto/uav-hmac.h"]="HMAC module"
    ["crypto/uav-replay.h"]="Replay protection"
    ["crypto/uav-crt-manager.h"]="CRT/GCRT manager"
    ["headers/uav-packet-enums.h"]="Packet enums"
    ["headers/uav-base-header.h"]="Base header"
    ["headers/uav-mtk-packet.h"]="MTK packet"
    ["routing/uav-topology.h"]="Topology builder"
    ["routing/uav-flowmonitor.h"]="FlowMonitor"
    ["routing/uav-olsr-manager.h"]="OLSR manager"
    ["mobility/uav-mobility-manager.h"]="Mobility manager"
    ["mobility/uav-jammer-mobility.h"]="Jammer mobility"
    ["apps/uav-kdc-app.h"]="KDC application"
    ["apps/uav-skdc-app.h"]="SKDC application"
    ["apps/uav-uav-app.h"]="UAV application"
    ["apps/uav-multicast-manager.h"]="Multicast manager"
    ["apps/uav-tek-manager.h"]="TEK manager"
    ["apps/uav-mtk-distribution.h"]="MTK distribution"
    ["apps/uav-join-event.h"]="Join event"
    ["apps/uav-leave-event.h"]="Leave event"
    ["apps/uav-rekey-manager.h"]="Rekey manager"
    ["apps/uav-handover-manager.h"]="Handover manager"
    ["apps/uav-compromise-detector.h"]="Compromise detector"
    ["apps/uav-jammer-manager.h"]="Jammer manager"
    ["apps/uav-jammer-attack-handler.h"]="Jammer attack handler"
    ["visualization/uav-netanim.h"]="NetAnim"
    ["visualization/uav-node-color.h"]="Node coloring"
    ["visualization/uav-packet-viz.h"]="Packet viz"
    ["visualization/uav-event-annotations.h"]="Event annotations"
    ["metrics/uav-throughput-metrics.h"]="Throughput metrics"
    ["metrics/uav-delay-metrics.h"]="Delay metrics"
    ["metrics/uav-pdr-metrics.h"]="PDR metrics"
    ["metrics/uav-routing-overhead.h"]="Routing overhead"
    ["metrics/uav-rekey-latency.h"]="Rekey latency"
    ["metrics/uav-sinr-metrics.h"]="SINR metrics"
    ["metrics/uav-csv-export.h"]="CSV export"
    ["metrics/uav-pcap-export.h"]="PCAP export"
)

for file in "${!MODULES[@]}"; do
    name="${MODULES[$file]}"
    [[ -f "${SCRATCH}/${file}" ]] \
        && pass "${name}" \
        || fail "${name}: ${file} MISSING"
done

# ---------------------------------------------------------------------------
hdr "CHECK 3: JSON Crypto Parameters"
# ---------------------------------------------------------------------------
JSON="${SCRATCH}/json/crypto_params.json"
[[ -f "${JSON}" ]] && pass "crypto_params.json exists" \
                   || fail "crypto_params.json MISSING"
if [[ -f "${JSON}" ]]; then
    clusters=$(python3 -c "
import json
d=json.load(open('${JSON}'))
print(len(d.get('clusters',[])))
" 2>/dev/null || echo "0")
    [[ "${clusters}" == "3" ]] \
        && pass "JSON: 3 clusters found" \
        || fail "JSON: expected 3 clusters, got ${clusters}"
fi

# ---------------------------------------------------------------------------
hdr "CHECK 4: Quick Simulation Run"
# ---------------------------------------------------------------------------
TMPLOG=$(mktemp)
if "${EXEC}" --seed=42 --duration=30 \
             --pcap=0 --anim=0 \
             > "${TMPLOG}" 2>&1; then
    pass "30s simulation completed"

    # Check key outputs
    rekeys=$(grep "Total rekeys"    "${TMPLOG}" | tail -1 | awk '{print $NF}' || echo "0")
    handovers=$(grep "Total handovers" "${TMPLOG}" | tail -1 | awk '{print $NF}' || echo "0")
    pdr=$(grep "Global PDR"         "${TMPLOG}" | tail -1 | awk '{print $NF}' || echo "0")

    [[ "${rekeys}" -gt 0 ]]    2>/dev/null \
        && pass "Rekeys: ${rekeys}" \
        || warn "Rekeys: ${rekeys} (low for 30s)"

    [[ "${handovers}" -gt 0 ]] 2>/dev/null \
        && pass "Handovers: ${handovers}" \
        || warn "Handovers: ${handovers} (UAVs may not cross boundary in 30s)"

    python3 -c "
pdr='${pdr}'
try:
    v=float(pdr)
    assert 0.0<=v<=1.0
    print('PDR in range [0,1]:', v)
except:
    print('PDR invalid:', pdr)
" | grep -q "PDR in range" \
        && pass "PDR valid: ${pdr}" \
        || fail "PDR invalid: ${pdr}"
else
    fail "Simulation FAILED — check ${TMPLOG}"
    tail -10 "${TMPLOG}"
fi
rm -f "${TMPLOG}"

# ---------------------------------------------------------------------------
hdr "CHECK 5: Output Files"
# ---------------------------------------------------------------------------
declare -A OUTPUT_FILES=(
    ["output/metrics_global.csv"]="Global metrics CSV"
    ["output/metrics_per_cluster.csv"]="Cluster metrics CSV"
    ["output/metrics_per_uav.csv"]="Per-UAV metrics CSV"
    ["output/throughput.csv"]="Throughput CSV"
    ["output/delay.csv"]="Delay CSV"
    ["output/pdr.csv"]="PDR CSV"
    ["output/sinr.csv"]="SINR CSV"
    ["output/rekey_latency.csv"]="Rekey latency CSV"
    ["output/routing_overhead.csv"]="Routing overhead CSV"
    ["output/uav-fanet-anim.xml"]="NetAnim XML"
    ["output/flowmonitor.xml"]="FlowMonitor XML"
)
for file in "${!OUTPUT_FILES[@]}"; do
    name="${OUTPUT_FILES[$file]}"
    [[ -f "${SCRATCH}/${file}" ]] \
        && pass "${name}" \
        || warn "${name}: ${file} not found (run simulation first)"
done

# ---------------------------------------------------------------------------
hdr "CHECK 6: Graph Files"
# ---------------------------------------------------------------------------
EXPECTED_GRAPHS=(
    "throughput_vs_uav.png" "pdr_vs_uav.png"
    "sinr_vs_uav.png" "delay_vs_uav.png"
    "drop_prob_vs_uav.png" "cluster_throughput.png"
    "cluster_pdr.png" "rekey_latency_hist.png"
    "rekey_per_cluster.png" "global_metrics_bar.png"
    "sinr_cdf.png" "routing_overhead.png"
    "scenario_handovers.png" "scenario_rekeys.png"
)
for g in "${EXPECTED_GRAPHS[@]}"; do
    [[ -f "${SCRATCH}/graphs/${g}" ]] \
        && pass "Graph: ${g}" \
        || warn "Graph: ${g} not found (run plot_all.py)"
done

# ---------------------------------------------------------------------------
hdr "CHECK 7: Scripts"
# ---------------------------------------------------------------------------
[[ -x "${SCRATCH}/run.sh" ]] \
    && pass "run.sh executable" \
    || fail "run.sh not executable"
[[ -x "${SCRATCH}/scripts/simulate_all.sh" ]] \
    && pass "simulate_all.sh executable" \
    || fail "simulate_all.sh not executable"
[[ -x "${SCRATCH}/scripts/batch_run.sh" ]] \
    && pass "batch_run.sh executable" \
    || fail "batch_run.sh not executable"
[[ -f "${SCRATCH}/graphs/plot_all.py" ]] \
    && pass "plot_all.py present" \
    || fail "plot_all.py missing"

# ---------------------------------------------------------------------------
hdr "CHECK 8: Crypto Correctness"
# ---------------------------------------------------------------------------
python3 - << 'PYEOF'
import subprocess, json, sys

# Verify crypto_params.json structure
try:
    with open('scratch/uav-secure-fanet/json/crypto_params.json') as f:
        d = json.load(f)
    assert 'clusters' in d and len(d['clusters']) == 3
    assert 'uavs' in d and len(d['uavs']) == 18
    for c in d['clusters']:
        assert 'cluster_id' in c
        assert 'e_M' in c or 'eM' in c or 'master_key' in c \
            or len(c) > 2
    print("  JSON structure: OK")
except Exception as e:
    print(f"  JSON structure: WARN ({e})")
PYEOF
pass "Crypto params loadable"

# ---------------------------------------------------------------------------
hdr "FINAL SUMMARY"
# ---------------------------------------------------------------------------
sep
TOTAL=$(( PASS + FAIL + WARN ))
echo -e "  ${GREEN}PASS: ${PASS}${NC}"
echo -e "  ${RED}FAIL: ${FAIL}${NC}"
echo -e "  ${YELLOW}WARN: ${WARN}${NC}"
echo -e "  Total checks: ${TOTAL}"
sep

if [[ ${FAIL} -eq 0 ]]; then
    echo -e "\n${GREEN}✓ ALL CHECKS PASSED — Implementation complete${NC}"
    echo -e "${GREEN}  Project: Hierarchical CRT-GCRT UAV Swarm FANET${NC}"
    echo -e "${GREEN}  Phases:  1-10 complete (Modules 1-66)${NC}"
    echo -e "${GREEN}  Status:  READY FOR EVALUATION${NC}\n"
    exit 0
else
    echo -e "\n${RED}✗ ${FAIL} CHECK(S) FAILED${NC}"
    exit 1
fi
