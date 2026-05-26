#!/usr/bin/env bash
# deploy_metrics_patch.sh — FIXED
# Run from ANYWHERE. Auto-detects project root.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# The patch files live in the same directory as this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Project root is the parent of wherever this script lives
SCRATCH="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify we found the project
if [[ ! -f "${SCRATCH}/main.cc" ]]; then
    if [[ -f "${SCRIPT_DIR}/main.cc" ]]; then
        SCRATCH="${SCRIPT_DIR}"
    else
        fail "Cannot find main.cc. Expected it at ${SCRATCH}/main.cc"
    fi
fi

echo "========================================================"
echo "  UAV FANET — Metrics Framework Deployment"
echo "  Patch dir: ${SCRIPT_DIR}"
echo "  Project:   ${SCRATCH}"
echo "========================================================"

mkdir -p "${SCRATCH}/metrics" "${SCRATCH}/graphs"

echo ""
echo "--- Deploying metrics/ ---"
cp "${SCRIPT_DIR}/uav-metrics-framework.h"  "${SCRATCH}/metrics/"
ok  "metrics/uav-metrics-framework.h"
cp "${SCRIPT_DIR}/uav-metrics-framework.cc" "${SCRATCH}/metrics/"
ok  "metrics/uav-metrics-framework.cc"

echo ""
echo "--- Deploying graphs/ ---"
cp "${SCRIPT_DIR}/plot_metrics_full.py" "${SCRATCH}/graphs/"
ok  "graphs/plot_metrics_full.py"
cp "${SCRIPT_DIR}/INTEGRATION_PATCH.cc" "${SCRATCH}/"
ok  "INTEGRATION_PATCH.cc"

echo ""
echo "--- Patching CMakeLists.txt ---"
CMAKE="${SCRATCH}/CMakeLists.txt"
if [[ -f "${CMAKE}" ]]; then
    if grep -q "uav-metrics-framework" "${CMAKE}"; then
        warn "Already present — skip"
    elif grep -q "uav-pcap-export.cc" "${CMAKE}"; then
        sed -i 's|metrics/uav-pcap-export.cc|metrics/uav-pcap-export.cc\n    metrics/uav-metrics-framework.cc|' "${CMAKE}"
        ok  "CMakeLists.txt patched"
    elif grep -q "uav-sinr-metrics.cc" "${CMAKE}"; then
        sed -i 's|metrics/uav-sinr-metrics.cc|metrics/uav-sinr-metrics.cc\n    metrics/uav-metrics-framework.cc|' "${CMAKE}"
        ok  "CMakeLists.txt patched"
    else
        warn "Add manually to CMakeLists.txt: metrics/uav-metrics-framework.cc"
    fi
fi

echo ""
echo "--- Patching main.cc include ---"
MAIN="${SCRATCH}/main.cc"
if [[ -f "${MAIN}" ]]; then
    if grep -q "uav-metrics-framework" "${MAIN}"; then
        warn "Already included — skip"
    else
        sed -i 's|#include "metrics/uav-pcap-export.h"|#include "metrics/uav-pcap-export.h"\n#include "metrics/uav-metrics-framework.h"|' "${MAIN}" \
        && ok "main.cc include added" \
        || warn 'Add manually: #include "metrics/uav-metrics-framework.h"'
    fi
fi

echo ""
echo "========================================================"
echo "  DEPLOYMENT COMPLETE"
echo ""
echo "  NEXT STEPS:"
echo "  1. Read INTEGRATION_PATCH.cc (what to add to main.cc)"
echo "  2. cd ~/ns-allinone-3.43/ns-3.43"
echo "     cmake --build cmake-cache/scratch/uav-secure-fanet/ -j\$(nproc)"
echo "  3. Run simulation"
echo "  4. cd ${SCRATCH}"
echo "     python3 graphs/plot_metrics_full.py"
echo "========================================================"
