#!/usr/bin/env bash
# =============================================================================
# init_project.sh
# Project: Hierarchical CRT-GCRT Based UAV Swarm Multicast Key Management
#          in Denied FANET Environments using NS-3.43
#
# PURPOSE:
#   Creates the COMPLETE project folder hierarchy inside NS-3.43's scratch dir.
#   Run this ONCE before any module implementation begins.
#
# USAGE:
#   chmod +x init_project.sh
#   ./init_project.sh [/path/to/ns-3.43/scratch]
#
# DEFAULT TARGET: ./scratch/uav-secure-fanet/  (relative to NS-3 root)
# =============================================================================

set -euo pipefail

NS3_ROOT="${1:-$(pwd)}"
PROJECT_DIR="${NS3_ROOT}/scratch/uav-secure-fanet"

echo "============================================================"
echo "  UAV Secure FANET — Project Initialization"
echo "  Target: ${PROJECT_DIR}"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. Application layer
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/apps/kdc"
mkdir -p "${PROJECT_DIR}/apps/skdc"
mkdir -p "${PROJECT_DIR}/apps/uav"
mkdir -p "${PROJECT_DIR}/apps/multicast"
mkdir -p "${PROJECT_DIR}/apps/tek"
mkdir -p "${PROJECT_DIR}/apps/mtk"

# ---------------------------------------------------------------------------
# 2. Cryptography layer
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/crypto/aes"
mkdir -p "${PROJECT_DIR}/crypto/hmac"
mkdir -p "${PROJECT_DIR}/crypto/crt"
mkdir -p "${PROJECT_DIR}/crypto/replay"
mkdir -p "${PROJECT_DIR}/crypto/keymgr"

# ---------------------------------------------------------------------------
# 3. Packet headers
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/headers/common"
mkdir -p "${PROJECT_DIR}/headers/packets"

# ---------------------------------------------------------------------------
# 4. Mobility models
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/mobility/gauss"
mkdir -p "${PROJECT_DIR}/mobility/jammer"
mkdir -p "${PROJECT_DIR}/mobility/cluster"

# ---------------------------------------------------------------------------
# 5. Routing
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/routing/olsr"
mkdir -p "${PROJECT_DIR}/routing/flowmon"

# ---------------------------------------------------------------------------
# 6. Metrics
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/metrics/throughput"
mkdir -p "${PROJECT_DIR}/metrics/delay"
mkdir -p "${PROJECT_DIR}/metrics/pdr"
mkdir -p "${PROJECT_DIR}/metrics/overhead"

# ---------------------------------------------------------------------------
# 7. Visualization
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/visualization/netanim"
mkdir -p "${PROJECT_DIR}/visualization/pyviz"

# ---------------------------------------------------------------------------
# 8. Utilities
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/utils/logging"
mkdir -p "${PROJECT_DIR}/utils/config"
mkdir -p "${PROJECT_DIR}/utils/json"

# ---------------------------------------------------------------------------
# 9. Scripts
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/scripts/python"
mkdir -p "${PROJECT_DIR}/scripts/gnuplot"

# ---------------------------------------------------------------------------
# 10. Runtime output directories
# ---------------------------------------------------------------------------
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/output"
mkdir -p "${PROJECT_DIR}/pcap"
mkdir -p "${PROJECT_DIR}/graphs"
mkdir -p "${PROJECT_DIR}/json"

# ---------------------------------------------------------------------------
# 11. Initialize log files
# ---------------------------------------------------------------------------
LOG_FILES=(
    "crypto.log"
    "routing.log"
    "mobility.log"
    "jammer.log"
    "rekey.log"
    "packet.log"
    "flowmonitor.log"
)

for logfile in "${LOG_FILES[@]}"; do
    LOG_PATH="${PROJECT_DIR}/logs/${logfile}"
    if [[ ! -f "${LOG_PATH}" ]]; then
        cat > "${LOG_PATH}" << LOGEOF
# UAV Secure FANET — ${logfile}
# Project: Hierarchical CRT-GCRT Based UAV Swarm Multicast Key Management
# Created: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Format: [TIMESTAMP] [LEVEL] [MODULE] MESSAGE
LOGEOF
    fi
done

# ---------------------------------------------------------------------------
# 12. Create placeholder output CSV files
# ---------------------------------------------------------------------------
OUTPUT_CSVS=(
    "metrics_global.csv"
    "metrics_per_uav.csv"
    "metrics_per_cluster.csv"
)

CSV_HEADERS=(
    "time_s,throughput_bps,pdr,e2e_delay_ms,routing_overhead,rekey_latency_ms,handover_latency_ms,packet_loss_pct,sinr_db"
    "time_s,uav_id,cluster_id,throughput_bps,pdr,e2e_delay_ms,tx_packets,rx_packets,dropped_packets,tek_version"
    "time_s,cluster_id,skdc_id,throughput_bps,pdr,member_count,rekey_count,handover_count,jammer_active"
)

for i in "${!OUTPUT_CSVS[@]}"; do
    CSV_PATH="${PROJECT_DIR}/output/${OUTPUT_CSVS[$i]}"
    if [[ ! -f "${CSV_PATH}" ]]; then
        echo "${CSV_HEADERS[$i]}" > "${CSV_PATH}"
    fi
done

# ---------------------------------------------------------------------------
# 13. Verify structure
# ---------------------------------------------------------------------------
echo ""
echo "=== DIRECTORY STRUCTURE CREATED ==="
find "${PROJECT_DIR}" -type d | sort | sed "s|${PROJECT_DIR}|.|g"

echo ""
echo "=== LOG FILES INITIALIZED ==="
ls -1 "${PROJECT_DIR}/logs/"

echo ""
echo "=== OUTPUT CSV FILES INITIALIZED ==="
ls -1 "${PROJECT_DIR}/output/"

echo ""
echo "============================================================"
echo "  Phase 1 Module 1: Project Folder Hierarchy — COMPLETE"
echo "  Next: Phase 1 Module 2 — waf/CMake Integration"
echo "============================================================"
