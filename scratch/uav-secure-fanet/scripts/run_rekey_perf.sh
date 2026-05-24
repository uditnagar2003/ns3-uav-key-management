#!/usr/bin/env bash
# run_rekey_perf.sh  — FIXED VERSION
# Fix 1: correct cmake target name
# Fix 2: use ./ns3 build instead of cmake --build
# Fix 3: correct executable path detection
# ============================================================
set -euo pipefail

# ============================================================
# CONFIG
# ============================================================
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH="${NS3_ROOT}/scratch/uav-secure-fanet"
OUT="${SCRATCH}/output/rekey_perf"
SCENARIO="rekey_perf"

UAV_COUNTS="${UAV_COUNTS:-6 12 18 24 30}"
RUNS="${RUNS:-5}"
DURATION="${DURATION:-600}"
SEED="${SEED:-42}"
ENABLE_GRAPHS="${ENABLE_GRAPHS:-1}"
ENABLE_NETANIM="${ENABLE_NETANIM:-1}"

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m';  GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[REKEY_PERF]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
sep()  { echo -e "${BLUE}══════════════════════════════════${NC}"; }

sep
log "Rekey Performance Scenario Runner"
log "NS-3 Root  : ${NS3_ROOT}"
log "UAV Counts : ${UAV_COUNTS}"
log "Runs/config: ${RUNS}"
log "Duration   : ${DURATION}s"
log "Seed base  : ${SEED}"
sep

# ============================================================
# FIX 1: BUILD — use ./ns3 build (correct for NS-3.43 cmake)
# ============================================================
log "Building NS-3 project..."
cd "${NS3_ROOT}"

# NS-3.43 uses cmake internally but exposes ./ns3 as the wrapper
# The cmake target is: scratch_uav-secure-fanet_uav-secure-fanet
# But ./ns3 build handles this correctly without path mangling

./ns3 build uav-secure-fanet 2>&1 | tail -8

# ============================================================
# FIX 2: FIND EXECUTABLE — search multiple possible paths
# ============================================================
EXEC=""
# NS-3.43 cmake build output locations (try in order):
POSSIBLE_PATHS=(
    "${NS3_ROOT}/cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug"
    "${NS3_ROOT}/cmake-cache/scratch/uav-secure-fanet/uav-secure-fanet"
    "${NS3_ROOT}/build/scratch/uav-secure-fanet"
    "${NS3_ROOT}/build/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug"
)
for p in "${POSSIBLE_PATHS[@]}"; do
    if [[ -x "$p" ]]; then
        EXEC="$p"
        break
    fi
done

if [[ -z "${EXEC}" ]]; then
    # Last resort: find it
    EXEC=$(find "${NS3_ROOT}/cmake-cache" \
               -name "*uav-secure-fanet*" \
               -type f -executable 2>/dev/null | head -1)
fi

if [[ -z "${EXEC}" ]]; then
    warn "Standalone executable not found."
    warn "Will use: ./ns3 run uav-secure-fanet"
    USE_NS3_RUN=1
else
    USE_NS3_RUN=0
    log "Executable: ${EXEC}"
fi

# ============================================================
# PREPARE DIRECTORIES
# ============================================================
mkdir -p "${OUT}/csv"
mkdir -p "${OUT}/netanim"
mkdir -p "${OUT}/pcap"
mkdir -p "${OUT}/graphs"
mkdir -p "${OUT}/logs"

# Scalability CSV header
SCAL_CSV="${OUT}/scalability.csv"
echo "uav_count,run,seed,pdr,throughput_kbps,avg_delay_ms,\
rekey_latency_ms,total_rekeys,total_joins,total_leaves,\
total_compromises,total_handovers,security_overhead_ratio" \
    > "${SCAL_CSV}"

# ============================================================
# RUN SWEEP
# ============================================================
TOTAL_PASS=0
TOTAL_FAIL=0

for N in ${UAV_COUNTS}; do
    sep
    log "UAV COUNT = ${N}"

    for R in $(seq 1 "${RUNS}"); do
        RUN_SEED=$(( SEED + N * 100 + R - 1 ))
        LOG_FILE="${OUT}/logs/n${N}_run${R}.log"

        log "  Run ${R}/${RUNS} | N=${N} | seed=${RUN_SEED}"

        # Build the run command
        ARGS="--scenario=${SCENARIO} \
              --uav-count=${N} \
              --duration=${DURATION} \
              --seed=${RUN_SEED} \
              --enable-netanim=${ENABLE_NETANIM} \
              --output-dir=${OUT}"

        if [[ "${USE_NS3_RUN}" -eq 1 ]]; then
            # Use ./ns3 run wrapper
            RUN_CMD="./ns3 run \"uav-secure-fanet ${ARGS}\""
        else
            RUN_CMD="${EXEC} ${ARGS}"
        fi

        if eval "${RUN_CMD}" > "${LOG_FILE}" 2>&1; then
            TOTAL_PASS=$(( TOTAL_PASS + 1 ))
            log "    ✓ Run ${R} OK"
        else
            TOTAL_FAIL=$(( TOTAL_FAIL + 1 ))
            warn "    ✗ Run ${R} FAILED — ${LOG_FILE}"
        fi
    done
done

# ============================================================
# GRAPH GENERATION
# ============================================================
sep
if [[ "${ENABLE_GRAPHS}" -eq 1 ]]; then
    log "Generating graphs..."
    python3 "${SCRATCH}/graphs/generate_graphs.py" \
        --input  "${OUT}" \
        --output "${OUT}/graphs" \
        && log "Graphs: ${OUT}/graphs/" \
        || warn "Graph generation failed — run manually"
fi

sep
log "DONE  PASS=${TOTAL_PASS}  FAIL=${TOTAL_FAIL}"
log "Output: ${OUT}"

[[ "${TOTAL_FAIL}" -eq 0 ]] && exit 0 || exit 1
