#!/usr/bin/env bash
# run.sh — Module 62: Scenario Runner
# UAV Secure FANET — NS-3.43 Simulation Runner
#
# USAGE:
#   cd ~/ns-allinone-3.43/ns-3.43
#   ./scratch/uav-secure-fanet/run.sh [OPTIONS]
#
# OPTIONS:
#   --runs N        Number of simulation runs (default: 10)
#   --duration T    Simulation duration in seconds (default: 300)
#   --seed S        Random seed base (default: 42)
#   --no-pcap       Disable PCAP output
#   --no-anim       Disable NetAnim output
#   --debug         Enable NS_LOG verbose output
#   --build-only    Build only, do not run
#   --jobs N        Parallel build jobs (default: nproc)
#
# EXAMPLE:
#   ./scratch/uav-secure-fanet/run.sh --runs 3 --duration 300
#   ./scratch/uav-secure-fanet/run.sh --runs 1 --debug
#
# OUTPUT:
#   output/  — CSV metrics, NetAnim XML, FlowMonitor XML
#   pcap/    — PCAP traces (23 files per run)
#   logs/    — Per-run log files

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[RUN]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
sep()  { echo -e "${BLUE}══════════════════════════════════════════${NC}"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH_DIR="${NS3_ROOT}/scratch/uav-secure-fanet"
MODULE_NAME="uav-secure-fanet"
EXEC="${NS3_ROOT}/cmake-cache/scratch/${MODULE_NAME}/ns3.43-${MODULE_NAME}-debug"

RUNS=10
DURATION=300
SEED=42
ENABLE_PCAP=1
ENABLE_ANIM=1
DEBUG_NS_LOG=0
BUILD_ONLY=0
JOBS=$(nproc)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)      RUNS="$2";     shift ;;
        --duration)  DURATION="$2"; shift ;;
        --seed)      SEED="$2";     shift ;;
        --no-pcap)   ENABLE_PCAP=0  ;;
        --no-anim)   ENABLE_ANIM=0  ;;
        --debug)     DEBUG_NS_LOG=1 ;;
        --build-only) BUILD_ONLY=1  ;;
        --jobs)      JOBS="$2";     shift ;;
        -h|--help)
            head -30 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *) warn "Unknown option: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
sep
log "UAV Secure FANET — Scenario Runner"
log "NS-3 root  : ${NS3_ROOT}"
log "Runs       : ${RUNS}"
log "Duration   : ${DURATION}s"
log "Seed base  : ${SEED}"
log "PCAP       : ${ENABLE_PCAP}"
log "NetAnim    : ${ENABLE_ANIM}"
sep

[[ -d "${SCRATCH_DIR}" ]] || err "Scratch dir not found: ${SCRATCH_DIR}"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
log "Building..."
cd "${NS3_ROOT}"

cmake --build cmake-cache -j"${JOBS}" \
    --target "scratch_${MODULE_NAME}_${MODULE_NAME}" \
    2>&1 | tail -3

[[ -x "${EXEC}" ]] || err "Executable not found: ${EXEC}"
log "Build OK: ${EXEC}"

if [[ ${BUILD_ONLY} -eq 1 ]]; then
    log "Build-only mode. Exiting."
    exit 0
fi

# ---------------------------------------------------------------------------
# Prepare output directories
# ---------------------------------------------------------------------------
for d in logs output pcap json graphs; do
    mkdir -p "${SCRATCH_DIR}/${d}"
done

# ---------------------------------------------------------------------------
# NS_LOG (debug mode)
# ---------------------------------------------------------------------------
if [[ ${DEBUG_NS_LOG} -eq 1 ]]; then
    export NS_LOG="UavSecureFanet=level_all|prefix_time:\
UavHandoverManager=level_all:\
UavRekeyManager=level_all:\
UavJammerAttackHandler=level_all"
    log "NS_LOG verbose enabled"
fi

# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------
sep
log "Starting ${RUNS} simulation run(s)..."
sep

PASS=0
FAIL=0
TOTAL_START=$(date +%s)

for run_idx in $(seq 1 "${RUNS}"); do
    RUN_SEED=$(( SEED + run_idx - 1 ))
    RUN_LOG="${SCRATCH_DIR}/logs/run_${run_idx}.log"
    RUN_START=$(date +%s)

    info "Run ${run_idx}/${RUNS} | seed=${RUN_SEED} | ${DURATION}s"

    # Arguments matching main.cc CommandLine
    SIM_ARGS=(
        "--seed=${RUN_SEED}"
        "--duration=${DURATION}"
        "--pcap=${ENABLE_PCAP}"
        "--anim=${ENABLE_ANIM}"
    )

    if "${EXEC}" "${SIM_ARGS[@]}" \
            > "${RUN_LOG}" 2>&1; then
        RUN_END=$(date +%s)
        ELAPSED=$(( RUN_END - RUN_START ))
        PASS=$(( PASS + 1 ))
        log "  ✓ Run ${run_idx} PASSED in ${ELAPSED}s"

        # Extract key metrics from log
        REKEYS=$(grep "Total rekeys" "${RUN_LOG}" \
            | tail -1 | awk '{print $NF}')
        HANDOVERS=$(grep "Total handovers" "${RUN_LOG}" \
            | tail -1 | awk '{print $NF}')
        PDR=$(grep "Global PDR" "${RUN_LOG}" \
            | tail -1 | awk '{print $NF}')
        info "    rekeys=${REKEYS} handovers=${HANDOVERS} PDR=${PDR}"

        # Archive per-run outputs
        RUN_DIR="${SCRATCH_DIR}/output/run_${run_idx}"
        mkdir -p "${RUN_DIR}"
        cp "${SCRATCH_DIR}/output"/*.csv \
           "${RUN_DIR}/" 2>/dev/null || true
        cp "${SCRATCH_DIR}/output/flowmonitor.xml" \
           "${RUN_DIR}/" 2>/dev/null || true
    else
        FAIL=$(( FAIL + 1 ))
        warn "  ✗ Run ${run_idx} FAILED — see ${RUN_LOG}"
        tail -5 "${RUN_LOG}" || true
    fi
done

TOTAL_END=$(date +%s)
WALL_TIME=$(( TOTAL_END - TOTAL_START ))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sep
log "Simulation Complete"
log "  Total runs : ${RUNS}"
log "  Passed     : ${PASS}"
log "  Failed     : ${FAIL}"
log "  Wall time  : ${WALL_TIME}s"
log "  Output     : ${SCRATCH_DIR}/output/"
log "  Logs       : ${SCRATCH_DIR}/logs/"
log "  PCAP       : ${SCRATCH_DIR}/pcap/"
log "  NetAnim    : ${SCRATCH_DIR}/output/uav-fanet-anim.xml"
sep

if [[ ${FAIL} -gt 0 ]]; then
    warn "${FAIL} run(s) failed. Check logs for details."
    exit 1
fi

log "All runs completed successfully."
exit 0
