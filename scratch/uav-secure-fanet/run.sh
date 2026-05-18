#!/usr/bin/env bash
# run.sh
# Simulation runner for UAV Secure FANET in NS-3.43
#
# USAGE:
#   ./run.sh [OPTIONS]
#
# OPTIONS:
#   --debug           Enable NS_LOG verbose output
#   --build-only      Configure + build, do not run
#   --clean           Clean build artifacts before building
#   --runs N          Number of simulation runs (default: 10)
#   --duration T      Simulation duration in seconds (default: 180)
#   --seed S          Random seed base (default: 10)
#   --cmake           Use cmake instead of waf
#   --jobs N          Parallel build jobs (default: nproc)
#
# INTEGRATION NOTE:
#   This script MUST be run from <ns3-root>/ — NOT from the scratch subdir.
#   NS-3.43 waf is invoked from the NS-3 root.
#
# DEPENDENCY:
#   build_deps.sh must have been run successfully.
#   Module 1 folder hierarchy must exist.

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[RUN]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
sep()  { echo -e "${BLUE}══════════════════════════════════════════════${NC}"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH_DIR="${NS3_ROOT}/scratch/uav-secure-fanet"
MODULE_NAME="uav-secure-fanet"
BUILD_ONLY=0
CLEAN_BUILD=0
USE_CMAKE=0
DEBUG_NS_LOG=0
RUNS=10
DURATION=180
SEED=10
JOBS=$(nproc)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)       DEBUG_NS_LOG=1 ;;
        --build-only)  BUILD_ONLY=1 ;;
        --clean)       CLEAN_BUILD=1 ;;
        --cmake)       USE_CMAKE=1 ;;
        --runs)        RUNS="$2";    shift ;;
        --duration)    DURATION="$2"; shift ;;
        --seed)        SEED="$2";    shift ;;
        --jobs)        JOBS="$2";    shift ;;
        -h|--help)
            grep '^# ' "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            warn "Unknown option: $1"
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------
sep
log "UAV Secure FANET — Simulation Runner"
log "NS-3 root   : ${NS3_ROOT}"
log "Scratch dir : ${SCRATCH_DIR}"
log "Runs        : ${RUNS}"
log "Duration    : ${DURATION}s"
log "Seed base   : ${SEED}"
log "Jobs        : ${JOBS}"
sep

# Check NS-3 root
if [[ ! -f "${NS3_ROOT}/waf" && ! -f "${NS3_ROOT}/ns3" ]]; then
    err "NS-3 not found at ${NS3_ROOT}.\n" \
        "Set NS3_ROOT=/path/to/ns-3.43 or run from NS-3 root."
fi

# Check scratch module
if [[ ! -d "${SCRATCH_DIR}" ]]; then
    err "Scratch module not found: ${SCRATCH_DIR}\n" \
        "Run Module 1 setup first."
fi

# ---------------------------------------------------------------------------
# Ensure output directories exist (Module 1 should have created these,
# but run.sh guarantees them before simulation starts)
# ---------------------------------------------------------------------------
for d in logs output pcap json graphs; do
    mkdir -p "${SCRATCH_DIR}/${d}"
done
log "Output directories verified"

# ---------------------------------------------------------------------------
# Clean build
# ---------------------------------------------------------------------------
if [[ ${CLEAN_BUILD} -eq 1 ]]; then
    log "Cleaning build artifacts..."
    if [[ ${USE_CMAKE} -eq 0 ]]; then
        cd "${NS3_ROOT}"
        ./waf distclean 2>/dev/null || true
    else
        rm -rf "${NS3_ROOT}/build" 2>/dev/null || true
    fi
    log "Clean complete"
fi

# ---------------------------------------------------------------------------
# Build — WAF path
# ---------------------------------------------------------------------------
build_waf() {
    log "Configuring NS-3.43 with waf..."
    cd "${NS3_ROOT}"

    local waf_configure_args=(
        --enable-examples=no
        --enable-tests=no
        --build-profile=release
        "--out=build"
    )

    if [[ ${DEBUG_NS_LOG} -eq 1 ]]; then
        waf_configure_args+=(--build-profile=debug)
        log "Debug build profile selected"
    fi

    ./waf configure "${waf_configure_args[@]}"

    log "Building with waf (jobs=${JOBS})..."
    ./waf build --jobs="${JOBS}"

    log "WAF build complete"
}

# ---------------------------------------------------------------------------
# Build — CMake path
# ---------------------------------------------------------------------------
build_cmake() {
    log "Configuring NS-3.43 with CMake..."
    cd "${NS3_ROOT}"

    local cmake_build_type="Release"
    [[ ${DEBUG_NS_LOG} -eq 1 ]] && cmake_build_type="Debug"

    cmake -B build \
        -DCMAKE_BUILD_TYPE="${cmake_build_type}" \
        -DCMAKE_CXX_COMPILER=g++-13 \
        -DENABLE_EXAMPLES=OFF \
        -DENABLE_TESTS=OFF \
        -DNS3_ENABLED_MODULES="core;network;internet;wifi;csma;mobility;olsr;applications;flow-monitor;netanim;energy;propagation;stats" \
        -G Ninja

    log "Building with CMake/Ninja (jobs=${JOBS})..."
    cmake --build build \
        --target "${MODULE_NAME}" \
        --parallel "${JOBS}"

    log "CMake build complete"
}

# ---------------------------------------------------------------------------
# Execute build
# ---------------------------------------------------------------------------
if [[ ${USE_CMAKE} -eq 1 ]]; then
    build_cmake
else
    build_waf
fi

if [[ ${BUILD_ONLY} -eq 1 ]]; then
    log "Build-only mode — exiting without running simulation"
    exit 0
fi

# ---------------------------------------------------------------------------
# NS_LOG configuration
# ---------------------------------------------------------------------------
if [[ ${DEBUG_NS_LOG} -eq 1 ]]; then
    export NS_LOG="${MODULE_NAME}=level_all|prefix_func|prefix_time:\
KdcApplication=level_all:\
SkdcApplication=level_all:\
UavApplication=level_all:\
CryptoManager=level_all:\
MobilityManager=level_all"
    log "NS_LOG verbose mode enabled"
fi

# ---------------------------------------------------------------------------
# Run simulation N times
# ---------------------------------------------------------------------------
sep
log "Starting simulation runs..."
sep

PASS=0
FAIL=0
TOTAL_START=$(date +%s)

for run_idx in $(seq 1 "${RUNS}"); do
    RUN_SEED=$(( SEED + run_idx - 1 ))
    RUN_LOG="${SCRATCH_DIR}/logs/run_${run_idx}.log"
    RUN_START=$(date +%s)

    info "Run ${run_idx}/${RUNS} | seed=${RUN_SEED} | duration=${DURATION}s"

    # Build argument string for NS-3 program
    # These args will be parsed by main.cc (Module 60)
    SIM_ARGS=(
        "--RngSeed=${RUN_SEED}"
        "--simDuration=${DURATION}"
        "--runIndex=${run_idx}"
        "--logDir=${SCRATCH_DIR}/logs"
        "--outputDir=${SCRATCH_DIR}/output"
        "--pcapDir=${SCRATCH_DIR}/pcap"
        "--jsonDir=${SCRATCH_DIR}/json"
    )

    # Run via waf or cmake build
    if [[ ${USE_CMAKE} -eq 0 ]]; then
        cd "${NS3_ROOT}"
        if ./waf --run "${MODULE_NAME} ${SIM_ARGS[*]}" \
                 >> "${RUN_LOG}" 2>&1; then
            PASS=$(( PASS + 1 ))
            RUN_END=$(date +%s)
            log "  ✓ Run ${run_idx} PASSED in $(( RUN_END - RUN_START ))s"
        else
            FAIL=$(( FAIL + 1 ))
            warn "  ✗ Run ${run_idx} FAILED — see ${RUN_LOG}"
        fi
    else
        EXEC="${NS3_ROOT}/build/scratch/${MODULE_NAME}/${MODULE_NAME}"
        if [[ ! -x "${EXEC}" ]]; then
            err "Executable not found: ${EXEC}"
        fi
        if "${EXEC}" "${SIM_ARGS[@]}" >> "${RUN_LOG}" 2>&1; then
            PASS=$(( PASS + 1 ))
            RUN_END=$(date +%s)
            log "  ✓ Run ${run_idx} PASSED in $(( RUN_END - RUN_START ))s"
        else
            FAIL=$(( FAIL + 1 ))
            warn "  ✗ Run ${run_idx} FAILED — see ${RUN_LOG}"
        fi
    fi
done

TOTAL_END=$(date +%s)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sep
log "Simulation Complete"
log "  Total runs  : ${RUNS}"
log "  Passed      : ${PASS}"
log "  Failed      : ${FAIL}"
log "  Wall time   : $(( TOTAL_END - TOTAL_START ))s"
log "  Output      : ${SCRATCH_DIR}/output/"
log "  Logs        : ${SCRATCH_DIR}/logs/"
log "  PCAP        : ${SCRATCH_DIR}/pcap/"
sep

if [[ ${FAIL} -gt 0 ]]; then
    warn "${FAIL} run(s) failed. Check logs for details."
    exit 1
fi

log "All runs completed successfully."
exit 0