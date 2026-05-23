#!/usr/bin/env bash
# scripts/batch_run.sh
# Module 65 — Batch Execution Scripts
#
# Runs complete research evaluation pipeline:
#   Step 1: Build
#   Step 2: Run all scenarios (simulate_all.sh)
#   Step 3: Generate graphs (plot_all.py)
#   Step 4: Export summary report
#
# USAGE:
#   cd ~/ns-allinone-3.43/ns-3.43
#   bash scratch/uav-secure-fanet/scripts/batch_run.sh [--quick]
#
# OPTIONS:
#   --quick    1 run per scenario (for testing)
#   --runs N   Runs per scenario (default: 10)
#   --seed S   Base seed (default: 42)

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m';  RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[BATCH]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
sep()  { echo -e "${BLUE}══════════════════════════════════════${NC}"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH="${NS3_ROOT}/scratch/uav-secure-fanet"
RUNS=10
SEED=42
DURATION=300
QUICK=0
JOBS=$(nproc)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)    QUICK=1; RUNS=1 ;;
        --runs)     RUNS="$2"; shift ;;
        --seed)     SEED="$2"; shift ;;
        --duration) DURATION="$2"; shift ;;
        --jobs)     JOBS="$2"; shift ;;
        *) warn "Unknown: $1" ;;
    esac
    shift
done

BATCH_START=$(date +%s)
BATCH_LOG="${SCRATCH}/logs/batch_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "${SCRATCH}/logs"

sep
log "UAV Secure FANET — Batch Execution"
log "  NS3 root : ${NS3_ROOT}"
log "  Runs/sc  : ${RUNS}"
log "  Duration : ${DURATION}s"
log "  Seed     : ${SEED}"
log "  Quick    : ${QUICK}"
log "  Log      : ${BATCH_LOG}"
sep

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------
sep; log "STEP 1: Build"
cd "${NS3_ROOT}"
cmake --build cmake-cache -j"${JOBS}" \
    --target scratch_uav-secure-fanet_uav-secure-fanet \
    2>&1 | tee -a "${BATCH_LOG}" | tail -3

EXEC="${NS3_ROOT}/cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug"
[[ -x "${EXEC}" ]] || err "Executable not found"
log "Build OK ✓"

# ---------------------------------------------------------------------------
# Step 2: Prepare directories
# ---------------------------------------------------------------------------
sep; log "STEP 2: Prepare directories"
for d in logs output pcap json graphs; do
    mkdir -p "${SCRATCH}/${d}"
done
log "Directories ready ✓"

# ---------------------------------------------------------------------------
# Step 3: Run scenarios
# ---------------------------------------------------------------------------
sep; log "STEP 3: Run scenarios (${RUNS} runs × ${DURATION}s)"

RUNS_PER_SCENARIO="${RUNS}" \
SEED_BASE="${SEED}" \
    bash "${SCRATCH}/scripts/simulate_all.sh" \
    2>&1 | tee -a "${BATCH_LOG}"

log "Scenarios complete ✓"

# ---------------------------------------------------------------------------
# Step 4: Generate graphs
# ---------------------------------------------------------------------------
sep; log "STEP 4: Generate graphs"
python3 "${SCRATCH}/graphs/plot_all.py" \
    --input-dir "${SCRATCH}/output" \
    --output-dir "${SCRATCH}/graphs" \
    2>&1 | tee -a "${BATCH_LOG}"
log "Graphs generated ✓"

# ---------------------------------------------------------------------------
# Step 5: Summary report
# ---------------------------------------------------------------------------
sep; log "STEP 5: Generate summary report"

REPORT="${SCRATCH}/output/batch_report.txt"
{
echo "============================================"
echo " UAV Secure FANET — Batch Report"
echo " $(date)"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Duration:  ${DURATION}s"
echo "  Runs/sc:   ${RUNS}"
echo "  Seed base: ${SEED}"
echo "  NS3 root:  ${NS3_ROOT}"
echo ""
echo "Scenario Results:"
cat "${SCRATCH}/output/scenarios/summary.csv" 2>/dev/null || echo "  (no summary)"
echo ""
echo "Global Metrics (last run):"
cat "${SCRATCH}/output/metrics_global.csv" 2>/dev/null || echo "  (no metrics)"
echo ""
echo "Graphs Generated:"
ls "${SCRATCH}/graphs/"*.png 2>/dev/null | \
    xargs -I{} basename {} || echo "  (none)"
echo ""
echo "Output Files:"
echo "  CSV:     ${SCRATCH}/output/"
echo "  PCAP:    ${SCRATCH}/pcap/"
echo "  NetAnim: ${SCRATCH}/output/uav-fanet-anim.xml"
echo "  Graphs:  ${SCRATCH}/graphs/"
echo "  Log:     ${BATCH_LOG}"
echo ""
BATCH_END=$(date +%s)
echo "Total wall time: $(( BATCH_END - BATCH_START ))s"
echo "============================================"
} | tee "${REPORT}"

log "Report: ${REPORT} ✓"

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
BATCH_END=$(date +%s)
sep
log "BATCH COMPLETE"
log "  Wall time: $(( BATCH_END - BATCH_START ))s"
log "  Report:    ${REPORT}"
log "  Graphs:    $(ls ${SCRATCH}/graphs/*.png 2>/dev/null | wc -l) PNG files"
log "  Log:       ${BATCH_LOG}"
sep
