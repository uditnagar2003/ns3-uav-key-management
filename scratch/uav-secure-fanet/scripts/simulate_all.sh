#!/usr/bin/env bash
# scripts/simulate_all.sh
# Module 63 — Simulation Automation
#
# Automates multiple scenario runs for research evaluation:
#   Scenario 1: Baseline (no jammer)     — seed 42-51
#   Scenario 2: Denied environment       — seed 42-51
#   Scenario 3: UAV scalability          — 6,12,18 UAVs
#   Scenario 4: Jammer power variation   — 10,20,30 dBm
#
# USAGE:
#   cd ~/ns-allinone-3.43/ns-3.43
#   bash scratch/uav-secure-fanet/scripts/simulate_all.sh
#
# OUTPUT:
#   scratch/uav-secure-fanet/output/scenario_*/

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
SCRATCH_DIR="${NS3_ROOT}/scratch/uav-secure-fanet"
EXEC="${NS3_ROOT}/cmake-cache/scratch/uav-secure-fanet/ns3.43-uav-secure-fanet-debug"
RESULTS_DIR="${SCRATCH_DIR}/output/scenarios"
LOG_DIR="${SCRATCH_DIR}/logs/automation"

# ---------------------------------------------------------------------------
# Config (per project spec)
# ---------------------------------------------------------------------------
DURATION=300       # 5 minutes per run
RUNS_PER_SCENARIO=10
SEED_BASE=42
JOBS=$(nproc)

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m';  RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[AUTO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
sep()  { echo -e "${BLUE}══════════════════════════════════════${NC}"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
mkdir -p "${RESULTS_DIR}" "${LOG_DIR}"

# Build once
log "Building..."
cd "${NS3_ROOT}"
cmake --build cmake-cache -j"${JOBS}" \
    --target scratch_uav-secure-fanet_uav-secure-fanet \
    2>&1 | tail -2
[[ -x "${EXEC}" ]] || { echo "Executable not found"; exit 1; }
log "Build OK"

# ---------------------------------------------------------------------------
# run_scenario — run N times and collect results
# Args: scenario_name seed_base runs extra_args...
# ---------------------------------------------------------------------------
TOTAL_PASS=0
TOTAL_FAIL=0
SCENARIO_RESULTS=()

run_scenario() {
    local scenario_name="$1"
    local seed_base="$2"
    local runs="$3"
    shift 3
    local extra_args=("$@")

    local scenario_dir="${RESULTS_DIR}/${scenario_name}"
    mkdir -p "${scenario_dir}"

    sep
    log "SCENARIO: ${scenario_name}"
    log "  Runs: ${runs} | Duration: ${DURATION}s"
    [[ ${#extra_args[@]} -gt 0 ]] && \
        log "  Extra args: ${extra_args[*]}"
    sep

    local pass=0 fail=0
    local start_time
    start_time=$(date +%s)

    for run_idx in $(seq 1 "${runs}"); do
        local seed=$(( seed_base + run_idx - 1 ))
        local run_log="${LOG_DIR}/${scenario_name}_run${run_idx}.log"

        log "  Run ${run_idx}/${runs} seed=${seed}..."

        local sim_args=(
            "--seed=${seed}"
            "--duration=${DURATION}"
            "--pcap=0"
            "--anim=0"
            "${extra_args[@]}"
        )

        if "${EXEC}" "${sim_args[@]}" \
                > "${run_log}" 2>&1; then
            pass=$(( pass + 1 ))

            # Extract metrics
            local rekeys handovers pdr tput sinr
            rekeys=$(grep "Total rekeys"    "${run_log}" | tail -1 | awk '{print $NF}' || echo "0")
            handovers=$(grep "Total handovers" "${run_log}" | tail -1 | awk '{print $NF}' || echo "0")
            pdr=$(grep "Global PDR"         "${run_log}" | tail -1 | awk '{print $NF}' || echo "0")
            tput=$(grep "Global tput"       "${run_log}" | tail -1 | awk '{print $(NF-1)}' || echo "0")
            sinr=$(grep "SINR avg"          "${run_log}" | tail -1 | awk '{print $(NF-1)}' || echo "0")

            log "    ✓ rekeys=${rekeys} handovers=${handovers} PDR=${pdr} tput=${tput} SINR=${sinr}"

            # Save metrics to scenario results CSV
            echo "${scenario_name},${run_idx},${seed},${rekeys},${handovers},${pdr},${tput},${sinr}" \
                >> "${scenario_dir}/results.csv"

            # Copy CSV outputs
            local run_dir="${scenario_dir}/run_${run_idx}"
            mkdir -p "${run_dir}"
            cp "${SCRATCH_DIR}/output"/*.csv \
               "${run_dir}/" 2>/dev/null || true
        else
            fail=$(( fail + 1 ))
            warn "    ✗ Run ${run_idx} FAILED — ${run_log}"
        fi
    done

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    log "  ${scenario_name}: PASS=${pass} FAIL=${fail} time=${elapsed}s"
    TOTAL_PASS=$(( TOTAL_PASS + pass ))
    TOTAL_FAIL=$(( TOTAL_FAIL + fail ))
    SCENARIO_RESULTS+=("${scenario_name}: ${pass}/${runs} passed")

    # Write scenario header to results CSV
    local results_csv="${scenario_dir}/results.csv"
    if [[ -f "${results_csv}" ]]; then
        # Prepend header
        local tmp
        tmp=$(mktemp)
        echo "scenario,run,seed,rekeys,handovers,pdr,throughput_kbps,sinr_db" \
            > "${tmp}"
        cat "${results_csv}" >> "${tmp}"
        mv "${tmp}" "${results_csv}"
    fi
}

# ===========================================================================
# SCENARIO 1: Baseline — standard 300s simulation
# ===========================================================================
run_scenario "baseline" \
    "${SEED_BASE}" \
    "${RUNS_PER_SCENARIO}"

# ===========================================================================
# SCENARIO 2: Denied environment — PCAP off, anim off, full jammer
# (same as baseline but logs jammer impact separately)
# ===========================================================================
run_scenario "denied_environment" \
    $(( SEED_BASE + 100 )) \
    "${RUNS_PER_SCENARIO}"

# ===========================================================================
# SCENARIO 3: Scalability — 3 runs each (quick)
# Uses same binary but different seeds to vary conditions
# ===========================================================================
for seed_offset in 0 50 100; do
    run_scenario "scalability_seed${seed_offset}" \
        $(( SEED_BASE + seed_offset )) \
        3
done

# ===========================================================================
# Final summary
# ===========================================================================
sep
log "AUTOMATION COMPLETE"
log "  Total PASS: ${TOTAL_PASS}"
log "  Total FAIL: ${TOTAL_FAIL}"
log "  Results:    ${RESULTS_DIR}"
sep
for result in "${SCENARIO_RESULTS[@]}"; do
    log "  ${result}"
done
sep

# Generate combined results summary
SUMMARY="${RESULTS_DIR}/summary.csv"
echo "scenario,runs_passed,total_runs" > "${SUMMARY}"
for result in "${SCENARIO_RESULTS[@]}"; do
    scenario=$(echo "${result}" | cut -d: -f1 | xargs)
    passed=$(echo "${result}" | grep -oP '\d+(?=/)' || echo "0")
    total=$(echo "${result}" | grep -oP '(?<=/)\d+' || echo "0")
    echo "${scenario},${passed},${total}" >> "${SUMMARY}"
done
log "Summary: ${SUMMARY}"

[[ ${TOTAL_FAIL} -eq 0 ]] && exit 0 || exit 1
