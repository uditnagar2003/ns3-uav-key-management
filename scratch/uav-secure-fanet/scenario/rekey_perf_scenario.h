/**
 * rekey_perf_scenario.h  — FIXED
 * Missing: #include <cstdint>, #include <string>, #include <vector>
 */

#ifndef REKEY_PERF_SCENARIO_H
#define REKEY_PERF_SCENARIO_H

#include <cstdint>
#include <string>
#include <vector>

namespace uav {
namespace scenario {

// ============================================================
// SCENARIO METRICS
// ============================================================
struct ScenarioMetrics {
    double   pdr               = 0.0;
    double   throughput_kbps   = 0.0;
    double   avg_delay_ms      = 0.0;
    double   rekey_latency_ms  = 0.0;
    uint32_t total_rekeys      = 0;
    uint32_t total_joins       = 0;
    uint32_t total_leaves      = 0;
    uint32_t total_compromises = 0;
    uint32_t total_handovers   = 0;
    double   avg_sinr_db       = 0.0;
    double   min_sinr_db       = 0.0;
    double   security_overhead = 0.0;
};

// ============================================================
// SCENARIO CONFIGURATION
// ============================================================
struct RekeyPerfScenarioConfig {
    RekeyPerfScenarioConfig();

    std::vector<uint32_t> uav_counts;
    double   duration_s;
    uint32_t runs_per_config;
    uint32_t seed_base;

    double   join_interval_s;
    double   join_start_s;
    double   leave_interval_s;
    double   leave_start_s;
    std::vector<double> compromise_times;
    std::vector<double> batch_rekey_times;
    double   handover_time_s;

    double   min_speed_mps;
    double   max_speed_mps;
    double   alpha;
    double   variance;
    double   min_alt_m;
    double   max_alt_m;

    bool        enable_netanim;
    bool        enable_pcap;
    bool        enable_flowmon;
    std::string output_dir;
};

// ============================================================
// SCENARIO CLASS
// ============================================================
class RekeyPerfScenario {
public:
    explicit RekeyPerfScenario(const RekeyPerfScenarioConfig& cfg);

    void RunAll();

    ScenarioMetrics RunSingle(
        uint32_t uav_count,
        uint32_t seed,
        uint32_t run_idx);

    uint32_t GetTotalRekeys()      const { return m_total_rekeys;      }
    uint32_t GetTotalJoins()       const { return m_total_joins;       }
    uint32_t GetTotalLeaves()      const { return m_total_leaves;      }
    uint32_t GetTotalCompromises() const { return m_total_compromises; }
    uint32_t GetTotalHandovers()   const { return m_total_handovers;   }

private:
    RekeyPerfScenarioConfig m_cfg;
    void*    m_anim;

    uint32_t m_total_rekeys;
    uint32_t m_total_joins;
    uint32_t m_total_leaves;
    uint32_t m_total_compromises;
    uint32_t m_total_handovers;

    std::vector<double> m_rekey_timestamps;
    std::vector<double> m_sinr_samples;
};

} // namespace scenario
} // namespace uav

#endif // REKEY_PERF_SCENARIO_H
