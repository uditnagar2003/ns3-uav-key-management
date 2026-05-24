/**
 * rekey_perf_scenario.h
 * ============================================================
 * SCENARIO: Rekey Performance + Scalability + Security
 * ============================================================
 */

#ifndef REKEY_PERF_SCENARIO_H
#define REKEY_PERF_SCENARIO_H

#include <string>
#include <vector>

namespace uav {
namespace scenario {

// ============================================================
// SCENARIO METRICS (returned per run)
// ============================================================
struct ScenarioMetrics {
    double   pdr              = 0.0;
    double   throughput_kbps  = 0.0;
    double   avg_delay_ms     = 0.0;
    double   rekey_latency_ms = 0.0;
    uint32_t total_rekeys     = 0;
    uint32_t total_joins      = 0;
    uint32_t total_leaves     = 0;
    uint32_t total_compromises= 0;
    uint32_t total_handovers  = 0;
    double   avg_sinr_db      = 0.0;
    double   min_sinr_db      = 0.0;
    double   security_overhead= 0.0; // events/second
};

// ============================================================
// SCENARIO CONFIGURATION
// ============================================================
struct RekeyPerfScenarioConfig {
    RekeyPerfScenarioConfig(); // defaults in .cc

    // UAV sweep
    std::vector<uint32_t> uav_counts;    // e.g. {6,12,18,24,30}
    double   duration_s;                 // 600s
    uint32_t runs_per_config;            // 5
    uint32_t seed_base;                  // 42

    // Event schedule
    double   join_interval_s;            // 10s
    double   join_start_s;              // 20s
    double   leave_interval_s;           // 15s
    double   leave_start_s;             // 25s
    std::vector<double> compromise_times;// {50,120,200}
    std::vector<double> batch_rekey_times;// {60,130,210,300}
    double   handover_time_s;            // 80s

    // Mobility (cluster-stay tuned)
    double   min_speed_mps;             // 10
    double   max_speed_mps;             // 20
    double   alpha;                     // 0.90 (high = stays)
    double   variance;                  // 1.5  (low = stays)
    double   min_alt_m;                 // 50
    double   max_alt_m;                 // 150

    // Output
    bool     enable_netanim;
    bool     enable_pcap;
    bool     enable_flowmon;
    std::string output_dir;
};

// ============================================================
// SCENARIO CLASS
// ============================================================
class RekeyPerfScenario {
public:
    explicit RekeyPerfScenario(
        const RekeyPerfScenarioConfig& cfg);

    /// Run ALL UAV count configurations
    void RunAll();

    /// Run single configuration
    ScenarioMetrics RunSingle(
        uint32_t uav_count,
        uint32_t seed,
        uint32_t run_idx);

    // Accessors for current run counters
    uint32_t GetTotalRekeys()      const { return m_total_rekeys;      }
    uint32_t GetTotalJoins()       const { return m_total_joins;       }
    uint32_t GetTotalLeaves()      const { return m_total_leaves;      }
    uint32_t GetTotalCompromises() const { return m_total_compromises; }
    uint32_t GetTotalHandovers()   const { return m_total_handovers;   }

private:
    RekeyPerfScenarioConfig m_cfg;
    void*    m_anim;       // AnimationInterface*

    // Counters (reset per run)
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
