/**
 * tests/test_config_manager.cc
 * Unit test for Phase 1 Module 6: Configuration Manager
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I/usr/include \
 *       tests/test_config_manager.cc \
 *       utils/uav-error.cc \
 *       utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc \
 *       utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc \
 *       utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc \
 *       utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc \
 *       utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       utils/uav-json-loader.cc \
 *       utils/uav-json-validator.cc \
 *       utils/uav-config-manager.cc \
 *       -o tests/test_config_manager
 *
 * RUN:
 *   ./tests/test_config_manager
 */

#include "utils/uav-config-manager.h"
#include "utils/uav-logger.h"
#include "utils/uav-file-utils.h"
#include "utils/uav-constants.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace uav;

namespace {

int g_pass = 0;
int g_fail = 0;

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { \
        std::cerr << "  ASSERT_TRUE failed: " #expr \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_EQ(a, b) \
    do { if (!((a) == (b))) { \
        std::cerr << "  ASSERT_EQ failed: " #a " != " #b \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_THROWS(expr) \
    do { bool threw = false; \
        try { expr; } catch (...) { threw = true; } \
        if (!threw) { \
            std::cerr << "  ASSERT_THROWS failed: " #expr \
                      << " @ line " << __LINE__ << "\n"; \
            return false; } } while (0)

void RunTest(const std::string& name, bool (*fn)()) {
    std::cout << "[ RUN  ] " << name << "\n";
    bool ok = false;
    try { ok = fn(); }
    catch (const std::exception& ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        ok = false;
    }
    if (ok) { std::cout << "[ PASS ] " << name << "\n\n"; ++g_pass; }
    else    { std::cout << "[ FAIL ] " << name << "\n\n"; ++g_fail; }
}

// Helper — write a temp JSON file
void WriteTempJson(const std::string& path, const std::string& content) {
    utils::FileUtils::WriteTextFile(path, content);
}

// ===========================================================================
// Test 1: Defaults — no JSON loaded
// ===========================================================================
bool test_defaults() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    ASSERT_EQ(cfg.NumUavs(),         utils::constants::NUM_UAVS);
    ASSERT_EQ(cfg.NumClusters(),     utils::constants::NUM_CLUSTERS);
    ASSERT_EQ(cfg.UavsPerCluster(),  utils::constants::UAVS_PER_CLUSTER);
    ASSERT_EQ(cfg.NumSkdcs(),        utils::constants::NUM_SKDCS);
    ASSERT_EQ(cfg.RngSeed(),         utils::constants::DEFAULT_RNG_SEED);
    ASSERT_TRUE(std::abs(cfg.SimDuration() -
                utils::constants::DEFAULT_SIM_DURATION_S) < 1e-6);
    ASSERT_EQ(cfg.LogDir(),          std::string("logs"));
    ASSERT_EQ(cfg.OutputDir(),       std::string("output"));
    ASSERT_EQ(cfg.CryptoScheme(),    std::string("CRT-GCRT"));
    ASSERT_EQ(cfg.CryptoAesBits(),   256u);
    return true;
}

// ===========================================================================
// Test 2: Load sim config from file
// ===========================================================================
bool test_load_sim_config() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    const std::string path = "/tmp/uav_test_sim.json";
    WriteTempJson(path, R"({
        "topology": {
            "num_kdc": 1, "num_skdcs": 3, "num_clusters": 3,
            "uavs_per_cluster": 6, "num_uavs": 18,
            "num_jammers": 1, "max_uav_count": 30
        },
        "simulation": {
            "duration_s": 120.0, "rng_seed": 42, "runs": 5,
            "debug": true, "enable_netanim": false,
            "enable_pcap": true, "enable_flowmonitor": true
        },
        "area": {
            "x_min": 0.0, "x_max": 1000.0,
            "y_min": 0.0, "y_max": 1000.0,
            "z_min": 50.0, "z_max": 150.0
        },
        "mobility": {
            "uav_speed_min": 5.0, "uav_speed_max": 20.0,
            "uav_alt_min": 50.0, "uav_alt_max": 150.0,
            "jammer_speed": 8.0
        },
        "wireless": {
            "freq_hz": 5000000000.0, "channel_width_mhz": 20.0,
            "tx_power_dbm": 20.0, "phy_rate_mbps": 26.0,
            "jammer_power_dbm": 30.0, "sinr_threshold_db": 8.0
        },
        "olsr": { "hello_interval_s": 2.0, "tc_interval_s": 5.0 },
        "security": {
            "node_compromise_prob": 0.05,
            "replay_window_size": 64,
            "replay_skew_us": 5000000
        },
        "output": {
            "log_dir": "logs", "output_dir": "output",
            "pcap_dir": "pcap", "json_dir": "json",
            "graphs_dir": "graphs",
            "csv_interval_s": 1.0, "netanim_interval_ms": 100.0
        },
        "ports": {
            "kdc_udp": 9000, "skdc_udp": 9001,
            "uav_data_udp": 9100, "mtk_multicast": 9200
        }
    })");

    cfg.LoadSimConfig(path);

    ASSERT_TRUE(cfg.IsSimConfigLoaded());
    ASSERT_EQ(cfg.NumUavs(),      18u);
    ASSERT_EQ(cfg.NumClusters(),  3u);
    ASSERT_EQ(cfg.RngSeed(),      42u);
    ASSERT_EQ(cfg.NumRuns(),      5u);
    ASSERT_EQ(cfg.DebugMode(),    true);
    ASSERT_EQ(cfg.EnableNetAnim(),false);
    ASSERT_TRUE(std::abs(cfg.SimDuration() - 120.0) < 1e-6);
    ASSERT_TRUE(std::abs(cfg.AreaXMax()    - 1000.0) < 1e-6);
    ASSERT_TRUE(std::abs(cfg.UavSpeedMin() - 5.0)  < 1e-6);
    ASSERT_EQ(cfg.KdcUdpPort(),   9000u);
    ASSERT_EQ(cfg.SkdcUdpPort(),  9001u);

    fs::remove(path);
    return true;
}

// ===========================================================================
// Test 3: Load crypto config from file
// ===========================================================================
bool test_load_crypto_config() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    const std::string path = "/tmp/uav_test_crypto.json";
    WriteTempJson(path, R"({
        "crypto": {
            "scheme": "CRT-GCRT",
            "aes_bits": 256,
            "hmac": "SHA256",
            "key_version": 2,
            "kdc": {
                "num_safe_primes": 18,
                "prime_bits": 512,
                "master_key": "999999999999999999",
                "master_modulus": "111111111111111111"
            },
            "clusters": [
                {
                    "cluster_id": 0, "skdc_id": 0, "num_slaves": 2,
                    "master_key_eM": "123456789",
                    "master_mod_M":  "987654321",
                    "tek": "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
                    "slaves": [
                        {"uav_id": 0, "e_i": "65537", "d_i": "11111", "n_i": "99999"},
                        {"uav_id": 1, "e_i": "65539", "d_i": "22222", "n_i": "88888"}
                    ]
                },
                {
                    "cluster_id": 1, "skdc_id": 1, "num_slaves": 0,
                    "master_key_eM": "0", "master_mod_M": "0",
                    "tek": "0000000000000000000000000000000000000000000000000000000000000000",
                    "slaves": []
                }
            ]
        }
    })");

    cfg.LoadCryptoConfig(path);

    ASSERT_TRUE(cfg.IsCryptoConfigLoaded());
    ASSERT_EQ(cfg.CryptoScheme(),   std::string("CRT-GCRT"));
    ASSERT_EQ(cfg.CryptoAesBits(),  256u);
    ASSERT_EQ(cfg.KeyVersion(),     2u);
    ASSERT_EQ(cfg.NumSafePrimes(),  18u);

    const auto& c0 = cfg.ClusterCrypto(0);
    ASSERT_EQ(c0.cluster_id,    0u);
    ASSERT_EQ(c0.skdc_id,       0u);
    ASSERT_EQ(c0.master_key_eM, std::string("123456789"));
    ASSERT_EQ(c0.slaves.size(), 2u);
    ASSERT_EQ(c0.slaves[0].e_i, std::string("65537"));
    ASSERT_EQ(c0.slaves[1].uav_id, 1u);
    ASSERT_EQ(c0.slaves[1].d_i, std::string("22222"));

    const auto& c1 = cfg.ClusterCrypto(1);
    ASSERT_EQ(c1.slaves.size(), 0u);

    // Invalid cluster id throws
    ASSERT_THROWS(cfg.ClusterCrypto(99));

    fs::remove(path);
    return true;
}

// ===========================================================================
// Test 4: Missing config file — uses defaults gracefully
// ===========================================================================
bool test_missing_file_uses_defaults() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    cfg.LoadSimConfig("/tmp/does_not_exist_sim.json");
    cfg.LoadCryptoConfig("/tmp/does_not_exist_crypto.json");

    ASSERT_TRUE(cfg.IsSimConfigLoaded());
    ASSERT_TRUE(cfg.IsCryptoConfigLoaded());
    ASSERT_EQ(cfg.NumUavs(), utils::constants::NUM_UAVS);
    return true;
}

// ===========================================================================
// Test 5: CLI overrides
// ===========================================================================
bool test_cli_overrides() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    const char* argv[] = {
        "program",
        "--simDuration=90.0",
        "--RngSeed=7",
        "--runIndex=3",
        "--logDir=/tmp/custom_logs",
        "--debug",
        nullptr
    };
    int argc = 6;

    cfg.ApplyCliOverrides(argc, const_cast<char**>(argv));

    ASSERT_TRUE(std::abs(cfg.SimDuration() - 90.0) < 1e-6);
    ASSERT_EQ(cfg.RngSeed(),   7u);
    ASSERT_EQ(cfg.RunIndex(),  3u);
    ASSERT_EQ(cfg.LogDir(),    std::string("/tmp/custom_logs"));
    ASSERT_EQ(cfg.DebugMode(), true);
    return true;
}

// ===========================================================================
// Test 6: Validation — valid config passes
// ===========================================================================
bool test_validation_pass() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    // Defaults are valid — should not throw
    bool threw = false;
    try { cfg.ValidateOrThrow(); }
    catch (...) { threw = true; }
    ASSERT_TRUE(!threw);
    return true;
}

// ===========================================================================
// Test 7: Validation — invalid config throws
// ===========================================================================
bool test_validation_fail() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    const std::string path = "/tmp/uav_test_bad.json";
    WriteTempJson(path, R"({
        "topology": {
            "num_kdc": 1, "num_skdcs": 3, "num_clusters": 3,
            "uavs_per_cluster": 6, "num_uavs": 99,
            "num_jammers": 1, "max_uav_count": 30
        },
        "simulation": {
            "duration_s": -1.0, "rng_seed": 0, "runs": 1,
            "debug": false, "enable_netanim": true,
            "enable_pcap": true, "enable_flowmonitor": true
        },
        "area": {
            "x_min": 0.0, "x_max": 1500.0,
            "y_min": 0.0, "y_max": 1500.0,
            "z_min": 50.0, "z_max": 200.0
        },
        "mobility": {
            "uav_speed_min": 10.0, "uav_speed_max": 25.0,
            "uav_alt_min": 50.0, "uav_alt_max": 150.0,
            "jammer_speed": 10.0
        },
        "wireless": {
            "freq_hz": 5000000000.0, "channel_width_mhz": 20.0,
            "tx_power_dbm": 20.0, "phy_rate_mbps": 26.0,
            "jammer_power_dbm": 30.0, "sinr_threshold_db": 8.0
        },
        "olsr": { "hello_interval_s": 2.0, "tc_interval_s": 5.0 },
        "security": {
            "node_compromise_prob": 0.05,
            "replay_window_size": 64, "replay_skew_us": 5000000
        },
        "output": {
            "log_dir": "logs", "output_dir": "output",
            "pcap_dir": "pcap", "json_dir": "json",
            "graphs_dir": "graphs",
            "csv_interval_s": 1.0, "netanim_interval_ms": 100.0
        },
        "ports": {
            "kdc_udp": 9000, "skdc_udp": 9001,
            "uav_data_udp": 9100, "mtk_multicast": 9200
        }
    })");

    cfg.LoadSimConfig(path);

    // num_uavs=99 != 3*6=18, duration=-1, seed=0 -> should throw
    ASSERT_THROWS(cfg.ValidateOrThrow());

    fs::remove(path);
    return true;
}

// ===========================================================================
// Test 8: DumpResolved produces non-empty string
// ===========================================================================
bool test_dump_resolved() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    std::string dump = cfg.DumpResolved();
    ASSERT_TRUE(!dump.empty());
    ASSERT_TRUE(dump.find("num_uavs") != std::string::npos);
    ASSERT_TRUE(dump.find("CRT-GCRT") != std::string::npos);
    return true;
}

// ===========================================================================
// Test 9: Load real json/ files if they exist
// ===========================================================================
bool test_load_real_json_files() {
    auto& cfg = config::ConfigManager::Instance();
    cfg.Reset();

    if (utils::FileUtils::Exists("json/simulation_config.json")) {
        cfg.LoadSimConfig("json/simulation_config.json");
        ASSERT_TRUE(cfg.IsSimConfigLoaded());
        ASSERT_EQ(cfg.NumUavs(), 18u);
        std::cout << "  Loaded real simulation_config.json\n";
    } else {
        std::cout << "  SKIP: json/simulation_config.json not found\n";
    }

    if (utils::FileUtils::Exists("json/crypto_params.json")) {
        cfg.LoadCryptoConfig("json/crypto_params.json");
        ASSERT_TRUE(cfg.IsCryptoConfigLoaded());
        std::cout << "  Loaded real crypto_params.json\n";
    } else {
        std::cout << "  SKIP: json/crypto_params.json not found\n";
    }

    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 1 Module 6 — Configuration Manager\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_config_test_logs",
        log::LogLevel::WARN,
        false);

    RunTest("defaults",                  test_defaults);
    RunTest("load_sim_config",           test_load_sim_config);
    RunTest("load_crypto_config",        test_load_crypto_config);
    RunTest("missing_file_uses_defaults",test_missing_file_uses_defaults);
    RunTest("cli_overrides",             test_cli_overrides);
    RunTest("validation_pass",           test_validation_pass);
    RunTest("validation_fail",           test_validation_fail);
    RunTest("dump_resolved",             test_dump_resolved);
    RunTest("load_real_json_files",      test_load_real_json_files);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}