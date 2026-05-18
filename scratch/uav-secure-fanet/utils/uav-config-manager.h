/**
 * utils/uav-config-manager.h
 *
 * Singleton configuration manager for the UAV Secure FANET project.
 *
 * Responsibilities:
 *   - Load simulation_config.json at startup
 *   - Load crypto_params.json at startup
 *   - Expose typed accessors for ALL project constants
 *   - Allow CLI argument overrides (passed from main.cc)
 *   - Validate all required keys before simulation starts
 *   - Provide runtime defaults matching uav-constants.h
 *
 * Usage:
 *   // In main.cc (Module 60):
 *   auto& cfg = uav::config::ConfigManager::Instance();
 *   cfg.LoadSimConfig("json/simulation_config.json");
 *   cfg.LoadCryptoConfig("json/crypto_params.json");
 *   cfg.ApplyCliOverrides(argc, argv);
 *   cfg.ValidateOrThrow();
 *
 *   // Anywhere:
 *   u32    n    = cfg.NumUavs();
 *   double dur  = cfg.SimDuration();
 *   std::string key = cfg.CryptoMasterKey(0);
 */

#ifndef UAV_CONFIG_MANAGER_H
#define UAV_CONFIG_MANAGER_H

#include "uav-types.h"
#include "uav-constants.h"
#include "uav-json-loader.h"
#include "uav-json-validator.h"

#include <mutex>
#include <string>
#include <vector>

namespace uav {
namespace config {

// ===========================================================================
// SlaveKeyParams — per-UAV CRT key parameters loaded from crypto JSON
// ===========================================================================
struct SlaveKeyParams {
    utils::u32  uav_id  = 0;
    std::string e_i;    // public exponent (decimal string)
    std::string d_i;    // private exponent (decimal string)
    std::string n_i;    // modulus (decimal string)
};

// ===========================================================================
// ClusterCryptoParams — per-cluster CRT parameters
// ===========================================================================
struct ClusterCryptoParams {
    utils::u32  cluster_id    = 0;
    utils::u32  skdc_id       = 0;
    utils::u32  num_slaves    = 0;
    std::string master_key_eM;  // decimal string
    std::string master_mod_M;   // decimal string
    std::string tek;            // hex string (64 chars = 32 bytes)
    std::vector<SlaveKeyParams> slaves;
};

// ===========================================================================
// ConfigManager — singleton
// ===========================================================================
class ConfigManager {
public:
    static ConfigManager& Instance();

    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------
    /// Load simulation config JSON. Uses defaults if file not found.
    void LoadSimConfig(const std::string& path);

    /// Load crypto params JSON. Required before simulation starts.
    void LoadCryptoConfig(const std::string& path);

    /// Apply command-line overrides.
    /// Supported flags:
    ///   --simDuration=<s>
    ///   --RngSeed=<n>
    ///   --runIndex=<n>
    ///   --logDir=<path>
    ///   --outputDir=<path>
    ///   --pcapDir=<path>
    ///   --jsonDir=<path>
    ///   --debug
    void ApplyCliOverrides(int argc, char* argv[]);

    /// Validate all required fields. Throws ConfigException on failure.
    void ValidateOrThrow() const;

    bool IsSimConfigLoaded()    const { return m_sim_loaded; }
    bool IsCryptoConfigLoaded() const { return m_crypto_loaded; }

    // -----------------------------------------------------------------------
    // Topology accessors
    // -----------------------------------------------------------------------
    utils::u32 NumKdc()           const { return m_num_kdc; }
    utils::u32 NumSkdcs()         const { return m_num_skdcs; }
    utils::u32 NumClusters()      const { return m_num_clusters; }
    utils::u32 UavsPerCluster()   const { return m_uavs_per_cluster; }
    utils::u32 NumUavs()          const { return m_num_uavs; }
    utils::u32 NumJammers()       const { return m_num_jammers; }
    utils::u32 MaxUavCount()      const { return m_max_uav_count; }

    // -----------------------------------------------------------------------
    // Simulation accessors
    // -----------------------------------------------------------------------
    double     SimDuration()      const { return m_sim_duration; }
    utils::u32 RngSeed()          const { return m_rng_seed; }
    utils::u32 RunIndex()         const { return m_run_index; }
    utils::u32 NumRuns()          const { return m_num_runs; }
    bool       DebugMode()        const { return m_debug; }
    bool       EnableNetAnim()    const { return m_enable_netanim; }
    bool       EnablePcap()       const { return m_enable_pcap; }
    bool       EnableFlowMonitor()const { return m_enable_flowmonitor; }

    // -----------------------------------------------------------------------
    // Area accessors
    // -----------------------------------------------------------------------
    double AreaXMin() const { return m_area_x_min; }
    double AreaXMax() const { return m_area_x_max; }
    double AreaYMin() const { return m_area_y_min; }
    double AreaYMax() const { return m_area_y_max; }
    double AreaZMin() const { return m_area_z_min; }
    double AreaZMax() const { return m_area_z_max; }

    // -----------------------------------------------------------------------
    // Mobility accessors
    // -----------------------------------------------------------------------
    double UavSpeedMin()  const { return m_uav_speed_min; }
    double UavSpeedMax()  const { return m_uav_speed_max; }
    double UavAltMin()    const { return m_uav_alt_min; }
    double UavAltMax()    const { return m_uav_alt_max; }
    double JammerSpeed()  const { return m_jammer_speed; }

    // -----------------------------------------------------------------------
    // Wireless accessors
    // -----------------------------------------------------------------------
    double FreqHz()           const { return m_freq_hz; }
    double ChannelWidthMHz()  const { return m_channel_width_mhz; }
    double TxPowerDbm()       const { return m_tx_power_dbm; }
    double PhyRateMbps()      const { return m_phy_rate_mbps; }
    double JammerPowerDbm()   const { return m_jammer_power_dbm; }
    double SinrThresholdDb()  const { return m_sinr_threshold_db; }

    // -----------------------------------------------------------------------
    // OLSR accessors
    // -----------------------------------------------------------------------
    double OlsrHelloInterval() const { return m_olsr_hello_interval; }
    double OlsrTcInterval()    const { return m_olsr_tc_interval; }

    // -----------------------------------------------------------------------
    // Security accessors
    // -----------------------------------------------------------------------
    double     NodeCompromiseProb() const { return m_node_compromise_prob; }
    utils::u32 ReplayWindowSize()   const { return m_replay_window_size; }
    utils::u64 ReplaySkewUs()       const { return m_replay_skew_us; }

    // -----------------------------------------------------------------------
    // Output path accessors
    // -----------------------------------------------------------------------
    const std::string& LogDir()     const { return m_log_dir; }
    const std::string& OutputDir()  const { return m_output_dir; }
    const std::string& PcapDir()    const { return m_pcap_dir; }
    const std::string& JsonDir()    const { return m_json_dir; }
    const std::string& GraphsDir()  const { return m_graphs_dir; }
    double CsvIntervalS()           const { return m_csv_interval_s; }
    double NetAnimIntervalMs()      const { return m_netanim_interval_ms; }

    // -----------------------------------------------------------------------
    // Port accessors
    // -----------------------------------------------------------------------
    utils::u16 KdcUdpPort()       const { return m_kdc_udp_port; }
    utils::u16 SkdcUdpPort()      const { return m_skdc_udp_port; }
    utils::u16 UavDataUdpPort()   const { return m_uav_data_udp_port; }
    utils::u16 MtkMulticastPort() const { return m_mtk_multicast_port; }

    // -----------------------------------------------------------------------
    // Crypto accessors
    // -----------------------------------------------------------------------
    const std::string& CryptoScheme()    const { return m_crypto_scheme; }
    utils::u32         CryptoAesBits()   const { return m_crypto_aes_bits; }
    const std::string& CryptoHmac()      const { return m_crypto_hmac; }
    utils::u32         KeyVersion()      const { return m_key_version; }
    utils::u32         NumSafePrimes()   const { return m_num_safe_primes; }
    utils::u32         PrimeBits()       const { return m_prime_bits; }

    /// Get cluster crypto parameters by cluster index.
    /// Throws if index out of range.
    const ClusterCryptoParams& ClusterCrypto(utils::u32 cluster_id) const;

    /// Get all cluster crypto params.
    const std::vector<ClusterCryptoParams>& AllClusterCrypto() const {
        return m_clusters;
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------
    /// Dump full resolved config as JSON string (for logging).
    std::string DumpResolved() const;

    /// Reset to defaults (used in unit tests).
    void Reset();

private:
    ConfigManager();
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&)            = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    void LoadDefaults();
    void ParseSimJson(const json::JsonLoader& loader);
    void ParseCryptoJson(const json::JsonLoader& loader);

    mutable std::mutex m_mtx;

    bool m_sim_loaded    = false;
    bool m_crypto_loaded = false;

    // ---- Topology ----
    utils::u32 m_num_kdc          = utils::constants::NUM_KDC;
    utils::u32 m_num_skdcs        = utils::constants::NUM_SKDCS;
    utils::u32 m_num_clusters     = utils::constants::NUM_CLUSTERS;
    utils::u32 m_uavs_per_cluster = utils::constants::UAVS_PER_CLUSTER;
    utils::u32 m_num_uavs         = utils::constants::NUM_UAVS;
    utils::u32 m_num_jammers      = utils::constants::NUM_JAMMERS;
    utils::u32 m_max_uav_count    = utils::constants::MAX_UAV_COUNT;

    // ---- Simulation ----
    double     m_sim_duration        = utils::constants::DEFAULT_SIM_DURATION_S;
    utils::u32 m_rng_seed            = utils::constants::DEFAULT_RNG_SEED;
    utils::u32 m_run_index           = 1;
    utils::u32 m_num_runs            = utils::constants::DEFAULT_RUNS_PER_SCENARIO;
    bool       m_debug               = false;
    bool       m_enable_netanim      = true;
    bool       m_enable_pcap         = true;
    bool       m_enable_flowmonitor  = true;

    // ---- Area ----
    double m_area_x_min = utils::constants::AREA_X_MIN;
    double m_area_x_max = utils::constants::AREA_X_MAX;
    double m_area_y_min = utils::constants::AREA_Y_MIN;
    double m_area_y_max = utils::constants::AREA_Y_MAX;
    double m_area_z_min = utils::constants::AREA_Z_MIN;
    double m_area_z_max = utils::constants::AREA_Z_MAX;

    // ---- Mobility ----
    double m_uav_speed_min = utils::constants::UAV_SPEED_MIN;
    double m_uav_speed_max = utils::constants::UAV_SPEED_MAX;
    double m_uav_alt_min   = utils::constants::UAV_ALT_MIN;
    double m_uav_alt_max   = utils::constants::UAV_ALT_MAX;
    double m_jammer_speed  = utils::constants::JAMMER_SPEED;

    // ---- Wireless ----
    double m_freq_hz           = utils::constants::WIFI_FREQ_HZ;
    double m_channel_width_mhz = utils::constants::WIFI_CHANNEL_WIDTH_MHZ;
    double m_tx_power_dbm      = utils::constants::WIFI_TX_POWER_DBM;
    double m_phy_rate_mbps     = utils::constants::WIFI_PHY_RATE_MBPS;
    double m_jammer_power_dbm  = utils::constants::JAMMER_TX_POWER;
    double m_sinr_threshold_db = utils::constants::SINR_FAILURE_DB;

    // ---- OLSR ----
    double m_olsr_hello_interval = utils::constants::OLSR_HELLO_INTERVAL;
    double m_olsr_tc_interval    = utils::constants::OLSR_TC_INTERVAL;

    // ---- Security ----
    double     m_node_compromise_prob = utils::constants::NODE_COMPROMISE_PROB;
    utils::u32 m_replay_window_size   = utils::constants::REPLAY_WINDOW_SIZE;
    utils::u64 m_replay_skew_us       = utils::constants::REPLAY_TIME_SKEW_US;

    // ---- Output ----
    std::string m_log_dir              = "logs";
    std::string m_output_dir           = "output";
    std::string m_pcap_dir             = "pcap";
    std::string m_json_dir             = "json";
    std::string m_graphs_dir           = "graphs";
    double      m_csv_interval_s       = utils::constants::CSV_EXPORT_INTERVAL_S;
    double      m_netanim_interval_ms  = utils::constants::NETANIM_UPDATE_INTERVAL_MS;

    // ---- Ports ----
    utils::u16 m_kdc_udp_port       = utils::constants::KDC_UDP_PORT;
    utils::u16 m_skdc_udp_port      = utils::constants::SKDC_UDP_PORT;
    utils::u16 m_uav_data_udp_port  = utils::constants::UAV_DATA_UDP_PORT;
    utils::u16 m_mtk_multicast_port = utils::constants::MTK_MULTICAST_PORT;

    // ---- Crypto ----
    std::string m_crypto_scheme   = "CRT-GCRT";
    utils::u32  m_crypto_aes_bits = utils::constants::AES_KEY_BYTES * 8;
    std::string m_crypto_hmac     = "SHA256";
    utils::u32  m_key_version     = 1;
    utils::u32  m_num_safe_primes = utils::constants::NUM_UAVS;
    utils::u32  m_prime_bits      = 512;

    std::vector<ClusterCryptoParams> m_clusters;
};

} // namespace config
} // namespace uav

#endif // UAV_CONFIG_MANAGER_H