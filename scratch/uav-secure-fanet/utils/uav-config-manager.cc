/**
 * utils/uav-config-manager.cc
 */

#include "uav-config-manager.h"
#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-string-utils.h"
#include "uav-file-utils.h"

#include <iostream>
#include <sstream>
#include <stdexcept>

namespace uav {
namespace config {

// ===========================================================================
// Singleton
// ===========================================================================

ConfigManager& ConfigManager::Instance() {
    static ConfigManager inst;
    return inst;
}

ConfigManager::ConfigManager() {
    LoadDefaults();
}

void ConfigManager::LoadDefaults() {
    // All member initialisers in the header already set defaults.
    // This function is a no-op placeholder for future dynamic defaults.
}

void ConfigManager::Reset() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_sim_loaded    = false;
    m_crypto_loaded = false;
    m_clusters.clear();

    // Re-apply compile-time defaults
    m_num_kdc          = utils::constants::NUM_KDC;
    m_num_skdcs        = utils::constants::NUM_SKDCS;
    m_num_clusters     = utils::constants::NUM_CLUSTERS;
    m_uavs_per_cluster = utils::constants::UAVS_PER_CLUSTER;
    m_num_uavs         = utils::constants::NUM_UAVS;
    m_num_jammers      = utils::constants::NUM_JAMMERS;
    m_max_uav_count    = utils::constants::MAX_UAV_COUNT;
    m_sim_duration     = utils::constants::DEFAULT_SIM_DURATION_S;
    m_rng_seed         = utils::constants::DEFAULT_RNG_SEED;
    m_run_index        = 1;
    m_num_runs         = utils::constants::DEFAULT_RUNS_PER_SCENARIO;
    m_debug            = false;
    m_enable_netanim   = true;
    m_enable_pcap      = true;
    m_enable_flowmonitor = true;
    m_log_dir          = "logs";
    m_output_dir       = "output";
    m_pcap_dir         = "pcap";
    m_json_dir         = "json";
    m_graphs_dir       = "graphs";
    m_crypto_scheme    = "CRT-GCRT";
    m_crypto_aes_bits  = utils::constants::AES_KEY_BYTES * 8;
    m_crypto_hmac      = "SHA256";
    m_key_version      = 1;
    m_num_safe_primes  = utils::constants::NUM_UAVS;
    m_prime_bits       = 512;
    m_kdc_udp_port     = utils::constants::KDC_UDP_PORT;
    m_skdc_udp_port    = utils::constants::SKDC_UDP_PORT;
    m_uav_data_udp_port  = utils::constants::UAV_DATA_UDP_PORT;
    m_mtk_multicast_port = utils::constants::MTK_MULTICAST_PORT;
}

// ===========================================================================
// LoadSimConfig
// ===========================================================================

void ConfigManager::LoadSimConfig(const std::string& path) {
    std::lock_guard<std::mutex> lk(m_mtx);

    if (!utils::FileUtils::Exists(path)) {
        UAV_LOG_WARN(log::channels::SYSTEM,
            "SimConfig not found at '" << path
            << "' — using compile-time defaults");
        m_sim_loaded = true;
        return;
    }

    try {
        auto loader = json::JsonLoader::FromFile(path);
        ParseSimJson(loader);
        m_sim_loaded = true;
        UAV_LOG_INFO(log::channels::SYSTEM,
                     "SimConfig loaded from '" << path << "'");
    } catch (const std::exception& ex) {
        UAV_THROW(utils::ConfigException,
                  std::string("LoadSimConfig failed: ") + ex.what());
    }
}

void ConfigManager::ParseSimJson(const json::JsonLoader& L) {
    // Topology
    m_num_kdc          = L.GetU32("topology.num_kdc",          m_num_kdc);
    m_num_skdcs        = L.GetU32("topology.num_skdcs",        m_num_skdcs);
    m_num_clusters     = L.GetU32("topology.num_clusters",     m_num_clusters);
    m_uavs_per_cluster = L.GetU32("topology.uavs_per_cluster", m_uavs_per_cluster);
    m_num_uavs         = L.GetU32("topology.num_uavs",         m_num_uavs);
    m_num_jammers      = L.GetU32("topology.num_jammers",      m_num_jammers);
    m_max_uav_count    = L.GetU32("topology.max_uav_count",    m_max_uav_count);

    // Simulation
    m_sim_duration       = L.GetDouble("simulation.duration_s",        m_sim_duration);
    m_rng_seed           = L.GetU32   ("simulation.rng_seed",          m_rng_seed);
    m_num_runs           = L.GetU32   ("simulation.runs",              m_num_runs);
    m_debug              = L.GetBool  ("simulation.debug",             m_debug);
    m_enable_netanim     = L.GetBool  ("simulation.enable_netanim",    m_enable_netanim);
    m_enable_pcap        = L.GetBool  ("simulation.enable_pcap",       m_enable_pcap);
    m_enable_flowmonitor = L.GetBool  ("simulation.enable_flowmonitor",m_enable_flowmonitor);

    // Area
    m_area_x_min = L.GetDouble("area.x_min", m_area_x_min);
    m_area_x_max = L.GetDouble("area.x_max", m_area_x_max);
    m_area_y_min = L.GetDouble("area.y_min", m_area_y_min);
    m_area_y_max = L.GetDouble("area.y_max", m_area_y_max);
    m_area_z_min = L.GetDouble("area.z_min", m_area_z_min);
    m_area_z_max = L.GetDouble("area.z_max", m_area_z_max);

    // Mobility
    m_uav_speed_min = L.GetDouble("mobility.uav_speed_min", m_uav_speed_min);
    m_uav_speed_max = L.GetDouble("mobility.uav_speed_max", m_uav_speed_max);
    m_uav_alt_min   = L.GetDouble("mobility.uav_alt_min",   m_uav_alt_min);
    m_uav_alt_max   = L.GetDouble("mobility.uav_alt_max",   m_uav_alt_max);
    m_jammer_speed  = L.GetDouble("mobility.jammer_speed",  m_jammer_speed);

    // Wireless
    m_freq_hz           = L.GetDouble("wireless.freq_hz",           m_freq_hz);
    m_channel_width_mhz = L.GetDouble("wireless.channel_width_mhz", m_channel_width_mhz);
    m_tx_power_dbm      = L.GetDouble("wireless.tx_power_dbm",      m_tx_power_dbm);
    m_phy_rate_mbps     = L.GetDouble("wireless.phy_rate_mbps",      m_phy_rate_mbps);
    m_jammer_power_dbm  = L.GetDouble("wireless.jammer_power_dbm",  m_jammer_power_dbm);
    m_sinr_threshold_db = L.GetDouble("wireless.sinr_threshold_db", m_sinr_threshold_db);

    // OLSR
    m_olsr_hello_interval = L.GetDouble("olsr.hello_interval_s", m_olsr_hello_interval);
    m_olsr_tc_interval    = L.GetDouble("olsr.tc_interval_s",    m_olsr_tc_interval);

    // Security
    m_node_compromise_prob = L.GetDouble("security.node_compromise_prob",
                                          m_node_compromise_prob);
    m_replay_window_size   = L.GetU32("security.replay_window_size",
                                       m_replay_window_size);
    m_replay_skew_us       = L.GetU64("security.replay_skew_us",
                                       m_replay_skew_us);

    // Output
    m_log_dir             = L.GetString("output.log_dir",      m_log_dir);
    m_output_dir          = L.GetString("output.output_dir",   m_output_dir);
    m_pcap_dir            = L.GetString("output.pcap_dir",     m_pcap_dir);
    m_json_dir            = L.GetString("output.json_dir",     m_json_dir);
    m_graphs_dir          = L.GetString("output.graphs_dir",   m_graphs_dir);
    m_csv_interval_s      = L.GetDouble("output.csv_interval_s",
                                         m_csv_interval_s);
    m_netanim_interval_ms = L.GetDouble("output.netanim_interval_ms",
                                         m_netanim_interval_ms);

    // Ports
    m_kdc_udp_port       = static_cast<utils::u16>(
        L.GetU32("ports.kdc_udp",       m_kdc_udp_port));
    m_skdc_udp_port      = static_cast<utils::u16>(
        L.GetU32("ports.skdc_udp",      m_skdc_udp_port));
    m_uav_data_udp_port  = static_cast<utils::u16>(
        L.GetU32("ports.uav_data_udp",  m_uav_data_udp_port));
    m_mtk_multicast_port = static_cast<utils::u16>(
        L.GetU32("ports.mtk_multicast", m_mtk_multicast_port));
}

// ===========================================================================
// LoadCryptoConfig
// ===========================================================================

void ConfigManager::LoadCryptoConfig(const std::string& path) {
    std::lock_guard<std::mutex> lk(m_mtx);

    if (!utils::FileUtils::Exists(path)) {
        UAV_LOG_WARN(log::channels::SYSTEM,
            "CryptoConfig not found at '" << path
            << "' — crypto params will be zeros until generated");
        m_crypto_loaded = true;
        return;
    }

    try {
        auto loader = json::JsonLoader::FromFile(path);
        ParseCryptoJson(loader);
        m_crypto_loaded = true;
        UAV_LOG_INFO(log::channels::CRYPTO,
                     "CryptoConfig loaded from '" << path << "'");
    } catch (const std::exception& ex) {
        UAV_THROW(utils::ConfigException,
                  std::string("LoadCryptoConfig failed: ") + ex.what());
    }
}

void ConfigManager::ParseCryptoJson(const json::JsonLoader& L) {
    m_crypto_scheme   = L.GetString("crypto.scheme",   m_crypto_scheme);
    m_crypto_aes_bits = L.GetU32   ("crypto.aes_bits", m_crypto_aes_bits);
    m_crypto_hmac     = L.GetString("crypto.hmac",     m_crypto_hmac);
    m_key_version     = L.GetU32   ("crypto.key_version", m_key_version);

    if (L.Has("crypto.kdc")) {
        m_num_safe_primes = L.GetU32("crypto.kdc.num_safe_primes",
                                      m_num_safe_primes);
        m_prime_bits      = L.GetU32("crypto.kdc.prime_bits", m_prime_bits);
    }

    // Parse clusters array
    m_clusters.clear();
    std::size_t num_clusters = L.ArraySize("crypto.clusters");
    m_clusters.reserve(num_clusters);

    for (std::size_t i = 0; i < num_clusters; ++i) {
        auto cl = L.ArrayElement("crypto.clusters", i);

        ClusterCryptoParams cp;
        cp.cluster_id    = cl.GetU32   ("cluster_id",    static_cast<utils::u32>(i));
        cp.skdc_id       = cl.GetU32   ("skdc_id",       static_cast<utils::u32>(i));
        cp.num_slaves    = cl.GetU32   ("num_slaves",    utils::constants::UAVS_PER_CLUSTER);
        cp.master_key_eM = cl.GetBigInt("master_key_eM", "0");
        cp.master_mod_M  = cl.GetBigInt("master_mod_M",  "0");
        cp.tek           = cl.GetString("tek",           std::string(64, '0'));

        // Parse slave keys
        std::size_t num_slaves = cl.ArraySize("slaves");
        cp.slaves.reserve(num_slaves);

        for (std::size_t j = 0; j < num_slaves; ++j) {
            auto sl = cl.ArrayElement("slaves", j);
            SlaveKeyParams sk;
            sk.uav_id = sl.GetU32   ("uav_id", static_cast<utils::u32>(j));
            sk.e_i    = sl.GetBigInt("e_i",    "65537");
            sk.d_i    = sl.GetBigInt("d_i",    "0");
            sk.n_i    = sl.GetBigInt("n_i",    "0");
            cp.slaves.push_back(std::move(sk));
        }

        m_clusters.push_back(std::move(cp));
    }
}

// ===========================================================================
// ApplyCliOverrides
// ===========================================================================

void ConfigManager::ApplyCliOverrides(int argc, char* argv[]) {
    std::lock_guard<std::mutex> lk(m_mtx);

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        // Strip leading --
        if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-') {
            arg = arg.substr(2);
        } else {
            continue;
        }

        // Split on '='
        auto eq = arg.find('=');
        if (eq == std::string::npos) {
            // Flag without value
            if (arg == "debug") { m_debug = true; continue; }
            continue;
        }

        std::string key = arg.substr(0, eq);
        std::string val = arg.substr(eq + 1);

        try {
            if      (key == "simDuration")  m_sim_duration  = std::stod(val);
            else if (key == "RngSeed")      m_rng_seed      = static_cast<utils::u32>(std::stoul(val));
            else if (key == "runIndex")     m_run_index     = static_cast<utils::u32>(std::stoul(val));
            else if (key == "logDir")       m_log_dir       = val;
            else if (key == "outputDir")    m_output_dir    = val;
            else if (key == "pcapDir")      m_pcap_dir      = val;
            else if (key == "jsonDir")      m_json_dir      = val;
            else if (key == "numUavs")      m_num_uavs      = static_cast<utils::u32>(std::stoul(val));
            else if (key == "debug")        m_debug         = (val == "true" || val == "1");
            else {
                UAV_LOG_WARN(log::channels::SYSTEM,
                             "Unknown CLI arg: '--" << key << "'");
            }
        } catch (const std::exception& ex) {
            UAV_LOG_WARN(log::channels::SYSTEM,
                         "CLI override parse error for '--" << key
                         << "=" << val << "': " << ex.what());
        }
    }

    UAV_LOG_INFO(log::channels::SYSTEM,
                 "CLI overrides applied (seed=" << m_rng_seed
                 << " run=" << m_run_index
                 << " dur=" << m_sim_duration << "s)");
}

// ===========================================================================
// ValidateOrThrow
// ===========================================================================

void ConfigManager::ValidateOrThrow() const {
    std::lock_guard<std::mutex> lk(m_mtx);

    std::vector<std::string> errors;

    // Topology sanity
    if (m_num_uavs == 0) {
        errors.push_back("num_uavs must be > 0");
    }
    if (m_num_clusters == 0) {
        errors.push_back("num_clusters must be > 0");
    }
    if (m_uavs_per_cluster == 0) {
        errors.push_back("uavs_per_cluster must be > 0");
    }
    if (m_num_uavs != m_num_clusters * m_uavs_per_cluster) {
        errors.push_back(
            "num_uavs (" + std::to_string(m_num_uavs) +
            ") != num_clusters * uavs_per_cluster (" +
            std::to_string(m_num_clusters) + " * " +
            std::to_string(m_uavs_per_cluster) + ")");
    }
    if (m_num_skdcs != m_num_clusters) {
        errors.push_back(
            "num_skdcs (" + std::to_string(m_num_skdcs) +
            ") must equal num_clusters (" +
            std::to_string(m_num_clusters) + ")");
    }

    // Simulation sanity
    if (m_sim_duration <= 0.0) {
        errors.push_back("sim_duration must be > 0");
    }
    if (m_rng_seed == 0) {
        errors.push_back("rng_seed must be > 0");
    }

    // Area sanity
    if (m_area_x_max <= m_area_x_min ||
        m_area_y_max <= m_area_y_min ||
        m_area_z_max <= m_area_z_min) {
        errors.push_back("area max must be > area min on all axes");
    }

    // Wireless sanity
    if (m_sinr_threshold_db < 0.0) {
        errors.push_back("sinr_threshold_db must be >= 0");
    }

    // Crypto sanity
    if (m_crypto_aes_bits != 128 && m_crypto_aes_bits != 256) {
        errors.push_back("crypto.aes_bits must be 128 or 256");
    }

    if (!errors.empty()) {
        std::string msg = "ConfigManager validation failed ("
                        + std::to_string(errors.size()) + " error(s)):\n";
        for (const auto& e : errors) {
            msg += "  - " + e + "\n";
        }
        UAV_THROW(utils::ConfigException, msg);
    }

    UAV_LOG_INFO(log::channels::SYSTEM,
                 "ConfigManager validation PASSED ("
                 << m_num_uavs << " UAVs, "
                 << m_num_clusters << " clusters, "
                 << m_sim_duration << "s)");
}

// ===========================================================================
// ClusterCrypto accessor
// ===========================================================================

const ClusterCryptoParams&
ConfigManager::ClusterCrypto(utils::u32 cluster_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (const auto& cp : m_clusters) {
        if (cp.cluster_id == cluster_id) return cp;
    }
    UAV_THROW(utils::ConfigException,
              "ClusterCrypto: cluster_id " +
              std::to_string(cluster_id) + " not found");
}

// ===========================================================================
// DumpResolved
// ===========================================================================

std::string ConfigManager::DumpResolved() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"topology\": {\n";
    oss << "    \"num_uavs\": "         << m_num_uavs         << ",\n";
    oss << "    \"num_clusters\": "     << m_num_clusters     << ",\n";
    oss << "    \"uavs_per_cluster\": " << m_uavs_per_cluster << ",\n";
    oss << "    \"num_skdcs\": "        << m_num_skdcs        << "\n";
    oss << "  },\n";
    oss << "  \"simulation\": {\n";
    oss << "    \"duration_s\": "  << m_sim_duration << ",\n";
    oss << "    \"rng_seed\": "    << m_rng_seed     << ",\n";
    oss << "    \"run_index\": "   << m_run_index    << ",\n";
    oss << "    \"debug\": "       << (m_debug ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"output\": {\n";
    oss << "    \"log_dir\": \""    << m_log_dir    << "\",\n";
    oss << "    \"output_dir\": \"" << m_output_dir << "\",\n";
    oss << "    \"pcap_dir\": \""   << m_pcap_dir   << "\"\n";
    oss << "  },\n";
    oss << "  \"crypto\": {\n";
    oss << "    \"scheme\": \""     << m_crypto_scheme   << "\",\n";
    oss << "    \"aes_bits\": "     << m_crypto_aes_bits << ",\n";
    oss << "    \"num_clusters\": " << m_clusters.size() << "\n";
    oss << "  }\n";
    oss << "}\n";
    return oss.str();
}

} // namespace config
} // namespace uav