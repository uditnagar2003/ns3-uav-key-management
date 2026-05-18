/**
 * utils/uav-constants.h
 * Project-wide compile-time constants.
 *
 * Scope: HEADER-ONLY.
 *
 * These constants are referenced by the configuration manager (Module 6)
 * as DEFAULT values that can be overridden at runtime via JSON.
 * Do NOT hardcode these elsewhere — always read through ConfigManager.
 */

#ifndef UAV_CONSTANTS_H
#define UAV_CONSTANTS_H

#include "uav-types.h"

namespace uav {
namespace utils {
namespace constants {

// ===========================================================================
// Topology — fixed per project specification
// ===========================================================================
constexpr u32 NUM_KDC              = 1;
constexpr u32 NUM_SKDCS            = 3;
constexpr u32 NUM_CLUSTERS         = 3;
constexpr u32 UAVS_PER_CLUSTER     = 6;
constexpr u32 NUM_UAVS             = NUM_CLUSTERS * UAVS_PER_CLUSTER;  // 18
constexpr u32 NUM_JAMMERS          = 1;
constexpr u32 MAX_UAV_COUNT        = 30;   // upper bound for scalability runs

// ===========================================================================
// Simulation area (metres)
// ===========================================================================
constexpr double AREA_X_MIN = 0.0;
constexpr double AREA_X_MAX = 1500.0;
constexpr double AREA_Y_MIN = 0.0;
constexpr double AREA_Y_MAX = 1500.0;
constexpr double AREA_Z_MIN = 50.0;
constexpr double AREA_Z_MAX = 200.0;

// ===========================================================================
// UAV mobility
// ===========================================================================
constexpr double UAV_SPEED_MIN   = 10.0;   // m/s
constexpr double UAV_SPEED_MAX   = 25.0;   // m/s
constexpr double UAV_ALT_MIN     = 50.0;   // m
constexpr double UAV_ALT_MAX     = 150.0;  // m

// ===========================================================================
// Jammer
// ===========================================================================
constexpr double JAMMER_SPEED    = 10.0;   // m/s
constexpr double JAMMER_TX_POWER = 30.0;   // dBm

// ===========================================================================
// Wireless PHY (802.11a, 5 GHz)
// ===========================================================================
constexpr double WIFI_FREQ_HZ          = 5.0e9;
constexpr double WIFI_CHANNEL_WIDTH_MHZ = 20.0;
constexpr double WIFI_TX_POWER_DBM      = 20.0;
constexpr double WIFI_PHY_RATE_MBPS     = 26.0;

// ===========================================================================
// OLSR parameters (seconds)
// ===========================================================================
constexpr double OLSR_HELLO_INTERVAL = 2.0;
constexpr double OLSR_TC_INTERVAL    = 5.0;

// ===========================================================================
// Failure thresholds
// ===========================================================================
constexpr double SINR_FAILURE_DB         = 8.0;
constexpr double NODE_COMPROMISE_PROB    = 0.05;   // 5%

// ===========================================================================
// Packet sizes (bytes) — payload only (headers extra)
// ===========================================================================
constexpr u32 CONTROL_PACKET_BYTES = 256;
constexpr u32 REKEY_PACKET_BYTES   = 512;
constexpr u32 DATA_PACKET_BYTES    = 1024;

// ===========================================================================
// Queue
// ===========================================================================
constexpr u32 MAX_QUEUE_PACKETS = 100;

// ===========================================================================
// Simulation defaults
// ===========================================================================
constexpr double DEFAULT_SIM_DURATION_S = 180.0;
constexpr u32    DEFAULT_RNG_SEED       = 10;
constexpr u32    DEFAULT_RUNS_PER_SCENARIO = 10;

// ===========================================================================
// Crypto constants
// ===========================================================================
constexpr u32 AES_KEY_BYTES       = 32;   // 256-bit
constexpr u32 AES_BLOCK_BYTES     = 16;   // 128-bit
constexpr u32 AES_IV_BYTES        = 16;   // CBC IV
constexpr u32 AES_GCM_IV_BYTES    = 12;   // GCM IV
constexpr u32 AES_GCM_TAG_BYTES   = 16;   // GCM authentication tag
constexpr u32 HMAC_SHA256_BYTES   = 32;
constexpr u32 NONCE_BYTES         = 16;
constexpr u32 SHA256_DIGEST_BYTES = 32;

// Replay cache window
constexpr u32 REPLAY_WINDOW_SIZE = 64;     // sliding window
constexpr u64 REPLAY_TIME_SKEW_US = 5'000'000ULL;  // 5 seconds tolerance

// ===========================================================================
// NetAnim
// ===========================================================================
constexpr double NETANIM_UPDATE_INTERVAL_MS = 100.0;

// ===========================================================================
// CSV export
// ===========================================================================
constexpr double CSV_EXPORT_INTERVAL_S = 1.0;

// ===========================================================================
// Multicast address ranges (used by Module 24+)
// ===========================================================================
constexpr u32 MULTICAST_GROUP_BASE = 0xE0010001;   // 224.1.0.1
constexpr u16 KDC_UDP_PORT         = 9000;
constexpr u16 SKDC_UDP_PORT        = 9001;
constexpr u16 UAV_DATA_UDP_PORT    = 9100;
constexpr u16 MTK_MULTICAST_PORT   = 9200;

// ===========================================================================
// Magic numbers / protocol version
// ===========================================================================
constexpr u32 PROTOCOL_MAGIC   = 0x55415646;   // 'UAVF'
constexpr u16 PROTOCOL_VERSION = 0x0100;       // 1.0

// ===========================================================================
// Logging file names (relative to UAV_LOG_DIR)
// ===========================================================================
constexpr const char* LOG_FILE_CRYPTO      = "crypto.log";
constexpr const char* LOG_FILE_ROUTING     = "routing.log";
constexpr const char* LOG_FILE_MOBILITY    = "mobility.log";
constexpr const char* LOG_FILE_JAMMER      = "jammer.log";
constexpr const char* LOG_FILE_REKEY       = "rekey.log";
constexpr const char* LOG_FILE_PACKET      = "packet.log";
constexpr const char* LOG_FILE_FLOWMONITOR = "flowmonitor.log";

} // namespace constants
} // namespace utils
} // namespace uav

#endif // UAV_CONSTANTS_H