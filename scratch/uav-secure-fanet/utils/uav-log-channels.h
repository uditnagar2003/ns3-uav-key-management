/**
 * utils/uav-log-channels.h
 * Named log channels — strings used as routing keys.
 *
 * Each channel maps (via the logger configuration) to ONE log file.
 * The project specification requires these seven files; channel names
 * use the file basename (without extension) for symmetry.
 *
 * Module-specific channels can be added later — the logger registers
 * channels lazily on first use, so adding a channel is just:
 *     UAV_LOG_INFO("my-channel", "first message");
 */

#ifndef UAV_LOG_CHANNELS_H
#define UAV_LOG_CHANNELS_H

namespace uav {
namespace log {
namespace channels {

// Mandatory channels (project spec)
inline constexpr const char* CRYPTO       = "crypto";
inline constexpr const char* ROUTING      = "routing";
inline constexpr const char* MOBILITY     = "mobility";
inline constexpr const char* JAMMER       = "jammer";
inline constexpr const char* REKEY        = "rekey";
inline constexpr const char* PACKET       = "packet";
inline constexpr const char* FLOWMONITOR  = "flowmonitor";

// Useful auxiliary channels
inline constexpr const char* SYSTEM       = "system";   // bootstrap/lifecycle
inline constexpr const char* SECURITY     = "security"; // join/leave/handover
inline constexpr const char* METRICS      = "metrics";  // CSV companion

} // namespace channels
} // namespace log
} // namespace uav

#endif // UAV_LOG_CHANNELS_H