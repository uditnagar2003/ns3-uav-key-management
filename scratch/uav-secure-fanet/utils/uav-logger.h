/**
 * utils/uav-logger.h
 *
 * Project-wide logger.
 *
 * Usage:
 *
 *   // One-time bootstrap (Module 60 main.cc — but tests can also call):
 *   uav::log::Logger::Instance().Initialize("logs", uav::log::LogLevel::INFO);
 *
 *   // Anywhere:
 *   UAV_LOG_INFO  (uav::log::channels::SYSTEM, "Starting simulation");
 *   UAV_LOG_DEBUG (uav::log::channels::CRYPTO, "TEK rotated v=%u", v);
 *   UAV_LOG_WARN  (uav::log::channels::PACKET, "HMAC mismatch from " << id);
 *
 *   // Shutdown (flushes and closes files):
 *   uav::log::Logger::Instance().Shutdown();
 *
 * Two macro families:
 *   UAV_LOG_<LEVEL>(channel, ...)        — printf-style or stream-style
 *   UAV_LOGF_<LEVEL>(channel, fmt, ...)  — explicit printf-style
 *
 * Default channel-to-file mapping (created on Initialize()):
 *   crypto      -> logs/crypto.log
 *   routing     -> logs/routing.log
 *   mobility    -> logs/mobility.log
 *   jammer      -> logs/jammer.log
 *   rekey       -> logs/rekey.log
 *   packet      -> logs/packet.log
 *   flowmonitor -> logs/flowmonitor.log
 *   system      -> logs/system.log
 *   security    -> logs/security.log
 *   metrics     -> logs/metrics.log
 *
 * Any channel name not explicitly mapped logs to console only.
 * Use BindChannelToFile() to add custom mappings.
 *
 * NS-3 bridge:
 *   The logger DOES NOT replace NS-3's NS_LOG. NS-3 internal modules
 *   continue to use NS_LOG as usual. The project's own code uses
 *   UAV_LOG_*. When NS-3 logs are enabled via NS_LOG env var, both
 *   appear on stderr — that's intentional.
 */

#ifndef UAV_LOGGER_H
#define UAV_LOGGER_H

#include "uav-log-level.h"
#include "uav-log-sink.h"

#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace uav {
namespace log {

// ===========================================================================
// Logger — singleton
// ===========================================================================
class Logger {
public:
    static Logger& Instance();

    // -----------------------------------------------------------------------
    // Bootstrap
    // -----------------------------------------------------------------------
    /// Initialize with a log directory and global minimum level.
    /// Creates console sink + the ten default channel→file mappings.
    /// Idempotent: re-calls reconfigure level/dir but do not duplicate sinks.
    void Initialize(const std::string& log_dir,
                    LogLevel global_level = LogLevel::INFO,
                    bool enable_console = true,
                    bool console_colour = true);

    /// Flush and close all sinks. Safe to call multiple times.
    void Shutdown();

    bool IsInitialized() const { return m_initialized; }
    const std::string& LogDir() const { return m_log_dir; }

    // -----------------------------------------------------------------------
    // Filtering
    // -----------------------------------------------------------------------
    void SetGlobalLevel(LogLevel l);
    LogLevel GlobalLevel() const { return m_global_level; }

    /// Override per-channel minimum level. Returns previous value.
    LogLevel SetChannelLevel(const std::string& channel, LogLevel l);
    LogLevel ChannelLevel(const std::string& channel) const;

    /// Fast check — used by macros to avoid stream formatting work.
    bool ShouldLog(const std::string& channel, LogLevel l) const;

    // -----------------------------------------------------------------------
    // Channel routing
    // -----------------------------------------------------------------------
    /// Route a channel to an additional file (absolute or relative path).
    /// If relative, prepended with the log directory.
    /// A channel may have multiple file sinks attached.
    void BindChannelToFile(const std::string& channel,
                           const std::string& filename);

    /// Disable console output for one specific channel (e.g. very chatty
    /// packet logs go to file only).
    void SetChannelConsoleEnabled(const std::string& channel, bool enabled);

    // -----------------------------------------------------------------------
    // Logging entry point — used by macros.
    //
    // The variant taking std::string is the "real" one. The macros below
    // build the string lazily so callers don't pay formatting cost when
    // the message is filtered out.
    // -----------------------------------------------------------------------
    void Log(LogLevel level,
             const std::string& channel,
             const char* file,
             int line,
             const char* func,
             std::string message);

    /// printf-style variant — internally calls StringUtils::Format.
    void Logf(LogLevel level,
              const std::string& channel,
              const char* file,
              int line,
              const char* func,
              const char* fmt,
              ...) __attribute__((format(printf, 7, 8)));

private:
    Logger();
    ~Logger();

    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;

    struct ChannelConfig {
        LogLevel              level          = LogLevel::TRACE;
        bool                  console_enabled = true;
        std::vector<FileSink*> file_sinks;     // non-owning; owned by m_file_sinks
    };

    void EnsureChannel(const std::string& channel);   // requires m_mtx held
    void DispatchUnlocked(const LogRecord& rec,
                          const ChannelConfig& cfg);

    // Mutable so const accessors can lock.
    mutable std::mutex                                 m_mtx;
    bool                                               m_initialized   = false;
    std::string                                        m_log_dir       = "logs";
    LogLevel                                           m_global_level  = LogLevel::INFO;

    std::unique_ptr<ConsoleSink>                       m_console;
    std::vector<std::unique_ptr<FileSink>>             m_file_sinks;
    std::unordered_map<std::string, ChannelConfig>     m_channels;
};

} // namespace log
} // namespace uav

// ===========================================================================
// Macros — primary user API
// ===========================================================================

// Stream-style: UAV_LOG_INFO("chan", "x=" << x << " y=" << y);
#define UAV_LOG(level, channel, expr)                                          \
    do {                                                                       \
        auto& __uav_logger = ::uav::log::Logger::Instance();                   \
        if (__uav_logger.ShouldLog((channel), (level))) {                      \
            std::ostringstream __uav_oss;                                      \
            __uav_oss << expr;                                                 \
            __uav_logger.Log((level), (channel),                               \
                __FILE__, __LINE__, __func__, __uav_oss.str());                \
        }                                                                      \
    } while (0)

#define UAV_LOG_TRACE(channel, expr)  UAV_LOG(::uav::log::LogLevel::TRACE, channel, expr)
#define UAV_LOG_DEBUG(channel, expr)  UAV_LOG(::uav::log::LogLevel::DEBUG, channel, expr)
#define UAV_LOG_INFO(channel, expr)   UAV_LOG(::uav::log::LogLevel::INFO,  channel, expr)
#define UAV_LOG_WARN(channel, expr)   UAV_LOG(::uav::log::LogLevel::WARN,  channel, expr)
#define UAV_LOG_ERROR(channel, expr)  UAV_LOG(::uav::log::LogLevel::ERROR, channel, expr)
#define UAV_LOG_FATAL(channel, expr)  UAV_LOG(::uav::log::LogLevel::FATAL, channel, expr)

// printf-style: UAV_LOGF_INFO("chan", "x=%d y=%.2f", x, y);
#define UAV_LOGF(level, channel, ...)                                          \
    do {                                                                       \
        auto& __uav_logger = ::uav::log::Logger::Instance();                   \
        if (__uav_logger.ShouldLog((channel), (level))) {                      \
            __uav_logger.Logf((level), (channel),                              \
                __FILE__, __LINE__, __func__, __VA_ARGS__);                    \
        }                                                                      \
    } while (0)

#define UAV_LOGF_TRACE(channel, ...) UAV_LOGF(::uav::log::LogLevel::TRACE, channel, __VA_ARGS__)
#define UAV_LOGF_DEBUG(channel, ...) UAV_LOGF(::uav::log::LogLevel::DEBUG, channel, __VA_ARGS__)
#define UAV_LOGF_INFO(channel,  ...) UAV_LOGF(::uav::log::LogLevel::INFO,  channel, __VA_ARGS__)
#define UAV_LOGF_WARN(channel,  ...) UAV_LOGF(::uav::log::LogLevel::WARN,  channel, __VA_ARGS__)
#define UAV_LOGF_ERROR(channel, ...) UAV_LOGF(::uav::log::LogLevel::ERROR, channel, __VA_ARGS__)
#define UAV_LOGF_FATAL(channel, ...) UAV_LOGF(::uav::log::LogLevel::FATAL, channel, __VA_ARGS__)

#endif // UAV_LOGGER_H