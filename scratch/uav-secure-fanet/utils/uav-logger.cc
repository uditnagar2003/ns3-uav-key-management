/**
 * utils/uav-logger.cc
 */

#include "uav-logger.h"
#include "uav-log-channels.h"
#include "uav-time-utils.h"
#include "uav-string-utils.h"
#include "uav-file-utils.h"

#include <cstdarg>
#include <cstdio>
#include <iostream>

namespace uav {
namespace log {

// ===========================================================================
// Singleton
// ===========================================================================

Logger& Logger::Instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() = default;

Logger::~Logger() {
    try {
        Shutdown();
    } catch (...) {
        // swallow
    }
}

// ===========================================================================
// Initialize / Shutdown
// ===========================================================================

void Logger::Initialize(const std::string& log_dir,
                        LogLevel global_level,
                        bool enable_console,
                        bool console_colour) {
    std::lock_guard<std::mutex> lk(m_mtx);

    // Reset sinks if log directory changes (e.g. between unit tests)
    if (m_initialized && m_log_dir != log_dir) {
        m_file_sinks.clear();
        m_channels.clear();
        m_console.reset();
        m_initialized = false;
    }

    m_log_dir      = log_dir;
    m_global_level = global_level;

    try {
        utils::FileUtils::MkdirRecursive(m_log_dir);
    } catch (...) {
        std::cerr << "[uav-log] WARNING: cannot create log dir '"
                  << m_log_dir << "'\n";
    }

    if (enable_console && !m_console) {
        m_console = std::make_unique<ConsoleSink>(console_colour);
        m_console->SetMinLevel(global_level);
    } else if (m_console) {
        m_console->SetMinLevel(global_level);
        m_console->SetColourEnabled(console_colour);
    }

    if (!m_initialized) {
        struct Mapping { const char* ch; const char* file; };
        const Mapping defaults[] = {
            { channels::CRYPTO,      "crypto.log"      },
            { channels::ROUTING,     "routing.log"     },
            { channels::MOBILITY,    "mobility.log"    },
            { channels::JAMMER,      "jammer.log"      },
            { channels::REKEY,       "rekey.log"       },
            { channels::PACKET,      "packet.log"      },
            { channels::FLOWMONITOR, "flowmonitor.log" },
            { channels::SYSTEM,      "system.log"      },
            { channels::SECURITY,    "security.log"    },
            { channels::METRICS,     "metrics.log"     },
        };
        for (const auto& m : defaults) {
            EnsureChannel(m.ch);
            std::string full = utils::FileUtils::JoinPath(m_log_dir, m.file);
            auto sink = std::make_unique<FileSink>(full);
            sink->SetMinLevel(global_level);
            m_channels[m.ch].file_sinks.push_back(sink.get());
            m_file_sinks.push_back(std::move(sink));
        }
    }

    m_initialized = true;
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_console) m_console->Flush();
    for (auto& s : m_file_sinks) s->Flush();
    // We deliberately keep sinks alive — Shutdown() may be called before
    // late-firing log calls during static destruction. The destructors of
    // the unique_ptrs close the files cleanly at program exit.
}

// ===========================================================================
// Filtering accessors
// ===========================================================================

void Logger::SetGlobalLevel(LogLevel l) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_global_level = l;
    if (m_console) m_console->SetMinLevel(l);
    // Note: file sinks keep their own min level; per-channel level overrides
    // are applied in Log() instead of pushing into the sink filter.
}

LogLevel Logger::SetChannelLevel(const std::string& channel, LogLevel l) {
    std::lock_guard<std::mutex> lk(m_mtx);
    EnsureChannel(channel);
    LogLevel prev = m_channels[channel].level;
    m_channels[channel].level = l;
    return prev;
}

LogLevel Logger::ChannelLevel(const std::string& channel) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_channels.find(channel);
    if (it == m_channels.end()) return LogLevel::TRACE; // not bound -> permissive
    return it->second.level;
}

bool Logger::ShouldLog(const std::string& channel, LogLevel l) const {
    // Fast path: take the lock briefly to read both levels.
    std::lock_guard<std::mutex> lk(m_mtx);
    if (l < m_global_level) return false;
    auto it = m_channels.find(channel);
    if (it == m_channels.end()) {
        return true;  // unbound channel — only global filter applies
    }
    return l >= it->second.level;
}

// ===========================================================================
// Channel routing
// ===========================================================================

void Logger::EnsureChannel(const std::string& channel) {
    if (m_channels.find(channel) == m_channels.end()) {
        m_channels[channel] = ChannelConfig{};
    }
}

void Logger::BindChannelToFile(const std::string& channel,
                               const std::string& filename) {
    std::lock_guard<std::mutex> lk(m_mtx);
    EnsureChannel(channel);

    std::string full = filename;
    // If not absolute, prepend log_dir.
    if (!full.empty() && full[0] != '/') {
        full = utils::FileUtils::JoinPath(m_log_dir, full);
    }

    auto sink = std::make_unique<FileSink>(full);
    sink->SetMinLevel(m_global_level);
    m_channels[channel].file_sinks.push_back(sink.get());
    m_file_sinks.push_back(std::move(sink));
}

void Logger::SetChannelConsoleEnabled(const std::string& channel, bool enabled) {
    std::lock_guard<std::mutex> lk(m_mtx);
    EnsureChannel(channel);
    m_channels[channel].console_enabled = enabled;
}

// ===========================================================================
// Dispatch
// ===========================================================================

void Logger::DispatchUnlocked(const LogRecord& rec,
                              const ChannelConfig& cfg) {
    if (m_console && cfg.console_enabled) {
        m_console->Write(rec);
    }
    for (auto* fs : cfg.file_sinks) {
        if (fs) fs->Write(rec);
    }
}

// ===========================================================================
// Log entry points
// ===========================================================================

void Logger::Log(LogLevel level,
                 const std::string& channel,
                 const char* file,
                 int line,
                 const char* func,
                 std::string message) {
    try {
        std::lock_guard<std::mutex> lk(m_mtx);

        if (level < m_global_level) return;

        EnsureChannel(channel);
        const ChannelConfig& cfg = m_channels[channel];
        if (level < cfg.level) return;

        LogRecord rec;
        rec.level    = level;
        rec.channel  = channel;
        rec.file     = file ? file : "?";
        rec.line     = line;
        rec.function = func ? func : "?";
        rec.message  = std::move(message);
        rec.epoch_us = utils::TimeUtils::NowEpochMicros();

        DispatchUnlocked(rec, cfg);

        // FATAL flushes synchronously so the message reaches disk before
        // any subsequent abort() / std::terminate().
        if (level == LogLevel::FATAL) {
            if (m_console) m_console->Flush();
            for (auto& s : m_file_sinks) s->Flush();
        }
    } catch (...) {
        // Logger must never throw into hot paths.
    }
}

void Logger::Logf(LogLevel level,
                  const std::string& channel,
                  const char* file,
                  int line,
                  const char* func,
                  const char* fmt,
                  ...) {
    if (!fmt) return;

    // Format outside the lock for minimal lock-hold time.
    std::string message;
    {
        va_list args1;
        va_start(args1, fmt);
        va_list args2;
        va_copy(args2, args1);

        int needed = std::vsnprintf(nullptr, 0, fmt, args1);
        va_end(args1);

        if (needed >= 0) {
            message.resize(static_cast<std::size_t>(needed));
            std::vsnprintf(message.data(),
                           static_cast<std::size_t>(needed) + 1, fmt, args2);
        }
        va_end(args2);
    }

    Log(level, channel, file, line, func, std::move(message));
}

} // namespace log
} // namespace uav