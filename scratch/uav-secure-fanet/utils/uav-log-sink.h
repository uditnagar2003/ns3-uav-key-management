/**
 * utils/uav-log-sink.h
 * Output destination abstraction for the logger.
 *
 * Two built-in sinks:
 *   - ConsoleSink: writes to stderr with optional ANSI colour
 *   - FileSink   : writes to a file, opened on first message
 *
 * Sinks are owned by the Logger via std::unique_ptr and are flushed
 * automatically on Logger::Shutdown() and on destruction.
 *
 * Thread-safety: each sink has an internal mutex; concurrent calls
 * from multiple threads serialize at the sink level. NS-3 itself is
 * single-threaded but the logger is safe regardless.
 */

#ifndef UAV_LOG_SINK_H
#define UAV_LOG_SINK_H

#include "uav-types.h"
#include "uav-log-level.h"

#include <fstream>
#include <memory>
#include <mutex>
#include <string>

namespace uav {
namespace log {

// ===========================================================================
// LogRecord — assembled by Logger before being handed to sinks.
// ===========================================================================
struct LogRecord {
    LogLevel       level;
    std::string    channel;
    std::string    file;       // __FILE__
    int            line;       // __LINE__
    std::string    function;   // __func__
    std::string    message;
    utils::u64     epoch_us;   // wall-clock timestamp (microseconds)
};

// ===========================================================================
// LogSink — abstract base
// ===========================================================================
class LogSink {
public:
    virtual ~LogSink() = default;

    /// Format and write a record. Implementations MUST be exception-safe;
    /// failures should be silently swallowed (logging must never crash).
    virtual void Write(const LogRecord& rec) = 0;

    /// Force-flush any buffered output. Called on shutdown.
    virtual void Flush() = 0;

    /// Sink-specific minimum level filter. Records below this are dropped
    /// at the sink layer regardless of channel/global filters.
    void SetMinLevel(LogLevel l) { m_min_level = l; }
    LogLevel MinLevel() const    { return m_min_level; }

protected:
    LogLevel m_min_level = LogLevel::TRACE;
};

// ===========================================================================
// ConsoleSink — stderr with optional colour.
// ===========================================================================
class ConsoleSink : public LogSink {
public:
    explicit ConsoleSink(bool enable_colour = true);

    void Write(const LogRecord& rec) override;
    void Flush() override;

    void SetColourEnabled(bool e) { m_colour = e; }

private:
    bool       m_colour;
    std::mutex m_mtx;
};

// ===========================================================================
// FileSink — appends to a single file.
//
// File is opened lazily on first Write() call. Parent directory is
// created if missing. Open failure disables the sink (no throw).
// ===========================================================================
class FileSink : public LogSink {
public:
    explicit FileSink(std::string path);
    ~FileSink() override;

    void Write(const LogRecord& rec) override;
    void Flush() override;

    const std::string& Path() const { return m_path; }
    bool IsOpen() const             { return m_ok; }

private:
    std::string   m_path;
    std::ofstream m_stream;
    std::mutex    m_mtx;
    bool          m_ok      = false;
    bool          m_failed  = false;   // set once if open fails — don't retry
};

// ===========================================================================
// Free function — format a record to a single line.
// Exposed for testing and for sinks that want a default format.
//
// Format:
//   YYYY-MM-DDTHH:MM:SS.uuuuuuZ [L] [channel] file:line func() message
// ===========================================================================
std::string FormatLogLine(const LogRecord& rec);

} // namespace log
} // namespace uav

#endif // UAV_LOG_SINK_H