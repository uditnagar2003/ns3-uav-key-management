/**
 * utils/uav-log-sink.cc
 */

#include "uav-log-sink.h"
#include "uav-time-utils.h"
#include "uav-file-utils.h"
#include "uav-string-utils.h"

#include <iostream>
#include <sstream>
#include <unistd.h>   // isatty

namespace uav {
namespace log {

// ===========================================================================
// FormatLogLine
// ===========================================================================

std::string FormatLogLine(const LogRecord& rec) {
    // Extract just the basename of the source file to keep lines short.
    std::string base = rec.file;
    auto pos = base.find_last_of("/\\");
    if (pos != std::string::npos) base = base.substr(pos + 1);

    std::ostringstream oss;
    oss << utils::TimeUtils::FormatEpochMicros(rec.epoch_us)
        << " [" << LogLevelChar(rec.level) << "]"
        << " [" << rec.channel << "]"
        << " " << base << ":" << rec.line
        << " " << rec.function << "()"
        << " " << rec.message;
    return oss.str();
}

// ===========================================================================
// ConsoleSink
// ===========================================================================

ConsoleSink::ConsoleSink(bool enable_colour)
    : m_colour(enable_colour && ::isatty(fileno(stderr)) != 0)
{}

void ConsoleSink::Write(const LogRecord& rec) {
    if (rec.level < m_min_level) return;
    try {
        std::string line = FormatLogLine(rec);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_colour) {
            const char* col = LogLevelAnsiColour(rec.level);
            std::cerr << col << line << "\x1b[0m\n";
        } else {
            std::cerr << line << "\n";
        }
    } catch (...) {
        // Logging failures must never propagate.
    }
}

void ConsoleSink::Flush() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::cerr.flush();
}

// ===========================================================================
// FileSink
// ===========================================================================

FileSink::FileSink(std::string path)
    : m_path(std::move(path))
{}

FileSink::~FileSink() {
    try {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_stream.is_open()) {
            m_stream.flush();
            m_stream.close();
        }
    } catch (...) {
        // swallow
    }
}

void FileSink::Write(const LogRecord& rec) {
    if (rec.level < m_min_level) return;
    try {
        std::lock_guard<std::mutex> lk(m_mtx);

        if (!m_ok && !m_failed) {
            // Lazy open — create parent dir.
            try {
                std::string parent = utils::FileUtils::ParentDir(m_path);
                if (!parent.empty()) {
                    utils::FileUtils::MkdirRecursive(parent);
                }
            } catch (...) {
                // ignore mkdir failures; open will fail too and we'll mark failed
            }

            m_stream.open(m_path,
                std::ios::out | std::ios::app | std::ios::binary);
            if (m_stream.is_open()) {
                m_ok = true;
            } else {
                m_failed = true;
                // One-time diagnostic to stderr — bypasses logger to avoid loop.
                std::cerr << "[uav-log] FileSink: cannot open '"
                          << m_path << "'\n";
                return;
            }
        }

        if (!m_ok) return;

        std::string line = FormatLogLine(rec);
        m_stream.write(line.data(),
                       static_cast<std::streamsize>(line.size()));
        m_stream.put('\n');
        if (m_stream.bad()) {
            m_stream.clear();
        }
    } catch (...) {
        // swallow
    }
}

void FileSink::Flush() {
    try {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_ok) m_stream.flush();
    } catch (...) {
        // swallow
    }
}

} // namespace log
} // namespace uav