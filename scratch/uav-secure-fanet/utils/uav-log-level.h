/**
 * utils/uav-log-level.h
 * Log severity levels. Header-only.
 *
 * Levels map to NS_LOG conventions for compatibility:
 *   TRACE  → NS_LOG_LOGIC
 *   DEBUG  → NS_LOG_DEBUG
 *   INFO   → NS_LOG_INFO
 *   WARN   → NS_LOG_WARN
 *   ERROR  → NS_LOG_ERROR
 *   FATAL  → NS_LOG_ERROR (with abort semantics in our wrapper)
 */

#ifndef UAV_LOG_LEVEL_H
#define UAV_LOG_LEVEL_H

#include "uav-types.h"
#include <string>

namespace uav {
namespace log {

enum class LogLevel : utils::u8 {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    FATAL = 5,
    OFF   = 255
};

/// Single-letter tag for compact log output ('T','D','I','W','E','F').
char LogLevelChar(LogLevel l);

/// Human-readable name ("TRACE"..."FATAL").
const char* LogLevelToString(LogLevel l);

/// Parse case-insensitive level name. Returns OFF on unknown input.
LogLevel LogLevelFromString(const std::string& s);

/// ANSI colour escape for a level (empty if colour disabled).
/// Returns just the SGR sequence; caller appends "\x1b[0m" to reset.
const char* LogLevelAnsiColour(LogLevel l);

} // namespace log
} // namespace uav

#endif // UAV_LOG_LEVEL_H