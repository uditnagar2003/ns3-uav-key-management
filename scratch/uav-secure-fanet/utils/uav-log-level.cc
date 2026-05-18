/**
 * utils/uav-log-level.cc
 */

#include "uav-log-level.h"
#include "uav-string-utils.h"

namespace uav {
namespace log {

char LogLevelChar(LogLevel l) {
    switch (l) {
        case LogLevel::TRACE: return 'T';
        case LogLevel::DEBUG: return 'D';
        case LogLevel::INFO : return 'I';
        case LogLevel::WARN : return 'W';
        case LogLevel::ERROR: return 'E';
        case LogLevel::FATAL: return 'F';
        case LogLevel::OFF  : return '-';
    }
    return '?';
}

const char* LogLevelToString(LogLevel l) {
    switch (l) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO : return "INFO";
        case LogLevel::WARN : return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        case LogLevel::OFF  : return "OFF";
    }
    return "UNKNOWN";
}

LogLevel LogLevelFromString(const std::string& s) {
    std::string u = utils::StringUtils::ToUpper(utils::StringUtils::Trim(s));
    if (u == "TRACE") return LogLevel::TRACE;
    if (u == "DEBUG") return LogLevel::DEBUG;
    if (u == "INFO" ) return LogLevel::INFO;
    if (u == "WARN" || u == "WARNING") return LogLevel::WARN;
    if (u == "ERROR" || u == "ERR")    return LogLevel::ERROR;
    if (u == "FATAL") return LogLevel::FATAL;
    if (u == "OFF"  ) return LogLevel::OFF;
    return LogLevel::OFF;
}

const char* LogLevelAnsiColour(LogLevel l) {
    switch (l) {
        case LogLevel::TRACE: return "\x1b[90m"; // grey
        case LogLevel::DEBUG: return "\x1b[36m"; // cyan
        case LogLevel::INFO : return "\x1b[37m"; // white
        case LogLevel::WARN : return "\x1b[33m"; // yellow
        case LogLevel::ERROR: return "\x1b[31m"; // red
        case LogLevel::FATAL: return "\x1b[1;31m"; // bold red
        case LogLevel::OFF  : return "";
    }
    return "";
}

} // namespace log
} // namespace uav