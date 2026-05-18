/**
 * utils/uav-csv-logger.h
 *
 * Structured CSV logger — separate from textual logger.
 *
 * Used by:
 *   - Module 41-46 (security events)
 *   - Module 52-58 (metrics: throughput, delay, PDR, rekey latency, ...)
 *   - Module 30+  (mobility traces)
 *
 * Each CsvLogger instance writes to ONE file. Headers are written on
 * first row append (if the file is new or empty). Fields are RFC-4180-
 * quoted when they contain commas, newlines, or quote characters.
 *
 * Thread-safety: each instance has its own mutex.
 *
 * Typical usage:
 *
 *   auto csv = uav::log::CsvLogger::Open(
 *       "output/metrics_throughput.csv",
 *       { "time_s", "node_id", "throughput_kbps" });
 *
 *   csv->AppendRow({
 *       std::to_string(t),
 *       std::to_string(node_id),
 *       std::to_string(tput) });
 *
 *   // Or with the builder:
 *   csv->Row()
 *      .Set("time_s",         t)
 *      .Set("node_id",        node_id)
 *      .Set("throughput_kbps",tput)
 *      .Commit();
 */

#ifndef UAV_CSV_LOGGER_H
#define UAV_CSV_LOGGER_H

#include "uav-types.h"

#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace uav {
namespace log {

class CsvLogger;   // fwd

// ---------------------------------------------------------------------------
// CsvRowBuilder — fluent builder for one row.
// ---------------------------------------------------------------------------
class CsvRowBuilder {
public:
    CsvRowBuilder(CsvLogger* parent);

    template <typename T>
    CsvRowBuilder& Set(const std::string& column, T&& value) {
        m_values[column] = ToString(std::forward<T>(value));
        return *this;
    }

    /// Append the row to the parent file.
    void Commit();

private:
    template <typename T>
    static std::string ToString(T&& v) {
        if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
            return v;
        } else if constexpr (std::is_same_v<std::decay_t<T>, const char*>) {
            return std::string(v);
        } else {
            return std::to_string(std::forward<T>(v));
        }
    }

    CsvLogger*                                   m_parent;
    std::unordered_map<std::string, std::string> m_values;
};

// ---------------------------------------------------------------------------
// CsvLogger
// ---------------------------------------------------------------------------
class CsvLogger {
public:
    /// Open or create a CSV file with the given header.
    /// If the file already exists and is non-empty, the header is NOT
    /// rewritten (assumes existing file has compatible header).
    /// Parent directory is created if missing.
    static std::shared_ptr<CsvLogger> Open(
        const std::string& path,
        const std::vector<std::string>& header);

    ~CsvLogger();

    /// Append a row by positional values (must match header arity).
    void AppendRow(const std::vector<std::string>& values);

    /// Append a row by column-name lookup. Missing columns -> empty.
    void AppendRow(const std::unordered_map<std::string, std::string>& named);

    /// Return a builder bound to this logger.
    CsvRowBuilder Row() { return CsvRowBuilder(this); }

    /// Flush the underlying stream.
    void Flush();

    /// Close the file. Further appends are no-ops.
    void Close();

    const std::string&             Path()   const { return m_path; }
    const std::vector<std::string>& Header() const { return m_header; }
    utils::u64                     RowsWritten() const { return m_rows; }
    bool                           IsOpen() const { return m_ok; }

private:
    CsvLogger(std::string path, std::vector<std::string> header);

    static std::string EscapeField(const std::string& v);

    std::string                                  m_path;
    std::vector<std::string>                     m_header;
    std::unordered_map<std::string, std::size_t> m_col_index;
    std::ofstream                                m_stream;
    std::mutex                                   m_mtx;
    utils::u64                                   m_rows = 0;
    bool                                         m_ok   = false;
};

} // namespace log
} // namespace uav

#endif // UAV_CSV_LOGGER_H