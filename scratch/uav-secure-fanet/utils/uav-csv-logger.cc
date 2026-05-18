/**
 * utils/uav-csv-logger.cc
 */

#include "uav-csv-logger.h"
#include "uav-file-utils.h"
#include "uav-error.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <iostream>
#include <sstream>

namespace uav {
namespace log {

// ===========================================================================
// CsvRowBuilder
// ===========================================================================

CsvRowBuilder::CsvRowBuilder(CsvLogger* parent)
    : m_parent(parent) {}

void CsvRowBuilder::Commit() {
    if (m_parent) {
        m_parent->AppendRow(m_values);
    }
}

// ===========================================================================
// CsvLogger
// ===========================================================================

CsvLogger::CsvLogger(std::string path, std::vector<std::string> header)
    : m_path(std::move(path))
    , m_header(std::move(header))
{
    for (std::size_t i = 0; i < m_header.size(); ++i) {
        m_col_index[m_header[i]] = i;
    }
}

CsvLogger::~CsvLogger() {
    try {
        Close();
    } catch (...) {
        // swallow
    }
}

std::shared_ptr<CsvLogger> CsvLogger::Open(
    const std::string& path,
    const std::vector<std::string>& header)
{
    auto inst = std::shared_ptr<CsvLogger>(new CsvLogger(path, header));

    try {
        std::string parent = utils::FileUtils::ParentDir(path);
        if (!parent.empty()) {
            utils::FileUtils::MkdirRecursive(parent);
        }
    } catch (const std::exception& ex) {
        UAV_LOG_WARN(channels::SYSTEM,
            "CsvLogger: cannot create parent dir for '" << path
            << "': " << ex.what());
        return inst;   // m_ok stays false
    }

    bool already_exists_with_content = false;
    if (utils::FileUtils::Exists(path)) {
        try {
            if (utils::FileUtils::FileSizeBytes(path) > 0) {
                already_exists_with_content = true;
            }
        } catch (...) {
            // ignore
        }
    }

    inst->m_stream.open(path,
        std::ios::out | std::ios::app | std::ios::binary);
    if (!inst->m_stream.is_open()) {
        UAV_LOG_WARN(channels::SYSTEM,
            "CsvLogger: cannot open '" << path << "'");
        return inst;
    }
    inst->m_ok = true;

    // Write header only if file is new/empty.
    if (!already_exists_with_content) {
        std::ostringstream oss;
        for (std::size_t i = 0; i < header.size(); ++i) {
            if (i > 0) oss << ',';
            oss << EscapeField(header[i]);
        }
        oss << '\n';
        const std::string s = oss.str();
        inst->m_stream.write(s.data(),
                             static_cast<std::streamsize>(s.size()));
    }

    return inst;
}

void CsvLogger::AppendRow(const std::vector<std::string>& values) {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (!m_ok) return;

    try {
        std::ostringstream oss;
        const std::size_t n = m_header.size();
        for (std::size_t i = 0; i < n; ++i) {
            if (i > 0) oss << ',';
            if (i < values.size()) {
                oss << EscapeField(values[i]);
            }
        }
        oss << '\n';
        const std::string s = oss.str();
        m_stream.write(s.data(),
                       static_cast<std::streamsize>(s.size()));
        if (m_stream.bad()) {
            m_stream.clear();
        } else {
            ++m_rows;
        }
    } catch (...) {
        // swallow
    }
}

void CsvLogger::AppendRow(
    const std::unordered_map<std::string, std::string>& named)
{
    std::vector<std::string> row(m_header.size());
    for (const auto& kv : named) {
        auto it = m_col_index.find(kv.first);
        if (it != m_col_index.end()) {
            row[it->second] = kv.second;
        }
    }
    AppendRow(row);
}

void CsvLogger::Flush() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_ok) m_stream.flush();
}

void CsvLogger::Close() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_ok) {
        m_stream.flush();
        m_stream.close();
        m_ok = false;
    }
}

std::string CsvLogger::EscapeField(const std::string& v) {
    bool needs_quote = false;
    for (char c : v) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quote = true;
            break;
        }
    }
    if (!needs_quote) return v;

    std::string out;
    out.reserve(v.size() + 2);
    out.push_back('"');
    for (char c : v) {
        if (c == '"') out.push_back('"');   // escape quote
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

} // namespace log
} // namespace uav