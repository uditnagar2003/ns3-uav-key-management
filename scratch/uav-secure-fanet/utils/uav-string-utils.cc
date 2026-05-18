/**
 * utils/uav-string-utils.cc
 */

#include "uav-string-utils.h"
#include "uav-error.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <sstream>

namespace uav {
namespace utils {

// ---------------------------------------------------------------------------
// Trim / case / split
// ---------------------------------------------------------------------------

std::string StringUtils::TrimLeft(const std::string& s) {
    auto it = std::find_if(s.begin(), s.end(), [](unsigned char c) {
        return !std::isspace(c);
    });
    return std::string(it, s.end());
}

std::string StringUtils::TrimRight(const std::string& s) {
    auto it = std::find_if(s.rbegin(), s.rend(), [](unsigned char c) {
        return !std::isspace(c);
    });
    return std::string(s.begin(), it.base());
}

std::string StringUtils::Trim(const std::string& s) {
    return TrimLeft(TrimRight(s));
}

std::string StringUtils::ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string StringUtils::ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::vector<std::string> StringUtils::Split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        out.push_back(item);
    }
    return out;
}

std::string StringUtils::Join(const std::vector<std::string>& parts,
                              const std::string& sep) {
    if (parts.empty()) return "";
    std::ostringstream oss;
    oss << parts[0];
    for (std::size_t i = 1; i < parts.size(); ++i) {
        oss << sep << parts[i];
    }
    return oss.str();
}

bool StringUtils::StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

bool StringUtils::EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string StringUtils::Replace(std::string s,
                                 const std::string& from,
                                 const std::string& to) {
    if (from.empty()) return s;
    std::size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

// ---------------------------------------------------------------------------
// printf-style Format
// ---------------------------------------------------------------------------

std::string StringUtils::Format(const char* fmt, ...) {
    va_list args1;
    va_start(args1, fmt);
    va_list args2;
    va_copy(args2, args1);

    int needed = std::vsnprintf(nullptr, 0, fmt, args1);
    va_end(args1);

    if (needed < 0) {
        va_end(args2);
        UAV_THROW(UavException, "Format: vsnprintf size query failed");
    }

    std::string out(static_cast<std::size_t>(needed), '\0');
    std::vsnprintf(out.data(), static_cast<std::size_t>(needed) + 1, fmt, args2);
    va_end(args2);
    return out;
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

namespace {
constexpr char kHexLower[] = "0123456789abcdef";

inline int HexDigitValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // anonymous namespace

std::string StringUtils::BytesToHex(const u8* data, std::size_t len) {
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHexLower[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHexLower[data[i] & 0x0F];
    }
    return out;
}

std::string StringUtils::BytesToHex(const ByteBuffer& b) {
    return BytesToHex(b.data(), b.size());
}

ByteBuffer StringUtils::HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        UAV_THROW(InvalidArgumentException,
                  "HexToBytes: input length must be even");
    }
    ByteBuffer out;
    out.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = HexDigitValue(hex[i]);
        int lo = HexDigitValue(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            UAV_THROW(InvalidArgumentException,
                      "HexToBytes: invalid hex character at index " +
                      std::to_string(i));
        }
        out.push_back(static_cast<u8>((hi << 4) | lo));
    }
    return out;
}

std::string StringUtils::BytesToHexAbbrev(const ByteBuffer& b,
                                          std::size_t prefix,
                                          std::size_t suffix) {
    if (b.size() <= prefix + suffix) {
        return BytesToHex(b);
    }
    std::string head = BytesToHex(b.data(), prefix);
    std::string tail = BytesToHex(b.data() + b.size() - suffix, suffix);
    return head + "..." + tail + "(" + std::to_string(b.size()) + "B)";
}

} // namespace utils
} // namespace uav