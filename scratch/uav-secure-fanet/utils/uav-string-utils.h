/**
 * utils/uav-string-utils.h
 * String manipulation helpers.
 */

#ifndef UAV_STRING_UTILS_H
#define UAV_STRING_UTILS_H

#include "uav-types.h"
#include <string>
#include <vector>

namespace uav {
namespace utils {

class StringUtils {
public:
    // -----------------------------------------------------------------------
    // Trim / case / split
    // -----------------------------------------------------------------------
    static std::string TrimLeft(const std::string& s);
    static std::string TrimRight(const std::string& s);
    static std::string Trim(const std::string& s);

    static std::string ToLower(std::string s);
    static std::string ToUpper(std::string s);

    static std::vector<std::string> Split(const std::string& s, char delim);
    static std::string Join(const std::vector<std::string>& parts,
                            const std::string& sep);

    static bool StartsWith(const std::string& s, const std::string& prefix);
    static bool EndsWith(const std::string& s, const std::string& suffix);

    static std::string Replace(std::string s,
                               const std::string& from,
                               const std::string& to);

    // -----------------------------------------------------------------------
    // printf-style formatter — small, safe, std::string-based
    // -----------------------------------------------------------------------
    static std::string Format(const char* fmt, ...);

    // -----------------------------------------------------------------------
    // Hex / Base64 helpers (used by crypto logging)
    // -----------------------------------------------------------------------
    /// Convert byte buffer to lowercase hex string.
    static std::string BytesToHex(const u8* data, std::size_t len);
    static std::string BytesToHex(const ByteBuffer& b);

    /// Parse hex string to byte buffer. Throws on invalid hex.
    static ByteBuffer HexToBytes(const std::string& hex);

    /// Truncated hex for log lines (first/last `n` bytes).
    static std::string BytesToHexAbbrev(const ByteBuffer& b,
                                        std::size_t prefix = 8,
                                        std::size_t suffix = 4);
};

} // namespace utils
} // namespace uav

#endif // UAV_STRING_UTILS_H