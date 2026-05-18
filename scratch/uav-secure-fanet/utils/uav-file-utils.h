/**
 * utils/uav-file-utils.h
 * Filesystem helpers — directory creation, file existence, read/write.
 *
 * Uses C++17 <filesystem> internally.
 */

#ifndef UAV_FILE_UTILS_H
#define UAV_FILE_UTILS_H

#include "uav-types.h"
#include <string>

namespace uav {
namespace utils {

class FileUtils {
public:
    // -----------------------------------------------------------------------
    // Existence / metadata
    // -----------------------------------------------------------------------
    static bool Exists(const std::string& path);
    static bool IsDirectory(const std::string& path);
    static bool IsRegularFile(const std::string& path);
    static u64  FileSizeBytes(const std::string& path);

    // -----------------------------------------------------------------------
    // Directory operations
    // -----------------------------------------------------------------------
    /// Recursively create directory. Returns true if created or already exists.
    static bool MkdirRecursive(const std::string& path);

    /// List regular files (non-recursive). Returns absolute paths.
    static std::vector<std::string> ListFiles(const std::string& dir);

    // -----------------------------------------------------------------------
    // Read / write text
    // -----------------------------------------------------------------------
    static std::string ReadTextFile(const std::string& path);
    static void        WriteTextFile(const std::string& path,
                                     const std::string& contents,
                                     bool append = false);

    // -----------------------------------------------------------------------
    // Read / write binary
    // -----------------------------------------------------------------------
    static ByteBuffer ReadBinaryFile(const std::string& path);
    static void       WriteBinaryFile(const std::string& path,
                                      const ByteBuffer& contents);

    // -----------------------------------------------------------------------
    // Path manipulation
    // -----------------------------------------------------------------------
    static std::string JoinPath(const std::string& a, const std::string& b);
    static std::string ParentDir(const std::string& path);
    static std::string BaseName(const std::string& path);
    static std::string Extension(const std::string& path);
};

} // namespace utils
} // namespace uav

#endif // UAV_FILE_UTILS_H