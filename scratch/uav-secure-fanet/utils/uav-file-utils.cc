/**
 * utils/uav-file-utils.cc
 */

#include "uav-file-utils.h"
#include "uav-error.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace uav {
namespace utils {

// ---------------------------------------------------------------------------
// Existence / metadata
// ---------------------------------------------------------------------------

bool FileUtils::Exists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

bool FileUtils::IsDirectory(const std::string& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

bool FileUtils::IsRegularFile(const std::string& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

u64 FileUtils::FileSizeBytes(const std::string& path) {
    std::error_code ec;
    auto sz = fs::file_size(path, ec);
    if (ec) {
        UAV_THROW(FileIOException,
                  "FileSizeBytes failed for '" + path + "': " + ec.message());
    }
    return static_cast<u64>(sz);
}

// ---------------------------------------------------------------------------
// Directory operations
// ---------------------------------------------------------------------------

bool FileUtils::MkdirRecursive(const std::string& path) {
    std::error_code ec;
    if (fs::exists(path, ec)) {
        if (!fs::is_directory(path, ec)) {
            UAV_THROW(FileIOException,
                      "MkdirRecursive: '" + path + "' exists but is not a directory");
        }
        return true;
    }
    bool created = fs::create_directories(path, ec);
    if (ec) {
        UAV_THROW(FileIOException,
                  "MkdirRecursive failed for '" + path + "': " + ec.message());
    }
    return created;
}

std::vector<std::string> FileUtils::ListFiles(const std::string& dir) {
    std::vector<std::string> out;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        UAV_THROW(FileIOException,
                  "ListFiles: '" + dir + "' is not a directory");
    }
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.is_regular_file(ec)) {
            out.push_back(entry.path().string());
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Read / write text
// ---------------------------------------------------------------------------

std::string FileUtils::ReadTextFile(const std::string& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        UAV_THROW(FileIOException,
                  "ReadTextFile: cannot open '" + path + "'");
    }
    std::ostringstream oss;
    oss << in.rdbuf();
    if (in.bad()) {
        UAV_THROW(FileIOException,
                  "ReadTextFile: read error on '" + path + "'");
    }
    return oss.str();
}

void FileUtils::WriteTextFile(const std::string& path,
                              const std::string& contents,
                              bool append) {
    // Ensure parent directory exists.
    std::string parent = ParentDir(path);
    if (!parent.empty()) {
        MkdirRecursive(parent);
    }
    auto mode = std::ios::out | std::ios::binary;
    if (append) mode |= std::ios::app;
    else        mode |= std::ios::trunc;

    std::ofstream out(path, mode);
    if (!out.is_open()) {
        UAV_THROW(FileIOException,
                  "WriteTextFile: cannot open '" + path + "'");
    }
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (!out.good()) {
        UAV_THROW(FileIOException,
                  "WriteTextFile: write error on '" + path + "'");
    }
}

// ---------------------------------------------------------------------------
// Read / write binary
// ---------------------------------------------------------------------------

ByteBuffer FileUtils::ReadBinaryFile(const std::string& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (!in.is_open()) {
        UAV_THROW(FileIOException,
                  "ReadBinaryFile: cannot open '" + path + "'");
    }
    std::streamsize sz = in.tellg();
    if (sz < 0) {
        UAV_THROW(FileIOException,
                  "ReadBinaryFile: tellg failed on '" + path + "'");
    }
    in.seekg(0, std::ios::beg);

    ByteBuffer buf(static_cast<std::size_t>(sz));
    if (sz > 0 && !in.read(reinterpret_cast<char*>(buf.data()), sz)) {
        UAV_THROW(FileIOException,
                  "ReadBinaryFile: read error on '" + path + "'");
    }
    return buf;
}

void FileUtils::WriteBinaryFile(const std::string& path,
                                const ByteBuffer& contents) {
    std::string parent = ParentDir(path);
    if (!parent.empty()) {
        MkdirRecursive(parent);
    }
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        UAV_THROW(FileIOException,
                  "WriteBinaryFile: cannot open '" + path + "'");
    }
    if (!contents.empty()) {
        out.write(reinterpret_cast<const char*>(contents.data()),
                  static_cast<std::streamsize>(contents.size()));
        if (!out.good()) {
            UAV_THROW(FileIOException,
                      "WriteBinaryFile: write error on '" + path + "'");
        }
    }
}

// ---------------------------------------------------------------------------
// Path manipulation
// ---------------------------------------------------------------------------

std::string FileUtils::JoinPath(const std::string& a, const std::string& b) {
    fs::path p = fs::path(a) / fs::path(b);
    return p.string();
}

std::string FileUtils::ParentDir(const std::string& path) {
    return fs::path(path).parent_path().string();
}

std::string FileUtils::BaseName(const std::string& path) {
    return fs::path(path).filename().string();
}

std::string FileUtils::Extension(const std::string& path) {
    return fs::path(path).extension().string();
}

} // namespace utils
} // namespace uav