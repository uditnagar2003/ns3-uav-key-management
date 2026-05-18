/**
 * utils/uav-error.h
 * Project-wide exception hierarchy.
 *
 * Design:
 *   UavException        (base — all project exceptions derive from this)
 *     ├── CryptoException
 *     ├── SerializationException
 *     ├── ConfigException
 *     ├── FileIOException
 *     └── InvalidArgumentException
 */

#ifndef UAV_ERROR_H
#define UAV_ERROR_H

#include <stdexcept>
#include <string>
#include "uav-types.h"

namespace uav {
namespace utils {

// ===========================================================================
// Base exception — all project exceptions derive from this
// ===========================================================================
class UavException : public std::runtime_error {
public:
    UavException(const std::string& msg, Status code = Status::INTERNAL_ERROR);

    Status code() const noexcept { return m_code; }

    /// Returns "[StatusName] message" for logging
    std::string formatted() const;

private:
    Status m_code;
};

// ===========================================================================
// Crypto-layer errors (OpenSSL failures, AES errors, HMAC mismatch, ...)
// ===========================================================================
class CryptoException : public UavException {
public:
    explicit CryptoException(const std::string& msg,
                             Status code = Status::DECRYPT_FAILED);
};

// ===========================================================================
// Packet (de)serialisation errors
// ===========================================================================
class SerializationException : public UavException {
public:
    explicit SerializationException(const std::string& msg);
};

// ===========================================================================
// Configuration / JSON loader errors
// ===========================================================================
class ConfigException : public UavException {
public:
    explicit ConfigException(const std::string& msg);
};

// ===========================================================================
// File IO errors
// ===========================================================================
class FileIOException : public UavException {
public:
    explicit FileIOException(const std::string& msg);
};

// ===========================================================================
// Invalid argument
// ===========================================================================
class InvalidArgumentException : public UavException {
public:
    explicit InvalidArgumentException(const std::string& msg);
};

// ===========================================================================
// Convenience macro to throw with file/line context
// ===========================================================================
#define UAV_THROW(ExceptionType, msg)                                          \
    throw ExceptionType(                                                       \
        std::string("[") + __FILE__ + ":" + std::to_string(__LINE__) + "] " + (msg))

#define UAV_CHECK(cond, ExceptionType, msg)                                    \
    do {                                                                       \
        if (!(cond)) {                                                         \
            UAV_THROW(ExceptionType,                                           \
                std::string("Check failed (") + #cond + "): " + (msg));        \
        }                                                                      \
    } while (0)

} // namespace utils
} // namespace uav

#endif // UAV_ERROR_H