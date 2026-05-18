/**
 * utils/uav-error.cc
 */

#include "uav-error.h"

namespace uav {
namespace utils {

// ---------------------------------------------------------------------------
// UavException
// ---------------------------------------------------------------------------
UavException::UavException(const std::string& msg, Status code)
    : std::runtime_error(msg)
    , m_code(code)
{}

std::string UavException::formatted() const {
    std::string out = "[";
    out += StatusToString(m_code);
    out += "] ";
    out += what();
    return out;
}

// ---------------------------------------------------------------------------
// Derived classes — minimal constructors delegating to base
// ---------------------------------------------------------------------------
CryptoException::CryptoException(const std::string& msg, Status code)
    : UavException(msg, code)
{}

SerializationException::SerializationException(const std::string& msg)
    : UavException(msg, Status::SERIALIZATION_ERROR)
{}

ConfigException::ConfigException(const std::string& msg)
    : UavException(msg, Status::INVALID_ARGUMENT)
{}

FileIOException::FileIOException(const std::string& msg)
    : UavException(msg, Status::INTERNAL_ERROR)
{}

InvalidArgumentException::InvalidArgumentException(const std::string& msg)
    : UavException(msg, Status::INVALID_ARGUMENT)
{}

} // namespace utils
} // namespace uav