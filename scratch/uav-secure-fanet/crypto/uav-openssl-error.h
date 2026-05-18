/**
 * crypto/uav-openssl-error.h
 *
 * OpenSSL error extraction and formatting helpers.
 * Header-only — no translation unit needed.
 *
 * OpenSSL 3.x uses a thread-local error queue.
 * These helpers drain the queue and format errors
 * as std::string for use in CryptoException messages.
 */

#ifndef UAV_OPENSSL_ERROR_H
#define UAV_OPENSSL_ERROR_H

#include "uav-error.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>
#include <sstream>

namespace uav {
namespace crypto {

// ===========================================================================
// OpenSSL error queue helpers
// ===========================================================================

/// Drain the OpenSSL error queue and return all errors
/// as a single newline-separated string.
inline std::string OpenSSLGetErrors() {
    std::ostringstream oss;
    unsigned long code;
    bool first = true;
    while ((code = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof(buf));
        if (!first) oss << "\n";
        oss << buf;
        first = false;
    }
    if (first) return "unknown OpenSSL error";
    return oss.str();
}

/// Throw CryptoException with OpenSSL error queue message.
/// Drains the queue automatically.
#define UAV_OPENSSL_THROW(context)                                        \
    UAV_THROW(::uav::utils::CryptoException,                              \
              std::string(context) + ": " +                               \
              ::uav::crypto::OpenSSLGetErrors())

/// Check OpenSSL return code (1 = success).
/// Throws CryptoException with error queue on failure.
#define UAV_OPENSSL_CHECK(call, context)                                  \
    do {                                                                  \
        if ((call) != 1) {                                                \
            UAV_OPENSSL_THROW(context);                                   \
        }                                                                 \
    } while (0)

/// Check OpenSSL pointer (non-null = success).
#define UAV_OPENSSL_CHECK_PTR(ptr, context)                               \
    do {                                                                  \
        if (!(ptr)) {                                                     \
            UAV_OPENSSL_THROW(context);                                   \
        }                                                                 \
    } while (0)

} // namespace crypto
} // namespace uav

#endif // UAV_OPENSSL_ERROR_H