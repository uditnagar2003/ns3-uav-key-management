/**
 * crypto/uav-openssl-ctx.h
 *
 * RAII wrappers for OpenSSL EVP context objects.
 *
 * OpenSSL requires explicit cleanup of EVP contexts.
 * These wrappers ensure cleanup happens automatically
 * via destructors — even on exception paths.
 *
 * Wrappers provided:
 *   EvpCipherCtx   — for EVP_CIPHER_CTX (AES encrypt/decrypt)
 *   EvpMdCtx       — for EVP_MD_CTX (digest / HMAC)
 *   EvpMacCtx      — for EVP_MAC_CTX (OpenSSL 3.x HMAC)
 *   EvpPkeyCtx     — for EVP_PKEY_CTX (key derivation)
 *
 * All wrappers are:
 *   - Non-copyable (OpenSSL contexts are not copyable)
 *   - Movable
 *   - Null-safe (get() returns nullptr safely)
 */

#ifndef UAV_OPENSSL_CTX_H
#define UAV_OPENSSL_CTX_H

#include "uav-openssl-error.h"
#include "uav-types.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <memory>

namespace uav {
namespace crypto {

// ===========================================================================
// EvpCipherCtx — RAII wrapper for EVP_CIPHER_CTX
// Used by AES-256-GCM encrypt/decrypt (Module 9)
// ===========================================================================
class EvpCipherCtx {
public:
    /// Create a new EVP_CIPHER_CTX.
    /// Throws CryptoException if allocation fails.
    EvpCipherCtx() {
        m_ctx = EVP_CIPHER_CTX_new();
        UAV_OPENSSL_CHECK_PTR(m_ctx, "EVP_CIPHER_CTX_new");
    }

    ~EvpCipherCtx() {
        if (m_ctx) {
            EVP_CIPHER_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

    // Non-copyable
    EvpCipherCtx(const EvpCipherCtx&)            = delete;
    EvpCipherCtx& operator=(const EvpCipherCtx&) = delete;

    // Movable
    EvpCipherCtx(EvpCipherCtx&& o) noexcept
        : m_ctx(o.m_ctx) { o.m_ctx = nullptr; }

    EvpCipherCtx& operator=(EvpCipherCtx&& o) noexcept {
        if (this != &o) {
            if (m_ctx) EVP_CIPHER_CTX_free(m_ctx);
            m_ctx   = o.m_ctx;
            o.m_ctx = nullptr;
        }
        return *this;
    }

    EVP_CIPHER_CTX* get() const noexcept { return m_ctx; }

    /// Reset context for reuse (calls EVP_CIPHER_CTX_reset).
    void Reset() {
        UAV_OPENSSL_CHECK(
            EVP_CIPHER_CTX_reset(m_ctx),
            "EVP_CIPHER_CTX_reset");
    }

private:
    EVP_CIPHER_CTX* m_ctx = nullptr;
};

// ===========================================================================
// EvpMdCtx — RAII wrapper for EVP_MD_CTX
// Used by SHA-256 digest and HMAC-SHA256 (Module 10)
// ===========================================================================
class EvpMdCtx {
public:
    EvpMdCtx() {
        m_ctx = EVP_MD_CTX_new();
        UAV_OPENSSL_CHECK_PTR(m_ctx, "EVP_MD_CTX_new");
    }

    ~EvpMdCtx() {
        if (m_ctx) {
            EVP_MD_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

    EvpMdCtx(const EvpMdCtx&)            = delete;
    EvpMdCtx& operator=(const EvpMdCtx&) = delete;

    EvpMdCtx(EvpMdCtx&& o) noexcept
        : m_ctx(o.m_ctx) { o.m_ctx = nullptr; }

    EvpMdCtx& operator=(EvpMdCtx&& o) noexcept {
        if (this != &o) {
            if (m_ctx) EVP_MD_CTX_free(m_ctx);
            m_ctx   = o.m_ctx;
            o.m_ctx = nullptr;
        }
        return *this;
    }

    EVP_MD_CTX* get() const noexcept { return m_ctx; }

    /// Reset for reuse without reallocation.
    void Reset() {
        UAV_OPENSSL_CHECK(
            EVP_MD_CTX_reset(m_ctx),
            "EVP_MD_CTX_reset");
    }

private:
    EVP_MD_CTX* m_ctx = nullptr;
};

// ===========================================================================
// EvpMacCtx — RAII wrapper for EVP_MAC_CTX (OpenSSL 3.x)
// Used by HMAC-SHA256 via EVP_MAC API (Module 10)
// ===========================================================================
class EvpMacCtx {
public:
    /// Takes ownership of an existing EVP_MAC_CTX*.
    explicit EvpMacCtx(EVP_MAC_CTX* ctx) : m_ctx(ctx) {
        UAV_OPENSSL_CHECK_PTR(m_ctx, "EvpMacCtx: null ctx");
    }

    ~EvpMacCtx() {
        if (m_ctx) {
            EVP_MAC_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

    EvpMacCtx(const EvpMacCtx&)            = delete;
    EvpMacCtx& operator=(const EvpMacCtx&) = delete;

    EvpMacCtx(EvpMacCtx&& o) noexcept
        : m_ctx(o.m_ctx) { o.m_ctx = nullptr; }

    EvpMacCtx& operator=(EvpMacCtx&& o) noexcept {
        if (this != &o) {
            if (m_ctx) EVP_MAC_CTX_free(m_ctx);
            m_ctx   = o.m_ctx;
            o.m_ctx = nullptr;
        }
        return *this;
    }

    EVP_MAC_CTX* get() const noexcept { return m_ctx; }

private:
    EVP_MAC_CTX* m_ctx = nullptr;
};

// ===========================================================================
// EvpMac — RAII wrapper for EVP_MAC (algorithm handle)
// ===========================================================================
class EvpMac {
public:
    /// Fetch a MAC algorithm by name (e.g. "HMAC").
    explicit EvpMac(const char* algorithm,
                    const char* properties = nullptr) {
        m_mac = EVP_MAC_fetch(nullptr, algorithm, properties);
        UAV_OPENSSL_CHECK_PTR(m_mac,
            std::string("EVP_MAC_fetch(") + algorithm + ")");
    }

    ~EvpMac() {
        if (m_mac) {
            EVP_MAC_free(m_mac);
            m_mac = nullptr;
        }
    }

    EvpMac(const EvpMac&)            = delete;
    EvpMac& operator=(const EvpMac&) = delete;

    EvpMac(EvpMac&& o) noexcept
        : m_mac(o.m_mac) { o.m_mac = nullptr; }

    EVP_MAC* get() const noexcept { return m_mac; }

    /// Create a new context from this MAC algorithm.
    EvpMacCtx NewCtx() {
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(m_mac);
        UAV_OPENSSL_CHECK_PTR(ctx, "EVP_MAC_CTX_new");
        return EvpMacCtx(ctx);
    }

private:
    EVP_MAC* m_mac = nullptr;
};

// ===========================================================================
// EvpPkeyCtx — RAII wrapper for EVP_PKEY_CTX
// Used for key derivation functions (future modules)
// ===========================================================================
class EvpPkeyCtx {
public:
    explicit EvpPkeyCtx(EVP_PKEY_CTX* ctx) : m_ctx(ctx) {
        UAV_OPENSSL_CHECK_PTR(m_ctx, "EvpPkeyCtx: null ctx");
    }

    ~EvpPkeyCtx() {
        if (m_ctx) {
            EVP_PKEY_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

    EvpPkeyCtx(const EvpPkeyCtx&)            = delete;
    EvpPkeyCtx& operator=(const EvpPkeyCtx&) = delete;

    EvpPkeyCtx(EvpPkeyCtx&& o) noexcept
        : m_ctx(o.m_ctx) { o.m_ctx = nullptr; }

    EVP_PKEY_CTX* get() const noexcept { return m_ctx; }

private:
    EVP_PKEY_CTX* m_ctx = nullptr;
};

} // namespace crypto
} // namespace uav

// ===========================================================================
// OpenSSLInit — one-time OpenSSL library lifecycle manager.
// Defined outside uav::crypto namespace for simple global access.
// Call OpenSSLInit::Bootstrap() once in main.cc before any crypto ops.
// ===========================================================================
class OpenSSLInit {
public:
    /// Load OpenSSL default provider. Idempotent — safe to call multiple times.
    static void Bootstrap();
    /// Cleanup OpenSSL resources at program exit.
    static void Cleanup();
};

#endif // UAV_OPENSSL_CTX_H
