/**
 * crypto/uav-bigint-utils.h
 * Header-only convenience aliases and literal helpers.
 *
 * Included by any module that needs quick access to BigInt
 * without pulling in BigIntOps method bodies.
 */

#ifndef UAV_BIGINT_UTILS_H
#define UAV_BIGINT_UTILS_H

#include "uav-bigint.h"
#include <string>

namespace uav {
namespace crypto {

// ---------------------------------------------------------------------------
// Literal constructor helpers
// ---------------------------------------------------------------------------

/// Construct BigInt from decimal string literal.
inline BigInt B(const std::string& s) {
    return BigIntOps::FromDecString(s);
}

/// Construct BigInt from integer literal.
inline BigInt B(long long v) {
    return BigInt(v);
}

inline BigInt B(unsigned long long v) {
    return BigInt(v);
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------
inline bool IsZero(const BigInt& n) { return n == 0; }
inline bool IsOne (const BigInt& n) { return n == 1; }
inline bool IsNeg (const BigInt& n) { return n < 0;  }

// ---------------------------------------------------------------------------
// Range check
// ---------------------------------------------------------------------------
inline bool FitsU64(const BigInt& n) {
    return n >= 0 &&
           n <= BigInt("18446744073709551615"); // 2^64 - 1
}

inline bool FitsU32(const BigInt& n) {
    return n >= 0 && n <= BigInt(0xFFFFFFFFULL);
}

} // namespace crypto
} // namespace uav

#endif // UAV_BIGINT_UTILS_H