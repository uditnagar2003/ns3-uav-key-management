/**
 * utils/uav-math-utils.h
 * Math helpers — RNG seeding, distance, clamping, rounding.
 *
 * The RNG here is for project-internal use only (e.g. generating nonces
 * in C++ when not using OpenSSL RAND_bytes, or random selection in
 * application logic). NS-3 has its own RngStream — that is used for
 * simulation reproducibility (Module 30).
 */

#ifndef UAV_MATH_UTILS_H
#define UAV_MATH_UTILS_H

#include "uav-types.h"
#include <random>

namespace uav {
namespace utils {

class MathUtils {
public:
    // -----------------------------------------------------------------------
    // 3D Euclidean distance
    // -----------------------------------------------------------------------
    static double Distance3D(const Vec3& a, const Vec3& b);
    static double DistanceSquared3D(const Vec3& a, const Vec3& b);

    // -----------------------------------------------------------------------
    // Clamp / saturate
    // -----------------------------------------------------------------------
    template <typename T>
    static T Clamp(T v, T lo, T hi) {
        return (v < lo) ? lo : ((v > hi) ? hi : v);
    }

    // -----------------------------------------------------------------------
    // Float comparison (within absolute tolerance)
    // -----------------------------------------------------------------------
    static bool NearlyEqual(double a, double b, double tol = 1e-9);

    // -----------------------------------------------------------------------
    // dB <-> linear
    // -----------------------------------------------------------------------
    static double DbToLinear(double db);
    static double LinearToDb(double linear);
};

// ---------------------------------------------------------------------------
// SecureRandom — wraps std::random_device + Mersenne twister.
// For cryptographic RNG, use crypto::AesUtils::RandomBytes (OpenSSL) instead.
// This RNG is for non-crypto application logic (selecting random nodes,
// generating cluster offsets, etc.).
// ---------------------------------------------------------------------------
class SecureRandom {
public:
    /// Singleton-style accessor (one global stream).
    static SecureRandom& Instance();

    /// Reseed deterministically — used for reproducible tests/scenarios.
    void Seed(u64 seed);

    u32    NextU32();
    u64    NextU64();
    double NextDouble();                       // [0.0, 1.0)
    double NextDouble(double lo, double hi);   // [lo,  hi)
    u32    NextU32InRange(u32 lo, u32 hi);     // [lo, hi]
    bool   NextBool(double prob_true);

    /// Fill a buffer with random bytes (non-crypto strength).
    void FillBytes(u8* dst, std::size_t n);
    ByteBuffer RandomBytes(std::size_t n);

private:
    SecureRandom();
    std::mt19937_64 m_engine;
};

} // namespace utils
} // namespace uav

#endif // UAV_MATH_UTILS_H