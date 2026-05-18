/**
 * utils/uav-math-utils.cc
 */

#include "uav-math-utils.h"

#include <cmath>
#include <random>

namespace uav {
namespace utils {

// ===========================================================================
// MathUtils
// ===========================================================================

double MathUtils::Distance3D(const Vec3& a, const Vec3& b) {
    return std::sqrt(DistanceSquared3D(a, b));
}

double MathUtils::DistanceSquared3D(const Vec3& a, const Vec3& b) {
    double dx = a.x - b.x;
    double dy = a.y - b.y;
    double dz = a.z - b.z;
    return dx * dx + dy * dy + dz * dz;
}

bool MathUtils::NearlyEqual(double a, double b, double tol) {
    return std::fabs(a - b) <= tol;
}

double MathUtils::DbToLinear(double db) {
    return std::pow(10.0, db / 10.0);
}

double MathUtils::LinearToDb(double linear) {
    if (linear <= 0.0) {
        return -std::numeric_limits<double>::infinity();
    }
    return 10.0 * std::log10(linear);
}

// ===========================================================================
// SecureRandom
// ===========================================================================

SecureRandom::SecureRandom() {
    std::random_device rd;
    // Mix two random_device draws to seed mt19937_64.
    u64 seed = (static_cast<u64>(rd()) << 32) ^ static_cast<u64>(rd());
    m_engine.seed(seed);
}

SecureRandom& SecureRandom::Instance() {
    static SecureRandom inst;
    return inst;
}

void SecureRandom::Seed(u64 seed) {
    m_engine.seed(seed);
}

u32 SecureRandom::NextU32() {
    return static_cast<u32>(m_engine() & 0xFFFFFFFFULL);
}

u64 SecureRandom::NextU64() {
    return m_engine();
}

double SecureRandom::NextDouble() {
    // 53-bit mantissa — standard idiom.
    constexpr double kInv = 1.0 / 9007199254740992.0;  // 2^53
    return static_cast<double>(m_engine() >> 11) * kInv;
}

double SecureRandom::NextDouble(double lo, double hi) {
    return lo + (hi - lo) * NextDouble();
}

u32 SecureRandom::NextU32InRange(u32 lo, u32 hi) {
    if (lo >= hi) return lo;
    std::uniform_int_distribution<u32> dist(lo, hi);
    return dist(m_engine);
}

bool SecureRandom::NextBool(double prob_true) {
    return NextDouble() < prob_true;
}

void SecureRandom::FillBytes(u8* dst, std::size_t n) {
    // Fill in 8-byte chunks for efficiency.
    std::size_t i = 0;
    while (i + 8 <= n) {
        u64 r = m_engine();
        for (int j = 0; j < 8; ++j) {
            dst[i + j] = static_cast<u8>((r >> (8 * j)) & 0xFF);
        }
        i += 8;
    }
    if (i < n) {
        u64 r = m_engine();
        while (i < n) {
            dst[i++] = static_cast<u8>(r & 0xFF);
            r >>= 8;
        }
    }
}

ByteBuffer SecureRandom::RandomBytes(std::size_t n) {
    ByteBuffer out(n);
    FillBytes(out.data(), n);
    return out;
}

} // namespace utils
} // namespace uav