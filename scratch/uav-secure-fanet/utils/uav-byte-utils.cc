/**
 * utils/uav-byte-utils.cc
 */

#include "uav-byte-utils.h"

#include <cstring>

namespace uav {
namespace utils {

// ---------------------------------------------------------------------------
// Big-endian writers
// ---------------------------------------------------------------------------

void ByteUtils::WriteU8(u8* dst, u8 v) {
    dst[0] = v;
}

void ByteUtils::WriteU16BE(u8* dst, u16 v) {
    dst[0] = static_cast<u8>((v >> 8) & 0xFF);
    dst[1] = static_cast<u8>( v       & 0xFF);
}

void ByteUtils::WriteU32BE(u8* dst, u32 v) {
    dst[0] = static_cast<u8>((v >> 24) & 0xFF);
    dst[1] = static_cast<u8>((v >> 16) & 0xFF);
    dst[2] = static_cast<u8>((v >>  8) & 0xFF);
    dst[3] = static_cast<u8>( v        & 0xFF);
}

void ByteUtils::WriteU64BE(u8* dst, u64 v) {
    dst[0] = static_cast<u8>((v >> 56) & 0xFF);
    dst[1] = static_cast<u8>((v >> 48) & 0xFF);
    dst[2] = static_cast<u8>((v >> 40) & 0xFF);
    dst[3] = static_cast<u8>((v >> 32) & 0xFF);
    dst[4] = static_cast<u8>((v >> 24) & 0xFF);
    dst[5] = static_cast<u8>((v >> 16) & 0xFF);
    dst[6] = static_cast<u8>((v >>  8) & 0xFF);
    dst[7] = static_cast<u8>( v        & 0xFF);
}

// ---------------------------------------------------------------------------
// Big-endian readers
// ---------------------------------------------------------------------------

u8 ByteUtils::ReadU8(const u8* src) {
    return src[0];
}

u16 ByteUtils::ReadU16BE(const u8* src) {
    return static_cast<u16>(
          (static_cast<u16>(src[0]) << 8)
        |  static_cast<u16>(src[1]));
}

u32 ByteUtils::ReadU32BE(const u8* src) {
    return  (static_cast<u32>(src[0]) << 24)
          | (static_cast<u32>(src[1]) << 16)
          | (static_cast<u32>(src[2]) <<  8)
          |  static_cast<u32>(src[3]);
}

u64 ByteUtils::ReadU64BE(const u8* src) {
    return  (static_cast<u64>(src[0]) << 56)
          | (static_cast<u64>(src[1]) << 48)
          | (static_cast<u64>(src[2]) << 40)
          | (static_cast<u64>(src[3]) << 32)
          | (static_cast<u64>(src[4]) << 24)
          | (static_cast<u64>(src[5]) << 16)
          | (static_cast<u64>(src[6]) <<  8)
          |  static_cast<u64>(src[7]);
}

// ---------------------------------------------------------------------------
// Append helpers
// ---------------------------------------------------------------------------

void ByteUtils::AppendU8(ByteBuffer& buf, u8 v) {
    buf.push_back(v);
}

void ByteUtils::AppendU16BE(ByteBuffer& buf, u16 v) {
    std::size_t off = buf.size();
    buf.resize(off + 2);
    WriteU16BE(buf.data() + off, v);
}

void ByteUtils::AppendU32BE(ByteBuffer& buf, u32 v) {
    std::size_t off = buf.size();
    buf.resize(off + 4);
    WriteU32BE(buf.data() + off, v);
}

void ByteUtils::AppendU64BE(ByteBuffer& buf, u64 v) {
    std::size_t off = buf.size();
    buf.resize(off + 8);
    WriteU64BE(buf.data() + off, v);
}

void ByteUtils::AppendBytes(ByteBuffer& buf, const u8* src, std::size_t n) {
    buf.insert(buf.end(), src, src + n);
}

void ByteUtils::AppendBytes(ByteBuffer& buf, const ByteBuffer& src) {
    buf.insert(buf.end(), src.begin(), src.end());
}

// ---------------------------------------------------------------------------
// Constant-time compare
// ---------------------------------------------------------------------------

bool ByteUtils::ConstantTimeEquals(const u8* a, const u8* b, std::size_t n) {
    // Volatile prevents compiler from short-circuiting on inequality.
    volatile u8 diff = 0;
    for (std::size_t i = 0; i < n; ++i) {
        diff |= static_cast<u8>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool ByteUtils::ConstantTimeEquals(const ByteBuffer& a, const ByteBuffer& b) {
    if (a.size() != b.size()) return false;
    return ConstantTimeEquals(a.data(), b.data(), a.size());
}

// ---------------------------------------------------------------------------
// Secure zero
// ---------------------------------------------------------------------------

void ByteUtils::SecureZero(void* ptr, std::size_t n) {
    volatile u8* p = static_cast<volatile u8*>(ptr);
    while (n--) {
        *p++ = 0;
    }
}

void ByteUtils::SecureZero(ByteBuffer& b) {
    if (!b.empty()) {
        SecureZero(b.data(), b.size());
    }
}

// ---------------------------------------------------------------------------
// Concat
// ---------------------------------------------------------------------------

ByteBuffer ByteUtils::Concat(const ByteBuffer& a, const ByteBuffer& b) {
    ByteBuffer out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace utils
} // namespace uav