/**
 * utils/uav-byte-utils.h
 * Byte-level helpers — endian-safe integer packing for packet serialization.
 *
 * ALL packet headers use BIG-ENDIAN (network byte order) for u16/u32/u64
 * fields. These helpers provide a single, consistent way to read/write
 * those fields. Module 16+ packet headers MUST use this API rather than
 * raw casts.
 */

#ifndef UAV_BYTE_UTILS_H
#define UAV_BYTE_UTILS_H

#include "uav-types.h"
#include <cstddef>

namespace uav {
namespace utils {

class ByteUtils {
public:
    // -----------------------------------------------------------------------
    // Write big-endian (network byte order) to a raw pointer.
    // Caller must guarantee at least sizeof(T) bytes are writable.
    // -----------------------------------------------------------------------
    static void WriteU8 (u8*  dst, u8  v);
    static void WriteU16BE(u8* dst, u16 v);
    static void WriteU32BE(u8* dst, u32 v);
    static void WriteU64BE(u8* dst, u64 v);

    // -----------------------------------------------------------------------
    // Read big-endian
    // -----------------------------------------------------------------------
    static u8  ReadU8 (const u8* src);
    static u16 ReadU16BE(const u8* src);
    static u32 ReadU32BE(const u8* src);
    static u64 ReadU64BE(const u8* src);

    // -----------------------------------------------------------------------
    // Append-to-buffer helpers (resize automatically)
    // -----------------------------------------------------------------------
    static void AppendU8 (ByteBuffer& buf, u8  v);
    static void AppendU16BE(ByteBuffer& buf, u16 v);
    static void AppendU32BE(ByteBuffer& buf, u32 v);
    static void AppendU64BE(ByteBuffer& buf, u64 v);
    static void AppendBytes(ByteBuffer& buf, const u8* src, std::size_t n);
    static void AppendBytes(ByteBuffer& buf, const ByteBuffer& src);

    // -----------------------------------------------------------------------
    // Constant-time comparison — for HMAC verification.
    // Returns true if memcmp would return 0, but takes time independent
    // of where the first differing byte lies (mitigates timing attacks).
    // -----------------------------------------------------------------------
    static bool ConstantTimeEquals(const u8* a, const u8* b, std::size_t n);
    static bool ConstantTimeEquals(const ByteBuffer& a, const ByteBuffer& b);

    // -----------------------------------------------------------------------
    // Zero-fill (used to scrub sensitive buffers — keys, MT_K plaintexts).
    // Uses volatile pointer to prevent compiler from optimising it away.
    // -----------------------------------------------------------------------
    static void SecureZero(void* ptr, std::size_t n);
    static void SecureZero(ByteBuffer& b);

    // -----------------------------------------------------------------------
    // Concatenate two byte buffers
    // -----------------------------------------------------------------------
    static ByteBuffer Concat(const ByteBuffer& a, const ByteBuffer& b);
};

} // namespace utils
} // namespace uav

#endif // UAV_BYTE_UTILS_H