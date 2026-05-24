#ifndef UAV_SHA256_H
#define UAV_SHA256_H

#include "uav-types.h"
#include "uav-error.h"
#include <openssl/sha.h>
#include <array>

namespace uav {
namespace crypto {

class Sha256Util {
public:
    static constexpr std::size_t OUTPUT_BYTES = 32;

    /// Compute SHA-256 over a byte buffer.
    /// Returns 32-byte digest.
    static std::array<utils::u8, OUTPUT_BYTES>
    Hash(const utils::ByteBuffer& data)
    {
        std::array<utils::u8, OUTPUT_BYTES> digest;
        SHA256(data.data(),
               static_cast<unsigned long>(data.size()),
               digest.data());
        return digest;
    }

    /// Compute SHA-256 over raw bytes.
    static std::array<utils::u8, OUTPUT_BYTES>
    Hash(const utils::u8* data, std::size_t len)
    {
        std::array<utils::u8, OUTPUT_BYTES> digest;
        SHA256(data, static_cast<unsigned long>(len), digest.data());
        return digest;
    }
};

} // namespace crypto
} // namespace uav

#endif // UAV_SHA256_H
