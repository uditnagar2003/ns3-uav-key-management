/**
 * crypto/uav-openssl-rand.cc
 */

#include "uav-openssl-rand.h"
#include "uav-openssl-error.h"

#include <openssl/rand.h>
#include <cstring>

namespace uav {
namespace crypto {

// ---------------------------------------------------------------------------
// FillBytes
// ---------------------------------------------------------------------------
void OpenSSLRand::FillBytes(utils::u8* buf, std::size_t len) {
    if (!buf || len == 0) return;
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) {
        UAV_OPENSSL_THROW("OpenSSLRand::FillBytes");
    }
}

// ---------------------------------------------------------------------------
// RandomBytes
// ---------------------------------------------------------------------------
utils::ByteBuffer OpenSSLRand::RandomBytes(std::size_t len) {
    utils::ByteBuffer buf(len);
    FillBytes(buf.data(), len);
    return buf;
}

// ---------------------------------------------------------------------------
// Fixed-size specializations
// ---------------------------------------------------------------------------
utils::Aes256Key OpenSSLRand::RandomAes256Key() {
    utils::Aes256Key key;
    FillBytes(key.data(), key.size());
    return key;
}

utils::AesIv OpenSSLRand::RandomAesIv() {
    utils::AesIv iv;
    FillBytes(iv.data(), iv.size());
    return iv;
}

std::array<utils::u8, 12> OpenSSLRand::RandomGcmIv() {
    std::array<utils::u8, 12> iv;
    FillBytes(iv.data(), iv.size());
    return iv;
}

utils::Nonce128 OpenSSLRand::RandomNonce128() {
    utils::Nonce128 nonce;
    FillBytes(nonce.data(), nonce.size());
    return nonce;
}

utils::HmacSha256 OpenSSLRand::RandomHmacKey() {
    utils::HmacSha256 key;
    FillBytes(key.data(), key.size());
    return key;
}

// ---------------------------------------------------------------------------
// RandomU64
// ---------------------------------------------------------------------------
utils::u64 OpenSSLRand::RandomU64() {
    utils::u64 val = 0;
    FillBytes(reinterpret_cast<utils::u8*>(&val), sizeof(val));
    return val;
}

// ---------------------------------------------------------------------------
// IsSeeded / AddEntropy
// ---------------------------------------------------------------------------
bool OpenSSLRand::IsSeeded() {
    return RAND_status() == 1;
}

void OpenSSLRand::AddEntropy(const utils::u8* buf,
                              std::size_t len,
                              double entropy_estimate) {
    RAND_add(buf, static_cast<int>(len), entropy_estimate);
}

} // namespace crypto
} // namespace uav