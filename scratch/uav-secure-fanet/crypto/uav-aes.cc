/**
 * crypto/uav-aes.cc
 */

#include "uav-aes.h"
#include "uav-openssl-error.h"
#include "uav-byte-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstring>

namespace uav {
namespace crypto {

// ===========================================================================
// Key generation
// ===========================================================================

AesGcmKey AesGcm::GenerateKey() {
    AesGcmKey key;
    OpenSSLRand::FillBytes(key.data(), key.size());
    return key;
}

AesGcmKey AesGcm::KeyFromBytes(const utils::ByteBuffer& raw) {
    return KeyFromBytes(raw.data(), raw.size());
}

AesGcmKey AesGcm::KeyFromBytes(const utils::u8* raw, std::size_t len) {
    if (len != AES_GCM_KEY_BYTES) {
        UAV_THROW(utils::CryptoException,
            "AesGcm::KeyFromBytes: expected 32 bytes, got " +
            std::to_string(len));
    }
    AesGcmKey key;
    std::memcpy(key.data(), raw, AES_GCM_KEY_BYTES);
    return key;
}

// ===========================================================================
// Internal encrypt implementation
// ===========================================================================

static AesGcmResult DoEncrypt(
    const AesGcmKey&                    key,
    const std::array<utils::u8, 12>&    iv,
    const utils::ByteBuffer&            plaintext,
    const utils::ByteBuffer&            aad)
{
    EvpCipherCtx ctx;

    // Init cipher type
    UAV_OPENSSL_CHECK(
        EVP_EncryptInit_ex(ctx.get(),
                           EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr),
        "AES-GCM EncryptInit cipher");

    // Set IV length to 12 bytes
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(AES_GCM_IV_BYTES),
                            nullptr),
        "AES-GCM set IV length");

    // Set key and IV
    UAV_OPENSSL_CHECK(
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), iv.data()),
        "AES-GCM EncryptInit key+iv");

    // Set AAD if provided
    if (!aad.empty()) {
        int aad_len = 0;
        UAV_OPENSSL_CHECK(
            EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len,
                              aad.data(),
                              static_cast<int>(aad.size())),
            "AES-GCM set AAD");
    }

    // Encrypt plaintext
    utils::ByteBuffer ciphertext(plaintext.size());
    int out_len = 0;

    if (!plaintext.empty()) {
        UAV_OPENSSL_CHECK(
            EVP_EncryptUpdate(ctx.get(),
                              ciphertext.data(), &out_len,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())),
            "AES-GCM EncryptUpdate");
    }

    // Finalise
    int final_len = 0;
    UAV_OPENSSL_CHECK(
        EVP_EncryptFinal_ex(ctx.get(),
                            ciphertext.data() + out_len,
                            &final_len),
        "AES-GCM EncryptFinal");

    ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

    // Extract GCM authentication tag
    std::array<utils::u8, AES_GCM_TAG_BYTES> tag{};
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(AES_GCM_TAG_BYTES),
                            tag.data()),
        "AES-GCM get tag");

    AesGcmResult result;
    result.ciphertext = std::move(ciphertext);
    result.iv         = iv;
    result.tag        = tag;
    return result;
}

// ===========================================================================
// Encrypt (random IV)
// ===========================================================================

AesGcmResult AesGcm::Encrypt(
    const AesGcmKey&         key,
    const utils::ByteBuffer& plaintext,
    const utils::ByteBuffer& aad)
{
    auto iv = OpenSSLRand::RandomGcmIv();
    return DoEncrypt(key, iv, plaintext, aad);
}

AesGcmResult AesGcm::EncryptWithIv(
    const AesGcmKey&                    key,
    const std::array<utils::u8, 12>&    iv,
    const utils::ByteBuffer&            plaintext,
    const utils::ByteBuffer&            aad)
{
    return DoEncrypt(key, iv, plaintext, aad);
}

// ===========================================================================
// Decrypt
// ===========================================================================

utils::ByteBuffer AesGcm::Decrypt(
    const AesGcmKey&                    key,
    const std::array<utils::u8, 12>&    iv,
    const utils::ByteBuffer&            ciphertext,
    const std::array<utils::u8, 16>&    tag,
    const utils::ByteBuffer&            aad)
{
    EvpCipherCtx ctx;

    // Init cipher type
    UAV_OPENSSL_CHECK(
        EVP_DecryptInit_ex(ctx.get(),
                           EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr),
        "AES-GCM DecryptInit cipher");

    // Set IV length
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(AES_GCM_IV_BYTES),
                            nullptr),
        "AES-GCM set IV length decrypt");

    // Set key and IV
    UAV_OPENSSL_CHECK(
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), iv.data()),
        "AES-GCM DecryptInit key+iv");

    // Set AAD if provided
    if (!aad.empty()) {
        int aad_len = 0;
        UAV_OPENSSL_CHECK(
            EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len,
                              aad.data(),
                              static_cast<int>(aad.size())),
            "AES-GCM set AAD decrypt");
    }

    // Decrypt ciphertext
    utils::ByteBuffer plaintext(
        ciphertext.empty() ? 0 : ciphertext.size());
    int out_len = 0;

    if (!ciphertext.empty()) {
        UAV_OPENSSL_CHECK(
            EVP_DecryptUpdate(ctx.get(),
                              plaintext.data(), &out_len,
                              ciphertext.data(),
                              static_cast<int>(ciphertext.size())),
            "AES-GCM DecryptUpdate");
    }

    // Set expected tag BEFORE DecryptFinal
    UAV_OPENSSL_CHECK(
        EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(AES_GCM_TAG_BYTES),
                            const_cast<utils::u8*>(tag.data())),
        "AES-GCM set tag for verify");

    // Finalise — returns 1 if tag OK, -1 if tag mismatch
    int final_len = 0;
    int verify = EVP_DecryptFinal_ex(
        ctx.get(),
        plaintext.data() + out_len,
        &final_len);

    if (verify != 1) {
        UAV_THROW(utils::CryptoException,
            "AES-GCM authentication tag verification FAILED — "
            "data may have been tampered");
    }

    plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    return plaintext;
}

// ===========================================================================
// Wire format
// ===========================================================================

utils::ByteBuffer AesGcm::Serialize(const AesGcmResult& result) {
    // Layout: [IV(12)][ciphertext][TAG(16)]
    utils::ByteBuffer wire;
    wire.reserve(AES_GCM_IV_BYTES +
                 result.ciphertext.size() +
                 AES_GCM_TAG_BYTES);

    utils::ByteUtils::AppendBytes(wire,
        result.iv.data(), result.iv.size());
    utils::ByteUtils::AppendBytes(wire, result.ciphertext);
    utils::ByteUtils::AppendBytes(wire,
        result.tag.data(), result.tag.size());

    return wire;
}

AesGcmResult AesGcm::Deserialize(const utils::ByteBuffer& wire) {
    if (wire.size() < AES_GCM_OVERHEAD) {
        UAV_THROW(utils::SerializationException,
            "AesGcm::Deserialize: buffer too short ("
            + std::to_string(wire.size())
            + " bytes, need >= "
            + std::to_string(AES_GCM_OVERHEAD) + ")");
    }

    AesGcmResult result;

    // Extract IV (first 12 bytes)
    std::memcpy(result.iv.data(), wire.data(), AES_GCM_IV_BYTES);

    // Extract tag (last 16 bytes)
    std::memcpy(result.tag.data(),
                wire.data() + wire.size() - AES_GCM_TAG_BYTES,
                AES_GCM_TAG_BYTES);

    // Extract ciphertext (middle)
    std::size_t ct_size = wire.size() - AES_GCM_OVERHEAD;
    result.ciphertext.assign(
        wire.begin() + AES_GCM_IV_BYTES,
        wire.begin() + AES_GCM_IV_BYTES +
            static_cast<std::ptrdiff_t>(ct_size));

    return result;
}

// ===========================================================================
// Convenience wrappers
// ===========================================================================

utils::ByteBuffer AesGcm::EncryptToWire(
    const AesGcmKey&         key,
    const utils::ByteBuffer& plaintext,
    const utils::ByteBuffer& aad)
{
    return Serialize(Encrypt(key, plaintext, aad));
}

utils::ByteBuffer AesGcm::DecryptFromWire(
    const AesGcmKey&         key,
    const utils::ByteBuffer& wire,
    const utils::ByteBuffer& aad)
{
    auto result = Deserialize(wire);
    return Decrypt(key, result.iv, result.ciphertext,
                   result.tag, aad);
}

// ===========================================================================
// TEK helpers
// ===========================================================================

utils::ByteBuffer AesGcm::EncryptTek(
    const AesGcmKey&         kek,
    const AesGcmKey&         tek,
    const utils::ByteBuffer& aad)
{
    utils::ByteBuffer tek_buf(tek.begin(), tek.end());
    return EncryptToWire(kek, tek_buf, aad);
}

AesGcmKey AesGcm::DecryptTek(
    const AesGcmKey&         kek,
    const utils::ByteBuffer& wire,
    const utils::ByteBuffer& aad)
{
    utils::ByteBuffer raw = DecryptFromWire(kek, wire, aad);
    if (raw.size() != AES_GCM_KEY_BYTES) {
        UAV_THROW(utils::CryptoException,
            "AesGcm::DecryptTek: expected 32 bytes, got "
            + std::to_string(raw.size()));
    }
    return KeyFromBytes(raw);
}

// ===========================================================================
// Key derivation (SHA-256 based KDF)
// ===========================================================================

AesGcmKey AesGcm::DeriveKey(
    const AesGcmKey&         input_key,
    const utils::ByteBuffer& context)
{
    // Simple KDF: SHA-256(input_key || context)
    // For production HKDF would be used — this is sufficient
    // for TEK rotation within the simulation.
    EvpMdCtx ctx;

    UAV_OPENSSL_CHECK(
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr),
        "AesGcm::DeriveKey DigestInit");

    UAV_OPENSSL_CHECK(
        EVP_DigestUpdate(ctx.get(),
                         input_key.data(),
                         input_key.size()),
        "AesGcm::DeriveKey DigestUpdate key");

    if (!context.empty()) {
        UAV_OPENSSL_CHECK(
            EVP_DigestUpdate(ctx.get(),
                             context.data(),
                             context.size()),
            "AesGcm::DeriveKey DigestUpdate context");
    }

    AesGcmKey derived{};
    unsigned int digest_len = 0;

    UAV_OPENSSL_CHECK(
        EVP_DigestFinal_ex(ctx.get(),
                           derived.data(),
                           &digest_len),
        "AesGcm::DeriveKey DigestFinal");

    if (digest_len != AES_GCM_KEY_BYTES) {
        UAV_THROW(utils::CryptoException,
            "AesGcm::DeriveKey: unexpected digest length "
            + std::to_string(digest_len));
    }

    return derived;
}

} // namespace crypto
} // namespace uav