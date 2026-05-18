/**
 * crypto/uav-hmac.cc
 */

#include "uav-hmac.h"
#include "uav-openssl-error.h"
#include "uav-byte-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

#include <cstring>

namespace uav {
namespace crypto {

// ===========================================================================
// Key generation
// ===========================================================================

HmacKey HmacSha256Util::GenerateKey() {
    HmacKey key;
    OpenSSLRand::FillBytes(key.data(), key.size());
    return key;
}

HmacKey HmacSha256Util::KeyFromBytes(const utils::u8* raw,
                                      std::size_t len) {
    if (len != HMAC_KEY_BYTES) {
        UAV_THROW(utils::CryptoException,
            "HmacSha256Util::KeyFromBytes: expected 32 bytes, got "
            + std::to_string(len));
    }
    HmacKey key;
    std::memcpy(key.data(), raw, HMAC_KEY_BYTES);
    return key;
}

HmacKey HmacSha256Util::KeyFromBytes(const utils::ByteBuffer& raw) {
    return KeyFromBytes(raw.data(), raw.size());
}

HmacKey HmacSha256Util::KeyFromAesKey(
    const std::array<utils::u8, 32>& aes_key) {
    HmacKey key;
    std::memcpy(key.data(), aes_key.data(), HMAC_KEY_BYTES);
    return key;
}

// ===========================================================================
// Internal HMAC computation using OpenSSL 3.x EVP_MAC API
// ===========================================================================

namespace {

/// Simple segment descriptor
struct DataSegment {
    const utils::u8* data;
    std::size_t      len;
};

/// Shared HMAC computation over multiple iovec-style segments.
utils::HmacSha256 DoHmac(
    const HmacKey&                  key,
    const std::vector<DataSegment>& segments)
{
    // Fetch HMAC algorithm (cached internally by OpenSSL)
    EvpMac mac("HMAC");
    EvpMacCtx ctx = mac.NewCtx();

    // Parameters: digest = SHA-256
    OSSL_PARAM params[2];
    const char* digest_name = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(
        "digest",
        const_cast<char*>(digest_name),
        0);
    params[1] = OSSL_PARAM_construct_end();

    // Init with key and parameters
    UAV_OPENSSL_CHECK(
        EVP_MAC_init(ctx.get(),
                     key.data(),
                     key.size(),
                     params),
        "HMAC-SHA256 EVP_MAC_init");

    // Update with each segment
    for (const auto& seg : segments) {
        if (seg.data && seg.len > 0) {
            UAV_OPENSSL_CHECK(
                EVP_MAC_update(ctx.get(), seg.data, seg.len),
                "HMAC-SHA256 EVP_MAC_update");
        }
    }

    // Finalise
    utils::HmacSha256 hmac{};
    std::size_t out_len = hmac.size();
    UAV_OPENSSL_CHECK(
        EVP_MAC_final(ctx.get(),
                      hmac.data(),
                      &out_len,
                      hmac.size()),
        "HMAC-SHA256 EVP_MAC_final");

    if (out_len != HMAC_SHA256_OUTPUT_BYTES) {
        UAV_THROW(utils::CryptoException,
            "HMAC-SHA256: unexpected output length "
            + std::to_string(out_len));
    }

    return hmac;
}

} // anonymous namespace

// ===========================================================================
// Compute
// ===========================================================================

utils::HmacSha256 HmacSha256Util::Compute(
    const HmacKey&           key,
    const utils::ByteBuffer& data)
{
    return Compute(key, data.data(), data.size());
}

utils::HmacSha256 HmacSha256Util::Compute(
    const HmacKey&   key,
    const utils::u8* data,
    std::size_t      len)
{
    std::vector<DataSegment> segs;
    segs.push_back({data, len});
    return DoHmac(key, segs);
}

utils::HmacSha256 HmacSha256Util::ComputeMulti(
    const HmacKey&                        key,
    const std::vector<utils::ByteBuffer>& parts)
{
    std::vector<DataSegment> segs;
    segs.reserve(parts.size());
    for (const auto& p : parts) {
        segs.push_back({p.data(), p.size()});
    }
    return DoHmac(key, segs);
}

// ===========================================================================
// Verify (constant-time)
// ===========================================================================

bool HmacSha256Util::Verify(
    const HmacKey&           key,
    const utils::ByteBuffer& data,
    const utils::HmacSha256& expected)
{
    return Verify(key, data.data(), data.size(), expected);
}

bool HmacSha256Util::Verify(
    const HmacKey&           key,
    const utils::u8*         data,
    std::size_t              len,
    const utils::HmacSha256& expected)
{
    utils::HmacSha256 computed = Compute(key, data, len);
    // Constant-time comparison — prevents timing attacks
    return utils::ByteUtils::ConstantTimeEquals(
        computed.data(),
        expected.data(),
        HMAC_SHA256_OUTPUT_BYTES);
}

void HmacSha256Util::VerifyOrThrow(
    const HmacKey&           key,
    const utils::ByteBuffer& data,
    const utils::HmacSha256& expected)
{
    if (!Verify(key, data, expected)) {
        UAV_THROW(utils::CryptoException,
            "HMAC-SHA256 verification FAILED — "
            "packet integrity compromised");
    }
}

// ===========================================================================
// Packet-level helpers
// ===========================================================================

void HmacSha256Util::AppendHmac(
    const HmacKey&     key,
    utils::ByteBuffer& packet)
{
    auto hmac = Compute(key, packet);
    utils::ByteUtils::AppendBytes(
        packet, hmac.data(), hmac.size());
}

utils::ByteBuffer HmacSha256Util::StripAndVerifyHmac(
    const HmacKey&           key,
    const utils::ByteBuffer& packet_with_hmac)
{
    if (packet_with_hmac.size() < HMAC_SHA256_OUTPUT_BYTES) {
        UAV_THROW(utils::SerializationException,
            "StripAndVerifyHmac: packet too short ("
            + std::to_string(packet_with_hmac.size())
            + " bytes, need >= 32)");
    }

    // Split packet: body + hmac
    std::size_t body_len =
        packet_with_hmac.size() - HMAC_SHA256_OUTPUT_BYTES;

    utils::ByteBuffer body(
        packet_with_hmac.begin(),
        packet_with_hmac.begin() +
            static_cast<std::ptrdiff_t>(body_len));

    utils::HmacSha256 expected{};
    std::memcpy(expected.data(),
                packet_with_hmac.data() + body_len,
                HMAC_SHA256_OUTPUT_BYTES);

    // Verify
    VerifyOrThrow(key, body, expected);

    return body;
}

// ===========================================================================
// SHA-256 (no key)
// ===========================================================================

utils::Sha256Hash HmacSha256Util::Sha256(
    const utils::ByteBuffer& data)
{
    return Sha256(data.data(), data.size());
}

utils::Sha256Hash HmacSha256Util::Sha256(
    const utils::u8* data,
    std::size_t      len)
{
    EvpMdCtx ctx;

    UAV_OPENSSL_CHECK(
        EVP_DigestInit_ex(ctx.get(),
                          EVP_sha256(),
                          nullptr),
        "SHA256 DigestInit");

    if (data && len > 0) {
        UAV_OPENSSL_CHECK(
            EVP_DigestUpdate(ctx.get(), data, len),
            "SHA256 DigestUpdate");
    }

    utils::Sha256Hash digest{};
    unsigned int digest_len = 0;

    UAV_OPENSSL_CHECK(
        EVP_DigestFinal_ex(ctx.get(),
                           digest.data(),
                           &digest_len),
        "SHA256 DigestFinal");

    if (digest_len != 32) {
        UAV_THROW(utils::CryptoException,
            "SHA256: unexpected digest length "
            + std::to_string(digest_len));
    }

    return digest;
}

utils::Sha256Hash HmacSha256Util::Sha256(const std::string& s) {
    return Sha256(
        reinterpret_cast<const utils::u8*>(s.data()),
        s.size());
}

} // namespace crypto
} // namespace uav