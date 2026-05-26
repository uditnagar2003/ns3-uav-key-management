/**
 * crypto/uav-handover-protocol.h
 *
 * Global Bootstrap Key (GK) utilities for inter-cluster handover.
 *
 * PROTOCOL ROLES:
 *   GK — AES-256 key pre-provisioned to ALL nodes (KDC, SKDCs, UAVs).
 *        Used ONLY to encrypt/decrypt slave key delivery packets.
 *        Never used for data payload encryption (TEK handles that).
 *
 * PACKET TYPES:
 *   HANDOVER_NOTIFY  — Old SKDC → KDC (CSMA, port 9000)
 *   SLAVE_FWD        — KDC → New SKDC (CSMA, port 9001)
 *   JOIN_ACCEPT      — New SKDC → UAV  (WiFi unicast, port 9200)
 *   KEY_ACK          — UAV → New SKDC  (WiFi unicast, port 9100)
 *
 * SECURITY:
 *   All packets carry HMAC-SHA256 keyed with GK.
 *   Slave key blob encrypted AES-256-GCM with GK.
 *   Replay protection: timestamp + nonce in every packet.
 */

#ifndef UAV_HANDOVER_PROTOCOL_H
#define UAV_HANDOVER_PROTOCOL_H

#include "crypto/uav-aes.h"
#include "crypto/uav-hmac.h"
#include "crypto/uav-crypto-params.h"
#include "utils/uav-types.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-error.h"

#include <array>
#include <cstring>
#include <chrono>

namespace uav {
namespace crypto {

// ============================================================================
// GlobalKey — 32-byte AES-256 GK type alias
// ============================================================================
using GlobalKey = std::array<utils::u8, 32>;

// ============================================================================
// SlaveKeyBlob — serialized slave key params for delivery
//
// Contains everything a UAV needs to operate in a new cluster:
//   d_i, n_i, e_i, Mi, Ni (all as 256-byte big-endian padded fields)
//
// Wire size: 5 × 256 = 1280 bytes plaintext
// Encrypted: 1280 + 12 (iv) + 16 (tag) = 1308 bytes
// ============================================================================
static constexpr size_t BIGINT_FIELD_BYTES = 256; // 2048-bit max
static constexpr size_t SLAVE_BLOB_PLAIN   = BIGINT_FIELD_BYTES * 5 + 8;
// +8: uav_index(4) + new_cluster(4)

struct SlaveKeyBlob {
    utils::u32 uav_index  = 0;
    utils::u32 cluster_id = 0;
    // Each BigInt serialized as BIGINT_FIELD_BYTES big-endian bytes
    utils::ByteBuffer d_i_bytes;
    utils::ByteBuffer n_i_bytes;
    utils::ByteBuffer e_i_bytes;
    utils::ByteBuffer Mi_bytes;
    utils::ByteBuffer Ni_bytes;

    /// Serialize to fixed-size buffer (SLAVE_BLOB_PLAIN bytes)
    utils::ByteBuffer Serialize() const {
        utils::ByteBuffer buf(SLAVE_BLOB_PLAIN, 0x00);
        utils::ByteUtils::WriteU32BE(buf.data(), uav_index);
        utils::ByteUtils::WriteU32BE(buf.data()+4, cluster_id);
        auto write_field = [&](size_t off,
                               const utils::ByteBuffer& v) {
            size_t n = std::min(v.size(), BIGINT_FIELD_BYTES);
            std::memcpy(buf.data() + off +
                (BIGINT_FIELD_BYTES - n), v.data(), n);
        };
        write_field(8,                       d_i_bytes);
        write_field(8 + BIGINT_FIELD_BYTES,  n_i_bytes);
        write_field(8 + BIGINT_FIELD_BYTES*2,e_i_bytes);
        write_field(8 + BIGINT_FIELD_BYTES*3,Mi_bytes);
        write_field(8 + BIGINT_FIELD_BYTES*4,Ni_bytes);
        return buf;
    }

    /// Deserialize from fixed-size buffer
    static SlaveKeyBlob Deserialize(
            const utils::ByteBuffer& buf) {
        if (buf.size() < SLAVE_BLOB_PLAIN)
            UAV_THROW(utils::SerializationException,
                "SlaveKeyBlob: buffer too small");
        SlaveKeyBlob b;
        b.uav_index  = utils::ByteUtils::ReadU32BE(buf.data());
        b.cluster_id = utils::ByteUtils::ReadU32BE(buf.data()+4);
        auto read_field = [&](size_t off) {
            utils::ByteBuffer v(BIGINT_FIELD_BYTES);
            std::memcpy(v.data(), buf.data()+off, BIGINT_FIELD_BYTES);
            return v;
        };
        b.d_i_bytes = read_field(8);
        b.n_i_bytes = read_field(8 + BIGINT_FIELD_BYTES);
        b.e_i_bytes = read_field(8 + BIGINT_FIELD_BYTES*2);
        b.Mi_bytes  = read_field(8 + BIGINT_FIELD_BYTES*3);
        b.Ni_bytes  = read_field(8 + BIGINT_FIELD_BYTES*4);
        return b;
    }
};

// ============================================================================
// HandoverProtocol — static helpers for packet build/parse
// ============================================================================
class HandoverProtocol {
public:
    // -----------------------------------------------------------------------
    // HANDOVER_NOTIFY (Old SKDC → KDC)
    // Wire: [type(1)][uav_id(4)][old_c(4)][new_c(4)][old_idx(4)]
    //       [ts(8)][nonce(16)][HMAC(32)]  = 73 bytes
    // -----------------------------------------------------------------------
    static constexpr uint8_t TYPE_NOTIFY    = 0x10;
    static constexpr uint8_t TYPE_SLAVE_FWD = 0x11;
    static constexpr uint8_t TYPE_JOIN_ACC  = 0x12;
    static constexpr uint8_t TYPE_KEY_ACK   = 0x13;

    static constexpr uint16_t PORT_KDC_HO   = 9050; // KDC handover port
    static constexpr uint16_t PORT_SKDC_FWD = 9051; // new SKDC receives FWD
    static constexpr uint16_t PORT_UAV_HO   = 9052; // UAV receives JOIN_ACCEPT
    static constexpr uint16_t PORT_SKDC_ACK = 9053; // SKDC receives KEY_ACK

    struct NotifyPkt {
        uint32_t uav_id      = 0;
        uint32_t old_cluster = 0;
        uint32_t new_cluster = 0;
        uint32_t old_index   = 0;
        uint64_t timestamp   = 0;
        std::array<uint8_t,16> nonce{};
    };

    struct SlaveAckPkt {
        uint32_t uav_id      = 0;
        uint32_t new_cluster = 0;
        uint32_t new_index   = 0;
        uint64_t timestamp   = 0;
        std::array<uint8_t,16> nonce{};
    };

    /// Build HANDOVER_NOTIFY bytes (HMAC keyed with GK)
    static utils::ByteBuffer BuildNotify(
        uint32_t uav_id, uint32_t old_c,
        uint32_t new_c,  uint32_t old_idx,
        const GlobalKey& gk)
    {
        utils::ByteBuffer buf(37, 0x00); // 1+4+4+4+4+8+16 - hmac portion
        buf[0] = TYPE_NOTIFY;
        utils::ByteUtils::WriteU32BE(buf.data()+1,  uav_id);
        utils::ByteUtils::WriteU32BE(buf.data()+5,  old_c);
        utils::ByteUtils::WriteU32BE(buf.data()+9,  new_c);
        utils::ByteUtils::WriteU32BE(buf.data()+13, old_idx);
        uint64_t ts = NowUs();
        utils::ByteUtils::WriteU64BE(buf.data()+17, ts);
        auto nonce_key = AesGcm::GenerateKey();
        std::array<uint8_t,12> nonce{};
        std::memcpy(nonce.data(), nonce_key.data(), 12);
        std::memcpy(buf.data()+25, nonce.data(), 12);
        // pad nonce to 16 bytes (12 used)
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        HmacSha256Util::AppendHmac(hk, buf);
        return buf;
    }

    static bool ParseNotify(
        const utils::ByteBuffer& buf,
        NotifyPkt& out,
        const GlobalKey& gk)
    {
        if (buf.size() < 37+32) return false;
        if (buf[0] != TYPE_NOTIFY) return false;
        utils::ByteBuffer data(buf.begin(), buf.end()-32);
        utils::HmacSha256 hmac{};
        std::memcpy(hmac.data(), buf.data() + buf.size() - 32, 32);
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        if (!HmacSha256Util::Verify(hk, data, hmac))
            return false;
        out.uav_id      = utils::ByteUtils::ReadU32BE(buf.data()+1);
        out.old_cluster = utils::ByteUtils::ReadU32BE(buf.data()+5);
        out.new_cluster = utils::ByteUtils::ReadU32BE(buf.data()+9);
        out.old_index   = utils::ByteUtils::ReadU32BE(buf.data()+13);
        out.timestamp   = utils::ByteUtils::ReadU64BE(buf.data()+17);
        return true;
    }

    /// Build SLAVE_FWD (KDC → New SKDC)
    /// Encrypts SlaveKeyBlob with GK using AES-256-GCM
    static utils::ByteBuffer BuildSlaveFwd(
        uint32_t uav_id,
        uint32_t new_cluster,
        const SlaveKeyBlob& blob,
        const GlobalKey& gk)
    {
        auto plain = blob.Serialize();
        AesGcmKey aes_gk;
        std::memcpy(aes_gk.data(), gk.data(), 32);

        // AAD = type(1) + uav_id(4) + new_cluster(4)
        utils::ByteBuffer aad(9);
        aad[0] = TYPE_SLAVE_FWD;
        utils::ByteUtils::WriteU32BE(aad.data()+1, uav_id);
        utils::ByteUtils::WriteU32BE(aad.data()+5, new_cluster);

        auto enc = AesGcm::Encrypt(aes_gk, plain, aad);

        // Wire: [type(1)][uav_id(4)][new_c(4)][iv(12)][tag(16)]
        //       [ct_len(4)][ct][HMAC(32)]
        utils::ByteBuffer buf;
        buf.push_back(TYPE_SLAVE_FWD);
        utils::ByteBuffer ui(4), nc(4), cl(4);
        utils::ByteUtils::WriteU32BE(ui.data(), uav_id);
        utils::ByteUtils::WriteU32BE(nc.data(), new_cluster);
        utils::ByteUtils::WriteU32BE(cl.data(),
            static_cast<uint32_t>(enc.ciphertext.size()));
        buf.insert(buf.end(), ui.begin(), ui.end());
        buf.insert(buf.end(), nc.begin(), nc.end());
        buf.insert(buf.end(),
            enc.iv.begin(), enc.iv.end());
        buf.insert(buf.end(),
            enc.tag.begin(), enc.tag.end());
        buf.insert(buf.end(), cl.begin(), cl.end());
        buf.insert(buf.end(),
            enc.ciphertext.begin(), enc.ciphertext.end());
        HmacKey hk;
        std::memcpy(hk.data(), gk.data(), 32);
        HmacSha256Util::AppendHmac(hk, buf);
        return buf;
    }

    static bool ParseSlaveFwd(
        const utils::ByteBuffer& buf,
        uint32_t& uav_id_out,
        uint32_t& new_cluster_out,
        SlaveKeyBlob& blob_out,
        const GlobalKey& gk)
    {
        if (buf.size() < 1+4+4+12+16+4+32) return false;
        if (buf[0] != TYPE_SLAVE_FWD) return false;
        utils::ByteBuffer data(buf.begin(), buf.end()-32);
        utils::HmacSha256 hmac{};
        std::memcpy(hmac.data(), buf.data() + buf.size() - 32, 32);
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        if (!HmacSha256Util::Verify(hk, data, hmac))
            return false;
        uav_id_out      = utils::ByteUtils::ReadU32BE(buf.data()+1);
        new_cluster_out = utils::ByteUtils::ReadU32BE(buf.data()+5);
        std::array<uint8_t,12> iv{};
        std::memcpy(iv.data(), buf.data()+9, 12);
        std::array<uint8_t,16> tag{};
        std::memcpy(tag.data(), buf.data()+21, 16);
        uint32_t ct_len =
            utils::ByteUtils::ReadU32BE(buf.data()+37);
        if (data.size() < 41 + ct_len) return false;
        utils::ByteBuffer ct(
            buf.begin()+41, buf.begin()+41+ct_len);
        AesGcmKey aes_gk;
        std::memcpy(aes_gk.data(), gk.data(), 32);
        utils::ByteBuffer aad(9);
        aad[0] = TYPE_SLAVE_FWD;
        utils::ByteUtils::WriteU32BE(aad.data()+1, uav_id_out);
        utils::ByteUtils::WriteU32BE(aad.data()+5, new_cluster_out);
        try {
            auto plain = AesGcm::Decrypt(
                aes_gk, iv, ct, tag, aad);
            blob_out = SlaveKeyBlob::Deserialize(plain);
        } catch (...) { return false; }
        return true;
    }

    /// Build JOIN_ACCEPT (New SKDC → UAV)
    /// Re-uses same encrypted blob from SLAVE_FWD
    /// HMAC keyed with GK (UAV has no TEK_new yet)
    static utils::ByteBuffer BuildJoinAccept(
        uint32_t uav_id,
        uint32_t new_cluster,
        uint32_t new_index,
        const SlaveKeyBlob& blob,
        const GlobalKey& gk)
    {
        // Encrypt blob with GK for UAV
        auto plain = blob.Serialize();
        AesGcmKey aes_gk;
        std::memcpy(aes_gk.data(), gk.data(), 32);
        utils::ByteBuffer aad(9);
        aad[0] = TYPE_JOIN_ACC;
        utils::ByteUtils::WriteU32BE(aad.data()+1, uav_id);
        utils::ByteUtils::WriteU32BE(aad.data()+5, new_cluster);
        auto enc = AesGcm::Encrypt(aes_gk, plain, aad);

        utils::ByteBuffer buf;
        buf.push_back(TYPE_JOIN_ACC);
        auto push_u32 = [&](uint32_t v) {
            utils::ByteBuffer b(4);
            utils::ByteUtils::WriteU32BE(b.data(), v);
            buf.insert(buf.end(), b.begin(), b.end());
        };
        push_u32(uav_id);
        push_u32(new_cluster);
        push_u32(new_index);
        buf.insert(buf.end(), enc.iv.begin(), enc.iv.end());
        buf.insert(buf.end(), enc.tag.begin(), enc.tag.end());
        utils::ByteBuffer cl(4);
        utils::ByteUtils::WriteU32BE(cl.data(),
            static_cast<uint32_t>(enc.ciphertext.size()));
        buf.insert(buf.end(), cl.begin(), cl.end());
        buf.insert(buf.end(),
            enc.ciphertext.begin(), enc.ciphertext.end());
        uint64_t ts = NowUs();
        utils::ByteBuffer tsb(8);
        utils::ByteUtils::WriteU64BE(tsb.data(), ts);
        buf.insert(buf.end(), tsb.begin(), tsb.end());
        HmacKey hk;
        std::memcpy(hk.data(), gk.data(), 32);
        HmacSha256Util::AppendHmac(hk, buf);
        return buf;
    }

    static bool ParseJoinAccept(
        const utils::ByteBuffer& buf,
        uint32_t& uav_id_out,
        uint32_t& new_cluster_out,
        uint32_t& new_index_out,
        SlaveKeyBlob& blob_out,
        const GlobalKey& gk)
    {
        if (buf.size() < 1+4+4+4+12+16+4+8+32) return false;
        if (buf[0] != TYPE_JOIN_ACC) return false;
        utils::ByteBuffer data(buf.begin(), buf.end()-32);
        utils::HmacSha256 hmac{};
        std::memcpy(hmac.data(), buf.data() + buf.size() - 32, 32);
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        if (!HmacSha256Util::Verify(hk, data, hmac))
            return false;
        uav_id_out      = utils::ByteUtils::ReadU32BE(buf.data()+1);
        new_cluster_out = utils::ByteUtils::ReadU32BE(buf.data()+5);
        new_index_out   = utils::ByteUtils::ReadU32BE(buf.data()+9);
        std::array<uint8_t,12> iv{};
        std::memcpy(iv.data(), buf.data()+13, 12);
        std::array<uint8_t,16> tag{};
        std::memcpy(tag.data(), buf.data()+25, 16);
        uint32_t ct_len =
            utils::ByteUtils::ReadU32BE(buf.data()+41);
        if (data.size() < 45 + ct_len) return false;
        utils::ByteBuffer ct(
            buf.begin()+45, buf.begin()+45+ct_len);
        AesGcmKey aes_gk;
        std::memcpy(aes_gk.data(), gk.data(), 32);
        utils::ByteBuffer aad(9);
        aad[0] = TYPE_JOIN_ACC;
        utils::ByteUtils::WriteU32BE(aad.data()+1, uav_id_out);
        utils::ByteUtils::WriteU32BE(aad.data()+5, new_cluster_out);
        try {
            auto plain = AesGcm::Decrypt(
               aes_gk, iv, ct, tag, aad);
            blob_out = SlaveKeyBlob::Deserialize(plain);
        } catch (...) { return false; }
        return true;
    }

    /// Build KEY_ACK (UAV → New SKDC)
    static utils::ByteBuffer BuildKeyAck(
        uint32_t uav_id, uint32_t new_cluster,
        uint32_t new_index, const GlobalKey& gk)
    {
        utils::ByteBuffer buf(21, 0x00);
        buf[0] = TYPE_KEY_ACK;
        utils::ByteUtils::WriteU32BE(buf.data()+1,  uav_id);
        utils::ByteUtils::WriteU32BE(buf.data()+5,  new_cluster);
        utils::ByteUtils::WriteU32BE(buf.data()+9,  new_index);
        uint64_t ts = NowUs();
        utils::ByteUtils::WriteU64BE(buf.data()+13, ts);
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        HmacSha256Util::AppendHmac(hk, buf);
        return buf;
    }

    static bool ParseKeyAck(
        const utils::ByteBuffer& buf,
        SlaveAckPkt& out,
        const GlobalKey& gk)
    {
        if (buf.size() < 21+32) return false;
        if (buf[0] != TYPE_KEY_ACK) return false;
        utils::ByteBuffer data(buf.begin(), buf.end()-32);
        utils::HmacSha256 hmac{};
        std::memcpy(hmac.data(), buf.data() + buf.size() - 32, 32);
        HmacKey hk; std::memcpy(hk.data(), gk.data(), 32);
        if (!HmacSha256Util::Verify(hk, data, hmac))
            return false;
        out.uav_id      = utils::ByteUtils::ReadU32BE(buf.data()+1);
        out.new_cluster = utils::ByteUtils::ReadU32BE(buf.data()+5);
        out.new_index   = utils::ByteUtils::ReadU32BE(buf.data()+9);
        out.timestamp   = utils::ByteUtils::ReadU64BE(buf.data()+13);
        return true;
    }

    /// Convert hex string (from JSON) to GlobalKey
    static GlobalKey HexToGlobalKey(const std::string& hex) {
        if (hex.size() != 64)
            UAV_THROW(utils::CryptoException,
                "HexToGlobalKey: expected 64 hex chars");
        GlobalKey k{};
        for (size_t i = 0; i < 32; ++i) {
            k[i] = static_cast<uint8_t>(
                std::stoul(hex.substr(i*2, 2), nullptr, 16));
        }
        return k;
    }

private:
    static uint64_t NowUs() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now()
                    .time_since_epoch()).count());
    }
};

} // namespace crypto
} // namespace uav

#endif // UAV_HANDOVER_PROTOCOL_H
