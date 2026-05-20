/**
 * tests/test_data_packet.cc
 * Unit test for Phase 3 Module 22: DATA Packet
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I./utils -I./crypto -I./headers -I/usr/include \
 *       tests/test_data_packet.cc \
 *       utils/uav-error.cc utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       crypto/uav-openssl-rand.cc crypto/uav-openssl-ctx.cc \
 *       crypto/uav-aes.cc crypto/uav-hmac.cc \
 *       crypto/uav-replay.cc \
 *       headers/uav-packet-enums.cc \
 *       headers/uav-base-header.cc \
 *       headers/uav-data-packet.cc \
 *       -lssl -lcrypto \
 *       -o tests/test_data_packet
 */

#include "headers/uav-data-packet.h"
#include "crypto/uav-openssl-ctx.h"
#include "utils/uav-logger.h"
#include "utils/uav-string-utils.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace uav;
using namespace uav::packet;
using namespace uav::crypto;

namespace {

int g_pass = 0;
int g_fail = 0;

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { \
        std::cerr << "  ASSERT_TRUE failed: " #expr \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_EQ(a, b) \
    do { if (!((a) == (b))) { \
        std::cerr << "  ASSERT_EQ failed: " #a " != " #b \
                  << " @ line " << __LINE__ << "\n"; \
        return false; } } while (0)

#define ASSERT_THROWS(expr) \
    do { bool threw = false; \
        try { expr; } catch (...) { threw = true; } \
        if (!threw) { \
            std::cerr << "  ASSERT_THROWS failed: " #expr \
                      << " @ line " << __LINE__ << "\n"; \
            return false; } } while (0)

void RunTest(const std::string& name, bool (*fn)()) {
    std::cout << "[ RUN  ] " << name << "\n";
    bool ok = false;
    try { ok = fn(); }
    catch (const std::exception& ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        ok = false;
    }
    if (ok) { std::cout << "[ PASS ] " << name << "\n\n"; ++g_pass; }
    else    { std::cout << "[ FAIL ] " << name << "\n\n"; ++g_fail; }
}

// ===========================================================================
// Test 1: DataBody serialize/deserialize round-trip
// ===========================================================================
bool test_data_body_roundtrip() {
    DataBody body;
    body.cluster_id    = 1;
    body.data_sequence = 42;
    body.timestamp_us  = 1234567890ULL;
    body.plaintext_len = 16;

    for (std::size_t i = 0; i < 12; ++i)
        body.aes_iv[i]  = static_cast<utils::u8>(i + 0x10);
    for (std::size_t i = 0; i < 16; ++i)
        body.aes_tag[i] = static_cast<utils::u8>(i + 0x20);

    body.ciphertext = {0xAA, 0xBB, 0xCC, 0xDD,
                       0xEE, 0xFF, 0x11, 0x22,
                       0x33, 0x44, 0x55, 0x66,
                       0x77, 0x88, 0x99, 0x00};

    auto wire  = body.Serialize();
    ASSERT_EQ(wire.size(),
              DataBody::FIXED_SIZE + body.ciphertext.size());

    auto body2 = DataBody::Deserialize(wire);
    ASSERT_EQ(body2.cluster_id,    body.cluster_id);
    ASSERT_EQ(body2.data_sequence, body.data_sequence);
    ASSERT_EQ(body2.timestamp_us,  body.timestamp_us);
    ASSERT_EQ(body2.plaintext_len, body.plaintext_len);
    ASSERT_EQ(body2.aes_iv,        body.aes_iv);
    ASSERT_EQ(body2.aes_tag,       body.aes_tag);
    ASSERT_EQ(body2.ciphertext,    body.ciphertext);

    std::cout << "  DataBody wire size: " << wire.size()
              << " bytes\n";
    std::cout << "  DataBody round-trip: PASS\n";
    return true;
}

// ===========================================================================
// Test 2: Build and decrypt small payload
// ===========================================================================
bool test_build_decrypt_small() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    std::string msg = "UAV telemetry data";
    utils::ByteBuffer plaintext(msg.begin(), msg.end());

    auto pkt = DataPacket::Build(
        0, 5, 100, 1, plaintext, tek, hmac_key, seq);

    ASSERT_TRUE(pkt.IsValid());
    ASSERT_EQ(pkt.GetHeader().packet_type,
              PacketType::DATA_PACKET);
    ASSERT_EQ(pkt.GetBody().plaintext_len,
              static_cast<utils::u32>(plaintext.size()));
    ASSERT_TRUE(pkt.GetHeader().IsEncrypted());

    // Decrypt
    auto recovered = pkt.Decrypt(tek);
    ASSERT_EQ(recovered, plaintext);

    std::cout << "  Plaintext: " << msg << "\n";
    std::cout << "  CT size: "
              << pkt.GetBody().ciphertext.size() << " bytes\n";
    std::cout << "  Build+decrypt: PASS\n";
    return true;
}

// ===========================================================================
// Test 3: Full 1024-byte payload (project spec DATA_PACKET_SIZE)
// ===========================================================================
bool test_full_1024_payload() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    // Max payload = 1024 - 136 overhead = 888 bytes
    // Overhead: header(32)+nonce(16)+body_fixed(56)+hmac(32) = 136
    utils::ByteBuffer plaintext(888);
    OpenSSLRand::FillBytes(plaintext.data(), 888);

    auto pkt  = DataPacket::Build(
        1, 7, 101, 1, plaintext, tek, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  Payload size: " << plaintext.size()
              << " bytes\n";
    std::cout << "  Wire size: " << wire.size() << " bytes\n";
    ASSERT_TRUE(wire.size() <= 1024u);
    std::cout << "  Fits in 1024 bytes: PASS\n";

    auto pkt2 = DataPacket::Deserialize(wire, hmac_key);
    auto rec  = pkt2.Decrypt(tek);
    ASSERT_EQ(rec, plaintext);

    std::cout << "  888-byte payload encrypt/decrypt: PASS\n";
    return true;
}

// ===========================================================================
// Test 4: Serialize/Deserialize round-trip
// ===========================================================================
bool test_serialize_roundtrip() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01,0x02,0x03,0x04,0x05};

    auto pkt  = DataPacket::Build(
        0, 3, 100, 5, pt, tek, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    std::cout << "  Wire size: " << wire.size() << " bytes\n";

    auto pkt2 = DataPacket::Deserialize(wire, hmac_key);
    ASSERT_EQ(pkt2.GetBody().cluster_id,
              pkt.GetBody().cluster_id);
    ASSERT_EQ(pkt2.GetBody().data_sequence,
              pkt.GetBody().data_sequence);
    ASSERT_EQ(pkt2.GetBody().plaintext_len,
              pkt.GetBody().plaintext_len);
    ASSERT_EQ(pkt2.GetBody().aes_iv,
              pkt.GetBody().aes_iv);
    ASSERT_EQ(pkt2.GetBody().aes_tag,
              pkt.GetBody().aes_tag);
    ASSERT_EQ(pkt2.GetBody().ciphertext,
              pkt.GetBody().ciphertext);

    // Decrypt
    auto rec = pkt2.Decrypt(tek);
    ASSERT_EQ(rec, pt);

    std::cout << "  Serialize/Deserialize/Decrypt: PASS\n";
    return true;
}

// ===========================================================================
// Test 5: Wrong TEK fails decryption
// ===========================================================================
bool test_wrong_tek() {
    auto tek      = AesGcm::GenerateKey();
    auto wrong_tek = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0xDE, 0xAD, 0xBE, 0xEF};

    auto pkt = DataPacket::Build(
        0, 5, 100, 1, pt, tek, hmac_key, seq);

    // Wrong TEK throws CryptoException
    ASSERT_THROWS(pkt.Decrypt(wrong_tek));

    std::cout << "  Wrong TEK rejected: PASS\n";
    return true;
}

// ===========================================================================
// Test 6: HMAC tamper detection
// ===========================================================================
bool test_hmac_tamper() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01, 0x02, 0x03};

    auto pkt  = DataPacket::Build(
        0, 5, 100, 1, pt, tek, hmac_key, seq);
    auto wire = pkt.Serialize();
    HmacSha256Util::AppendHmac(hmac_key, wire);

    // Tamper with ciphertext
    auto tampered = wire;
    tampered[90] ^= 0xFF;
    ASSERT_THROWS(DataPacket::Deserialize(tampered, hmac_key));

    // Wrong HMAC key
    auto wrong_key = HmacSha256Util::GenerateKey();
    ASSERT_THROWS(DataPacket::Deserialize(wire, wrong_key));

    std::cout << "  Tamper detection: PASS\n";
    return true;
}

// ===========================================================================
// Test 7: Replay fields unique per packet
// ===========================================================================
bool test_replay_fields_unique() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01, 0x02};

    auto p1 = DataPacket::Build(0,5,100,1,pt,tek,hmac_key,seq);
    auto p2 = DataPacket::Build(0,5,100,2,pt,tek,hmac_key,seq);

    ASSERT_TRUE(
        p1.GetHeader().sequence_num !=
        p2.GetHeader().sequence_num);
    ASSERT_TRUE(
        p1.GetHeader().nonce != p2.GetHeader().nonce);
    ASSERT_TRUE(
        p1.GetBody().aes_iv != p2.GetBody().aes_iv);

    std::cout << "  Unique replay tokens: PASS\n";
    std::cout << "  Unique AES IVs: PASS\n";
    return true;
}

// ===========================================================================
// Test 8: 18 UAVs each send data packet
// ===========================================================================
bool test_18_uavs_data() {
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    for (utils::u16 uav = 0; uav < 18; ++uav) {
        utils::u16 cluster = uav / 6;
        utils::u16 skdc    = cluster + 100;

        auto tek = AesGcm::GenerateKey();

        std::string msg = "UAV " + std::to_string(uav)
                        + " telemetry";
        utils::ByteBuffer pt(msg.begin(), msg.end());

        auto pkt  = DataPacket::Build(
            cluster, uav, skdc, uav,
            pt, tek, hmac_key, seq);
        auto wire = pkt.Serialize();
        HmacSha256Util::AppendHmac(hmac_key, wire);

        auto pkt2 = DataPacket::Deserialize(wire, hmac_key);
        auto rec  = pkt2.Decrypt(tek);
        ASSERT_EQ(rec, pt);
    }

    std::cout << "  18 UAVs data packets: PASS\n";
    return true;
}

// ===========================================================================
// Test 9: Ciphertext differs for same plaintext (random IV)
// ===========================================================================
bool test_random_iv_uniqueness() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01, 0x02, 0x03, 0x04};

    auto p1 = DataPacket::Build(0,5,100,1,pt,tek,hmac_key,seq);
    auto p2 = DataPacket::Build(0,5,100,2,pt,tek,hmac_key,seq);

    // Same plaintext, different IV → different ciphertext
    ASSERT_TRUE(
        p1.GetBody().ciphertext != p2.GetBody().ciphertext);

    // Both decrypt to same plaintext
    auto r1 = p1.Decrypt(tek);
    auto r2 = p2.Decrypt(tek);
    ASSERT_EQ(r1, pt);
    ASSERT_EQ(r2, pt);

    std::cout << "  Random IV uniqueness: PASS\n";
    return true;
}

// ===========================================================================
// Test 10: Data sequence counter increments
// ===========================================================================
bool test_data_sequence() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01};

    for (utils::u32 s = 1; s <= 5; ++s) {
        auto pkt = DataPacket::Build(
            0, 5, 100, s, pt, tek, hmac_key, seq);
        ASSERT_EQ(pkt.GetBody().data_sequence, s);
    }

    std::cout << "  Data sequences 1-5: PASS\n";
    return true;
}

// ===========================================================================
// Test 11: Describe output
// ===========================================================================
bool test_describe() {
    auto tek      = AesGcm::GenerateKey();
    auto hmac_key = HmacSha256Util::GenerateKey();
    SequenceCounter seq;

    utils::ByteBuffer pt = {0x01, 0x02, 0x03};
    auto pkt = DataPacket::Build(
        2, 14, 102, 7, pt, tek, hmac_key, seq);

    auto desc = pkt.Describe();
    ASSERT_TRUE(!desc.empty());
    ASSERT_TRUE(desc.find("DataPacket") != std::string::npos);
    ASSERT_TRUE(desc.find("uav=14")     != std::string::npos);
    ASSERT_TRUE(desc.find("seq=7")      != std::string::npos);

    std::cout << "  " << desc << "\n";
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 3 Module 22 — DATA Packet\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    log::Logger::Instance().Initialize(
        "/tmp/uav_data_packet_logs",
        log::LogLevel::WARN,
        false);

    OpenSSLInit::Bootstrap();

    RunTest("data_body_roundtrip",   test_data_body_roundtrip);
    RunTest("build_decrypt_small",   test_build_decrypt_small);
    RunTest("full_1024_payload",     test_full_1024_payload);
    RunTest("serialize_roundtrip",   test_serialize_roundtrip);
    RunTest("wrong_tek",             test_wrong_tek);
    RunTest("hmac_tamper",           test_hmac_tamper);
    RunTest("replay_fields_unique",  test_replay_fields_unique);
    RunTest("18_uavs_data",          test_18_uavs_data);
    RunTest("random_iv_uniqueness",  test_random_iv_uniqueness);
    RunTest("data_sequence",         test_data_sequence);
    RunTest("describe",              test_describe);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
