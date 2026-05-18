/**
 * tests/test_utils.cc
 * Unit test for Phase 1 Module 3: Common Utility Classes
 *
 * COMPILE (standalone — no NS-3):
 *   g++-13 -std=c++17 -Wall -Wextra \
 *       -I. \
 *       tests/test_utils.cc \
 *       utils/uav-error.cc \
 *       utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc \
 *       utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc \
 *       utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc \
 *       -o test_utils
 *
 * RUN:
 *   ./test_utils
 */

#include "utils/uav-types.h"
#include "utils/uav-constants.h"
#include "utils/uav-error.h"
#include "utils/uav-time-utils.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-byte-utils.h"
#include "utils/uav-math-utils.h"
#include "utils/uav-file-utils.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <filesystem>

using namespace uav::utils;

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

void RunTest(const std::string& name, bool (*fn)()) {
    std::cout << "[ RUN  ] " << name << "\n";
    bool ok = false;
    try {
        ok = fn();
    } catch (const std::exception& ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        ok = false;
    }
    if (ok) {
        std::cout << "[ PASS ] " << name << "\n\n";
        ++g_pass;
    } else {
        std::cout << "[ FAIL ] " << name << "\n\n";
        ++g_fail;
    }
}

// ===========================================================================
// Test 1: Strong IDs — type safety, hashing, ordering
// ===========================================================================
bool test_strong_ids() {
    UavId u1(5);
    UavId u2(5);
    UavId u3(10);
    ClusterId c1(5);

    ASSERT_TRUE(u1 == u2);
    ASSERT_TRUE(u1 != u3);
    ASSERT_TRUE(u1 < u3);

    // Hashing — verify ID types work in unordered_map.
    std::unordered_map<UavId, std::string> m;
    m[u1] = "uav-1";
    m[u3] = "uav-3";
    ASSERT_EQ(m[UavId(5)], std::string("uav-1"));
    ASSERT_EQ(m.size(), 2u);

    // Note: u1.value == c1.value but the types are distinct — this is
    // exactly what we want. A compile-time check that the types do NOT
    // compare is verified by static_assert in the type header (cannot be
    // tested at runtime, but their differing operator<< proves separation).
    std::ostringstream oss;
    oss << u1 << " " << c1;
    ASSERT_TRUE(oss.str().find("UavId") != std::string::npos);
    ASSERT_TRUE(oss.str().find("ClusterId") != std::string::npos);
    return true;
}

// ===========================================================================
// Test 2: Enum-to-string
// ===========================================================================
bool test_enum_strings() {
    ASSERT_EQ(std::string(NodeRoleToString(NodeRole::KDC)),    std::string("KDC"));
    ASSERT_EQ(std::string(NodeRoleToString(NodeRole::JAMMER)), std::string("JAMMER"));
    ASSERT_EQ(std::string(UavStateToString(UavState::ACTIVE)), std::string("ACTIVE"));
    ASSERT_EQ(std::string(SecurityEventTypeToString(SecurityEventType::REKEY)),
              std::string("REKEY"));
    ASSERT_EQ(std::string(StatusToString(Status::REPLAY_DETECTED)),
              std::string("REPLAY_DETECTED"));
    return true;
}

// ===========================================================================
// Test 3: Constants sanity check
// ===========================================================================
bool test_constants() {
    using namespace constants;
    ASSERT_EQ(NUM_UAVS, 18u);
    ASSERT_EQ(NUM_CLUSTERS * UAVS_PER_CLUSTER, NUM_UAVS);
    ASSERT_TRUE(AREA_X_MAX > AREA_X_MIN);
    ASSERT_TRUE(UAV_SPEED_MAX > UAV_SPEED_MIN);
    ASSERT_EQ(AES_KEY_BYTES, 32u);
    ASSERT_EQ(HMAC_SHA256_BYTES, 32u);
    return true;
}

// ===========================================================================
// Test 4: Exceptions
// ===========================================================================
bool test_exceptions() {
    try {
        UAV_THROW(InvalidArgumentException, "bad input");
        return false;  // should not reach
    } catch (const UavException& ex) {
        ASSERT_EQ(ex.code(), Status::INVALID_ARGUMENT);
        ASSERT_TRUE(std::string(ex.what()).find("bad input") != std::string::npos);
        ASSERT_TRUE(ex.formatted().find("INVALID_ARGUMENT") != std::string::npos);
    }

    bool threw = false;
    try {
        UAV_CHECK(2 + 2 == 5, CryptoException, "math broken");
    } catch (const CryptoException&) {
        threw = true;
    }
    ASSERT_TRUE(threw);
    return true;
}

// ===========================================================================
// Test 5: Time utilities
// ===========================================================================
bool test_time_utils() {
    u64 t1 = TimeUtils::NowEpochMicros();
    TimeUtils::SleepMicros(1500);  // ~1.5 ms
    u64 t2 = TimeUtils::NowEpochMicros();
    ASSERT_TRUE(t2 > t1);
    ASSERT_TRUE((t2 - t1) >= 500);   // allow scheduling slack

    std::string iso = TimeUtils::NowIso8601();
    ASSERT_TRUE(iso.size() >= 20);
    ASSERT_TRUE(iso.find('T') != std::string::npos);
    ASSERT_TRUE(iso.back() == 'Z');

    std::string fname = TimeUtils::NowFileSafe();
    ASSERT_TRUE(fname.find(':') == std::string::npos);
    ASSERT_TRUE(fname.find('-') == std::string::npos);

    ASSERT_TRUE(TimeUtils::WithinSkew(1000, 1500, 1000));
    ASSERT_TRUE(!TimeUtils::WithinSkew(1000, 5000, 1000));

    // ScopedTimer
    {
        ScopedTimer st("test_block");
        TimeUtils::SleepMicros(500);
        u64 elapsed = st.Stop();
        ASSERT_TRUE(elapsed >= 200);
    }
    return true;
}

// ===========================================================================
// Test 6: String utilities
// ===========================================================================
bool test_string_utils() {
    ASSERT_EQ(StringUtils::Trim("  hello  "), std::string("hello"));
    ASSERT_EQ(StringUtils::ToUpper("AbC"), std::string("ABC"));
    ASSERT_EQ(StringUtils::ToLower("AbC"), std::string("abc"));

    auto parts = StringUtils::Split("a,b,c", ',');
    ASSERT_EQ(parts.size(), 3u);
    ASSERT_EQ(parts[1], std::string("b"));

    ASSERT_EQ(StringUtils::Join({"x", "y", "z"}, "-"), std::string("x-y-z"));

    ASSERT_TRUE(StringUtils::StartsWith("uav-001", "uav-"));
    ASSERT_TRUE(StringUtils::EndsWith("file.log", ".log"));

    ASSERT_EQ(StringUtils::Replace("foo_bar_foo", "foo", "baz"),
              std::string("baz_bar_baz"));

    std::string f = StringUtils::Format("UAV %d at %.2f m/s", 7, 12.5);
    ASSERT_TRUE(f.find("UAV 7") != std::string::npos);
    ASSERT_TRUE(f.find("12.50") != std::string::npos);

    ByteBuffer buf = { 0xDE, 0xAD, 0xBE, 0xEF };
    ASSERT_EQ(StringUtils::BytesToHex(buf), std::string("deadbeef"));

    ByteBuffer back = StringUtils::HexToBytes("DEADBEEF");
    ASSERT_EQ(back, buf);

    // Long buffer abbreviation
    ByteBuffer big(64, 0xAB);
    std::string abbr = StringUtils::BytesToHexAbbrev(big, 4, 2);
    ASSERT_TRUE(abbr.find("...") != std::string::npos);
    ASSERT_TRUE(abbr.find("(64B)") != std::string::npos);
    return true;
}

// ===========================================================================
// Test 7: Byte utilities — endian, append, constant-time, secure zero
// ===========================================================================
bool test_byte_utils() {
    // Big-endian round-trip
    u8 buf[8];
    ByteUtils::WriteU64BE(buf, 0x0123456789ABCDEFULL);
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[7], 0xEF);
    u64 back = ByteUtils::ReadU64BE(buf);
    ASSERT_EQ(back, 0x0123456789ABCDEFULL);

    ByteUtils::WriteU32BE(buf, 0xCAFEBABE);
    ASSERT_EQ(ByteUtils::ReadU32BE(buf), 0xCAFEBABEu);

    ByteUtils::WriteU16BE(buf, 0xBEEF);
    ASSERT_EQ(ByteUtils::ReadU16BE(buf), 0xBEEFu);

    // Append
    ByteBuffer b;
    ByteUtils::AppendU32BE(b, 0x11223344);
    ByteUtils::AppendU16BE(b, 0x5566);
    ByteUtils::AppendU8(b, 0x77);
    ASSERT_EQ(b.size(), 7u);
    ASSERT_EQ(b[0], 0x11); ASSERT_EQ(b[3], 0x44);
    ASSERT_EQ(b[4], 0x55); ASSERT_EQ(b[5], 0x66); ASSERT_EQ(b[6], 0x77);

    // Constant-time compare
    ByteBuffer a1 = { 1,2,3,4,5 };
    ByteBuffer a2 = { 1,2,3,4,5 };
    ByteBuffer a3 = { 1,2,3,4,6 };
    ASSERT_TRUE(ByteUtils::ConstantTimeEquals(a1, a2));
    ASSERT_TRUE(!ByteUtils::ConstantTimeEquals(a1, a3));
    ASSERT_TRUE(!ByteUtils::ConstantTimeEquals(a1, ByteBuffer{1,2,3}));

    // Concat
    ByteBuffer c = ByteUtils::Concat(a1, ByteBuffer{0xAA, 0xBB});
    ASSERT_EQ(c.size(), 7u);
    ASSERT_EQ(c[5], 0xAA);

    // Secure zero
    ByteBuffer secret = { 0xDE, 0xAD, 0xBE, 0xEF };
    ByteUtils::SecureZero(secret);
    for (u8 v : secret) ASSERT_EQ(v, 0u);
    return true;
}

// ===========================================================================
// Test 8: Math utilities
// ===========================================================================
bool test_math_utils() {
    Vec3 a(0,0,0), b(3,4,0);
    ASSERT_TRUE(MathUtils::NearlyEqual(MathUtils::Distance3D(a, b), 5.0));

    ASSERT_EQ(MathUtils::Clamp(15, 0, 10), 10);
    ASSERT_EQ(MathUtils::Clamp(-3, 0, 10), 0);
    ASSERT_EQ(MathUtils::Clamp(5,  0, 10), 5);

    ASSERT_TRUE(MathUtils::NearlyEqual(MathUtils::DbToLinear(20.0), 100.0, 1e-6));
    ASSERT_TRUE(MathUtils::NearlyEqual(MathUtils::LinearToDb(1000.0), 30.0, 1e-6));

    // Random — verify seeded determinism
    auto& rng = SecureRandom::Instance();
    rng.Seed(42);
    u32 r1 = rng.NextU32();
    rng.Seed(42);
    u32 r2 = rng.NextU32();
    ASSERT_EQ(r1, r2);

    rng.Seed(12345);
    double d = rng.NextDouble();
    ASSERT_TRUE(d >= 0.0 && d < 1.0);

    u32 rng_val = rng.NextU32InRange(10, 20);
    ASSERT_TRUE(rng_val >= 10 && rng_val <= 20);

    ByteBuffer rb = rng.RandomBytes(64);
    ASSERT_EQ(rb.size(), 64u);
    // Probabilistically non-zero
    bool any_nonzero = false;
    for (u8 v : rb) if (v) { any_nonzero = true; break; }
    ASSERT_TRUE(any_nonzero);
    return true;
}

// ===========================================================================
// Test 9: File utilities
// ===========================================================================
bool test_file_utils() {
    std::string base = "/tmp/uav_utils_test";
    std::string dir  = FileUtils::JoinPath(base, "sub/dir");
    std::string txt  = FileUtils::JoinPath(dir, "hello.txt");
    std::string bin  = FileUtils::JoinPath(dir, "data.bin");

    // mkdir
    FileUtils::MkdirRecursive(dir);
    ASSERT_TRUE(FileUtils::Exists(dir));
    ASSERT_TRUE(FileUtils::IsDirectory(dir));

    // text I/O
    FileUtils::WriteTextFile(txt, "uav-secure-fanet\nphase1\n", false);
    ASSERT_TRUE(FileUtils::IsRegularFile(txt));
    std::string back = FileUtils::ReadTextFile(txt);
    ASSERT_TRUE(back.find("uav-secure-fanet") != std::string::npos);

    // append
    FileUtils::WriteTextFile(txt, "extra\n", true);
    back = FileUtils::ReadTextFile(txt);
    ASSERT_TRUE(back.find("extra") != std::string::npos);

    // binary I/O
    ByteBuffer payload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0xAA };
    FileUtils::WriteBinaryFile(bin, payload);
    ASSERT_EQ(FileUtils::FileSizeBytes(bin), payload.size());
    ByteBuffer rb = FileUtils::ReadBinaryFile(bin);
    ASSERT_EQ(rb, payload);

    // List
    auto files = FileUtils::ListFiles(dir);
    ASSERT_TRUE(files.size() >= 2);

    // Path manipulation
    ASSERT_EQ(FileUtils::BaseName(txt),  std::string("hello.txt"));
    ASSERT_EQ(FileUtils::Extension(txt), std::string(".txt"));
    ASSERT_EQ(FileUtils::ParentDir(txt), dir);

    // Cleanup
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 1 Module 3 — Common Utility Classes\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    RunTest("strong_ids",     test_strong_ids);
    RunTest("enum_strings",   test_enum_strings);
    RunTest("constants",      test_constants);
    RunTest("exceptions",     test_exceptions);
    RunTest("time_utils",     test_time_utils);
    RunTest("string_utils",   test_string_utils);
    RunTest("byte_utils",     test_byte_utils);
    RunTest("math_utils",     test_math_utils);
    RunTest("file_utils",     test_file_utils);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, " << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}