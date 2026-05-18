/**
 * tests/test_json_loader.cc
 * Unit test for Phase 1 Module 5: JSON Loader Framework
 *
 * COMPILE:
 *   g++-13 -std=c++20 -Wall -Wextra -pthread \
 *       -I. -I/usr/include \
 *       tests/test_json_loader.cc \
 *       utils/uav-error.cc \
 *       utils/uav-enum-strings.cc \
 *       utils/uav-time-utils.cc \
 *       utils/uav-string-utils.cc \
 *       utils/uav-byte-utils.cc \
 *       utils/uav-math-utils.cc \
 *       utils/uav-file-utils.cc \
 *       utils/uav-log-level.cc \
 *       utils/uav-log-sink.cc \
 *       utils/uav-logger.cc \
 *       utils/uav-csv-logger.cc \
 *       utils/uav-json-loader.cc \
 *       utils/uav-json-validator.cc \
 *       -o tests/test_json_loader
 *
 * RUN:
 *   ./tests/test_json_loader
 */

#include "utils/uav-json-loader.h"
#include "utils/uav-json-validator.h"
#include "utils/uav-logger.h"
#include "utils/uav-file-utils.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace uav;

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

// ---------------------------------------------------------------------------
// Test JSON strings
// ---------------------------------------------------------------------------
const std::string kSimpleJson = R"({
    "name": "uav-fanet",
    "version": 1,
    "enabled": true,
    "ratio": 3.14,
    "nested": {
        "depth": 2,
        "label": "inner"
    },
    "items": [10, 20, 30],
    "tags": ["alpha", "beta", "gamma"],
    "big_int": "123456789012345678901234567890"
})";

const std::string kCryptoJson = R"({
    "crypto": {
        "scheme": "CRT-GCRT",
        "aes_bits": 256,
        "kdc": {
            "num_safe_primes": 18,
            "master_key": "99999999999999999999999999999999"
        },
        "clusters": [
            {"cluster_id": 0, "tek": "deadbeef"},
            {"cluster_id": 1, "tek": "cafebabe"}
        ]
    }
})";

// ===========================================================================
// Test 1: FromString — basic load
// ===========================================================================
bool test_from_string() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);
    ASSERT_TRUE(loader.Has("name"));
    ASSERT_TRUE(loader.Has("nested.depth"));
    ASSERT_TRUE(!loader.Has("nonexistent"));
    ASSERT_TRUE(!loader.Has("nested.nonexistent"));
    return true;
}

// ===========================================================================
// Test 2: Typed getters — mandatory
// ===========================================================================
bool test_typed_getters() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);

    ASSERT_EQ(loader.GetString("name"),   std::string("uav-fanet"));
    ASSERT_EQ(loader.GetBool("enabled"),  true);
    ASSERT_EQ(loader.GetU32("version"),   1u);
    ASSERT_TRUE(std::abs(loader.GetDouble("ratio") - 3.14) < 1e-6);
    ASSERT_EQ(loader.GetString("nested.label"), std::string("inner"));
    ASSERT_EQ(loader.GetU32("nested.depth"), 2u);
    ASSERT_EQ(loader.GetBigInt("big_int"),
              std::string("123456789012345678901234567890"));
    return true;
}

// ===========================================================================
// Test 3: Optional getters — defaults
// ===========================================================================
bool test_optional_getters() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);

    ASSERT_EQ(loader.GetString("missing", "default"), std::string("default"));
    ASSERT_EQ(loader.GetBool("missing", false), false);
    ASSERT_EQ(loader.GetU32("missing", 42u), 42u);
    ASSERT_EQ(loader.GetDouble("missing", 9.9), 9.9);
    ASSERT_EQ(loader.GetBigInt("missing", "0"), std::string("0"));

    // Present key still returns value, not default
    ASSERT_EQ(loader.GetString("name", "wrong"), std::string("uav-fanet"));
    ASSERT_EQ(loader.GetU32("version", 99u), 1u);
    return true;
}

// ===========================================================================
// Test 4: Array access
// ===========================================================================
bool test_arrays() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);

    auto items = loader.GetU32Array("items");
    ASSERT_EQ(items.size(), 3u);
    ASSERT_EQ(items[0], 10u);
    ASSERT_EQ(items[2], 30u);

    auto tags = loader.GetStringArray("tags");
    ASSERT_EQ(tags.size(), 3u);
    ASSERT_EQ(tags[1], std::string("beta"));

    ASSERT_EQ(loader.ArraySize("items"), 3u);
    ASSERT_EQ(loader.ArraySize("nonexistent"), 0u);

    auto el = loader.ArrayElement("items", 1);
    ASSERT_EQ(el.GetU32(""), 20u);
    return true;
}

// ===========================================================================
// Test 5: Sub-loader
// ===========================================================================
bool test_sub_loader() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);
    auto sub    = loader.Sub("nested");

    ASSERT_EQ(sub.GetU32("depth"),       2u);
    ASSERT_EQ(sub.GetString("label"),    std::string("inner"));
    ASSERT_TRUE(!sub.Has("name"));  // parent key not visible

    // Nested crypto
    auto crypto = json::JsonLoader::FromString(kCryptoJson);
    auto kdc    = crypto.Sub("crypto.kdc");
    ASSERT_EQ(kdc.GetU32("num_safe_primes"), 18u);
    ASSERT_EQ(kdc.GetBigInt("master_key"),
              std::string("99999999999999999999999999999999"));
    return true;
}

// ===========================================================================
// Test 6: Error handling — missing keys and type mismatches
// ===========================================================================
bool test_error_handling() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);

    // Missing mandatory key
    ASSERT_THROWS(loader.GetString("no.such.key"));
    ASSERT_THROWS(loader.GetU32("no.such.key"));

    // Wrong type
    ASSERT_THROWS(loader.GetBool("name"));     // name is string, not bool
    ASSERT_THROWS(loader.GetU32("enabled"));   // bool, not int
    ASSERT_THROWS(loader.GetString("version")); // int, not string

    // Array index out of bounds
    ASSERT_THROWS(loader.ArrayElement("items", 99));

    // Sub on non-object
    ASSERT_THROWS(loader.Sub("name"));  // name is string

    // Invalid JSON
    ASSERT_THROWS(json::JsonLoader::FromString("{invalid json}"));

    return true;
}

// ===========================================================================
// Test 7: Merge / overlay
// ===========================================================================
bool test_merge() {
    auto base    = json::JsonLoader::FromString(R"({
        "a": 1, "b": "old", "nested": {"x": 10, "y": 20}
    })");
    auto overlay = json::JsonLoader::FromString(R"({
        "b": "new", "c": 99, "nested": {"y": 999, "z": 0}
    })");

    base.MergeFrom(overlay);

    ASSERT_EQ(base.GetU32("a"),            1u);      // unchanged
    ASSERT_EQ(base.GetString("b"),         std::string("new")); // overridden
    ASSERT_EQ(base.GetU32("c"),            99u);     // added
    ASSERT_EQ(base.GetU32("nested.x"),     10u);     // unchanged
    ASSERT_EQ(base.GetU32("nested.y"),     999u);    // overridden
    ASSERT_EQ(base.GetU32("nested.z"),     0u);      // added
    return true;
}

// ===========================================================================
// Test 8: File round-trip — write and reload
// ===========================================================================
bool test_file_roundtrip() {
    std::string path = "/tmp/uav_json_test_roundtrip.json";
    std::error_code ec;

    auto original = json::JsonLoader::FromString(kCryptoJson);
    original.ToFile(path);

    ASSERT_TRUE(utils::FileUtils::Exists(path));
    ASSERT_TRUE(utils::FileUtils::FileSizeBytes(path) > 0);

    auto reloaded = json::JsonLoader::FromFile(path);
    ASSERT_EQ(reloaded.GetString("crypto.scheme"),
              std::string("CRT-GCRT"));
    ASSERT_EQ(reloaded.GetU32("crypto.aes_bits"), 256u);
    ASSERT_EQ(reloaded.GetBigInt("crypto.kdc.master_key"),
              std::string("99999999999999999999999999999999"));

    auto tags0 = reloaded.ArrayElement("crypto.clusters", 0);
    ASSERT_EQ(tags0.GetU32("cluster_id"), 0u);
    ASSERT_EQ(tags0.GetString("tek"),     std::string("deadbeef"));

    fs::remove(path, ec);
    return true;
}

// ===========================================================================
// Test 9: Load simulation_config.json from json/ folder
// ===========================================================================
bool test_load_sim_config() {
    std::string path = "json/simulation_config.json";
    if (!utils::FileUtils::Exists(path)) {
        std::cout << "  SKIP: " << path << " not found (place it first)\n";
        return true;
    }

    auto cfg = json::JsonLoader::FromFile(path);
    ASSERT_EQ(cfg.GetU32("topology.num_uavs"),    18u);
    ASSERT_EQ(cfg.GetU32("topology.num_clusters"), 3u);
    ASSERT_TRUE(cfg.GetDouble("simulation.duration_s") > 0.0);
    ASSERT_EQ(cfg.GetString("output.log_dir"),    std::string("logs"));
    return true;
}

// ===========================================================================
// Test 10: JsonValidator — required + optional + wrong type
// ===========================================================================
bool test_validator() {
    auto loader = json::JsonLoader::FromString(kSimpleJson);

    json::JsonValidator v;
    v.RequireString("name");
    v.RequireBool("enabled");
    v.RequireU32("version");
    v.RequireDouble("ratio");
    v.RequireObject("nested");
    v.RequireArray("items");
    v.RequireArray("tags");

    auto errors = v.Validate(loader);
    ASSERT_EQ(errors.size(), 0u);

    // Add a missing required field
    v.RequireString("totally.missing");
    errors = v.Validate(loader);
    ASSERT_TRUE(errors.size() >= 1u);
    ASSERT_TRUE(errors[0].find("totally.missing") != std::string::npos);

    // ValidateOrThrow should throw
    ASSERT_THROWS(v.ValidateOrThrow(loader));

    // Optional field present with wrong type
    json::JsonValidator v2;
    v2.Optional("name",    json::JsonFieldType::BOOL); // name is string
    errors = v2.Validate(loader);
    ASSERT_TRUE(errors.size() >= 1u);

    // Optional field absent — no error
    json::JsonValidator v3;
    v3.Optional("not.there", json::JsonFieldType::STRING);
    errors = v3.Validate(loader);
    ASSERT_EQ(errors.size(), 0u);

    return true;
}

// ===========================================================================
// Test 11: Dump output is valid JSON
// ===========================================================================
bool test_dump() {
    auto loader  = json::JsonLoader::FromString(kSimpleJson);
    std::string dumped = loader.Dump(2);
    ASSERT_TRUE(!dumped.empty());

    // Re-parse the dump
    auto reloaded = json::JsonLoader::FromString(dumped);
    ASSERT_EQ(reloaded.GetString("name"), std::string("uav-fanet"));
    ASSERT_EQ(reloaded.GetBool("enabled"), true);
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 1 Module 5 — JSON Loader Framework\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    // Suppress logger output during tests
    log::Logger::Instance().Initialize(
        "/tmp/uav_json_test_logs",
        log::LogLevel::WARN,
        false);

    RunTest("from_string",       test_from_string);
    RunTest("typed_getters",     test_typed_getters);
    RunTest("optional_getters",  test_optional_getters);
    RunTest("arrays",            test_arrays);
    RunTest("sub_loader",        test_sub_loader);
    RunTest("error_handling",    test_error_handling);
    RunTest("merge",             test_merge);
    RunTest("file_roundtrip",    test_file_roundtrip);
    RunTest("load_sim_config",   test_load_sim_config);
    RunTest("validator",         test_validator);
    RunTest("dump",              test_dump);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, "
              << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}