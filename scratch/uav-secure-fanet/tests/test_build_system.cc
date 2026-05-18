/**
 * test_build_system.cc
 * Unit test for Phase 1 Module 2: Build System Integration
 *
 * Tests:
 *   1. OpenSSL EVP header availability and basic init
 *   2. Boost.Multiprecision header availability and basic arithmetic
 *   3. nlohmann/json header availability and basic parse
 *   4. C++17 feature availability
 *   5. Project macro definitions
 *
 * COMPILE (standalone — no NS-3):
 *   g++-13 -std=c++17 -Wall \
 *       -I/usr/include \
 *       tests/test_build_system.cc \
 *       -lssl -lcrypto \
 *       -o test_build_system
 *
 * RUN:
 *   ./test_build_system
 *
 * EXPECTED OUTPUT:
 *   [PASS] C++17 features
 *   [PASS] OpenSSL EVP init
 *   [PASS] Boost.Multiprecision arithmetic
 *   [PASS] nlohmann/json parse
 *   [PASS] Project macros
 *   All 5 tests PASSED.
 */

// ── Standard headers ────────────────────────────────────────────────────────
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <optional>        // C++17
#include <string_view>     // C++17
#include <variant>         // C++17
#include <filesystem>      // C++17

// ── OpenSSL ─────────────────────────────────────────────────────────────────
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// ── Boost.Multiprecision ─────────────────────────────────────────────────────
#include <boost/multiprecision/cpp_int.hpp>

// ── nlohmann/json ────────────────────────────────────────────────────────────
#include <nlohmann/json.hpp>

// ── Project macros (defined by build system) ─────────────────────────────────
#ifndef UAV_PROJECT_VERSION
#define UAV_PROJECT_VERSION "dev"
#endif
#ifndef UAV_LOG_DIR
#define UAV_LOG_DIR "logs"
#endif
#ifndef UAV_OUTPUT_DIR
#define UAV_OUTPUT_DIR "output"
#endif

// ── Test framework ───────────────────────────────────────────────────────────
namespace {

int  g_pass = 0;
int  g_fail = 0;

void test_pass(const std::string& name) {
    std::cout << "[PASS] " << name << "\n";
    ++g_pass;
}

void test_fail(const std::string& name, const std::string& reason) {
    std::cerr << "[FAIL] " << name << " — " << reason << "\n";
    ++g_fail;
}

// ---------------------------------------------------------------------------
// Test 1: C++17 features
// ---------------------------------------------------------------------------
void test_cpp17() {
    const std::string name = "C++17 features";
    try {
        // std::optional
        std::optional<int> opt = 42;
        if (!opt.has_value() || *opt != 42) {
            test_fail(name, "std::optional broken");
            return;
        }

        // std::string_view
        std::string_view sv = "UAV-FANET";
        if (sv.size() != 9) {
            test_fail(name, "std::string_view broken");
            return;
        }

        // std::variant
        std::variant<int, std::string> var = std::string("test");
        if (!std::holds_alternative<std::string>(var)) {
            test_fail(name, "std::variant broken");
            return;
        }

        // Structured bindings
        std::vector<std::pair<int,int>> pairs = {{1,2},{3,4}};
        for (auto& [a, b] : pairs) {
            (void)a; (void)b;
        }

        // if-init statement
        if (int x = 42; x == 42) {
            // ok
        } else {
            test_fail(name, "if-init statement broken");
            return;
        }

        test_pass(name);
    } catch (const std::exception& ex) {
        test_fail(name, ex.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: OpenSSL EVP init and basic RAND_bytes
// ---------------------------------------------------------------------------
void test_openssl_evp() {
    const std::string name = "OpenSSL EVP init";
    try {
        // Initialise OpenSSL (required in older OpenSSL; harmless in 3.x)
        OpenSSL_add_all_algorithms();

        // Generate 32 random bytes
        unsigned char buf[32] = {};
        int rc = RAND_bytes(buf, static_cast<int>(sizeof(buf)));
        if (rc != 1) {
            unsigned long err_code = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            test_fail(name, std::string("RAND_bytes failed: ") + err_buf);
            return;
        }

        // Check buffer is not all-zero (probabilistically)
        bool all_zero = true;
        for (unsigned char b : buf) {
            if (b != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            test_fail(name, "RAND_bytes returned all-zero buffer");
            return;
        }

        // Test EVP_MD_CTX lifecycle
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            test_fail(name, "EVP_MD_CTX_new returned null");
            return;
        }
        EVP_MD_CTX_free(ctx);

        // Verify OpenSSL version
        const char* ver = OpenSSL_version(OPENSSL_VERSION);
        if (!ver || ver[0] == '\0') {
            test_fail(name, "OpenSSL_version returned empty string");
            return;
        }
        std::cout << "  OpenSSL version: " << ver << "\n";

        EVP_cleanup();
        test_pass(name);
    } catch (const std::exception& ex) {
        test_fail(name, ex.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: Boost.Multiprecision arithmetic
// ---------------------------------------------------------------------------
void test_boost_multiprecision() {
    const std::string name = "Boost.Multiprecision arithmetic";
    try {
        using boost::multiprecision::cpp_int;

        // Large integer multiplication
        cpp_int a("123456789012345678901234567890");
        cpp_int b("987654321098765432109876543210");
        cpp_int product = a * b;

        // Expected: 121932631137021795226185032733622923332237463801111263526900
        std::string product_str = product.str();
        if (product_str.empty()) {
            test_fail(name, "cpp_int multiplication produced empty string");
            return;
        }

        // Modular exponentiation (core of CRT/RSA operations)
        cpp_int base("65537");
        cpp_int exp_val("12345678901234567890");
        cpp_int mod("99999999999999999999999999999999");
        cpp_int result = boost::multiprecision::powm(base, exp_val, mod);

        if (result == 0) {
            test_fail(name, "powm returned 0");
            return;
        }
        if (result >= mod) {
            test_fail(name, "powm result >= modulus");
            return;
        }

        std::cout << "  cpp_int product length: " << product_str.size() << " digits\n";
        std::cout << "  powm result: " << result.str().substr(0,20) << "...\n";

        test_pass(name);
    } catch (const std::exception& ex) {
        test_fail(name, ex.what());
    }
}

// ---------------------------------------------------------------------------
// Test 4: nlohmann/json parse and access
// ---------------------------------------------------------------------------
void test_nlohmann_json() {
    const std::string name = "nlohmann/json parse";
    try {
        // Test JSON parse
        std::string json_str = R"({
            "project": "uav-secure-fanet",
            "version": "1.0.0",
            "clusters": 3,
            "uavs_per_cluster": 6,
            "crypto": {
                "scheme": "CRT-GCRT",
                "aes_bits": 256,
                "hmac": "SHA256"
            },
            "primes": [65537, 131071, 262139]
        })";

        nlohmann::json j = nlohmann::json::parse(json_str);

        // Access fields
        if (j["project"] != "uav-secure-fanet") {
            test_fail(name, "project field mismatch");
            return;
        }
        if (j["clusters"] != 3) {
            test_fail(name, "clusters field mismatch");
            return;
        }
        if (j["crypto"]["aes_bits"] != 256) {
            test_fail(name, "nested aes_bits mismatch");
            return;
        }

        // Array access
        auto primes = j["primes"].get<std::vector<uint64_t>>();
        if (primes.size() != 3 || primes[0] != 65537) {
            test_fail(name, "primes array mismatch");
            return;
        }

        // Serialise and re-parse (round-trip)
        std::string serialised = j.dump(2);
        nlohmann::json j2 = nlohmann::json::parse(serialised);
        if (j2["version"] != "1.0.0") {
            test_fail(name, "round-trip serialisation failed");
            return;
        }

        // Test large integer as string (needed for cpp_int serialisation)
        nlohmann::json j3;
        j3["master_key"] = "123456789012345678901234567890987654321";
        std::string mk = j3["master_key"].get<std::string>();
        if (mk.size() < 30) {
            test_fail(name, "large integer string truncated");
            return;
        }

        std::cout << "  JSON round-trip: OK\n";
        std::cout << "  Large integer string length: " << mk.size() << "\n";

        test_pass(name);
    } catch (const std::exception& ex) {
        test_fail(name, ex.what());
    }
}

// ---------------------------------------------------------------------------
// Test 5: Project macro definitions
// ---------------------------------------------------------------------------
void test_project_macros() {
    const std::string name = "Project macros";
    try {
        std::string ver(UAV_PROJECT_VERSION);
        std::string log_dir(UAV_LOG_DIR);
        std::string out_dir(UAV_OUTPUT_DIR);

        std::cout << "  UAV_PROJECT_VERSION : " << ver     << "\n";
        std::cout << "  UAV_LOG_DIR         : " << log_dir << "\n";
        std::cout << "  UAV_OUTPUT_DIR      : " << out_dir << "\n";

        if (log_dir.empty()) {
            test_fail(name, "UAV_LOG_DIR is empty");
            return;
        }
        if (out_dir.empty()) {
            test_fail(name, "UAV_OUTPUT_DIR is empty");
            return;
        }

        test_pass(name);
    } catch (const std::exception& ex) {
        test_fail(name, ex.what());
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 1 Module 2 — Build System Validation\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    test_cpp17();
    test_openssl_evp();
    test_boost_multiprecision();
    test_nlohmann_json();
    test_project_macros();

    std::cout << "\n====================================================\n";
    std::cout << "Results: " << g_pass << " passed, " << g_fail << " failed\n";
    std::cout << "====================================================\n";

    if (g_fail > 0) {
        std::cerr << "SOME TESTS FAILED — fix before proceeding.\n";
        return EXIT_FAILURE;
    }
    std::cout << "All " << g_pass << " tests PASSED.\n";
    return EXIT_SUCCESS;
}