/**
 * tests/test_logger.cc
 * Unit test for Phase 1 Module 4: Logging Framework
 *
 * COMPILE (standalone — no NS-3):
 *   g++-13 -std=c++17 -Wall -Wextra -pthread \
 *       -I. \
 *       tests/test_logger.cc \
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
 *       -o test_logger
 *
 * RUN:
 *   ./test_logger
 */

#include "utils/uav-logger.h"
#include "utils/uav-csv-logger.h"
#include "utils/uav-log-channels.h"
#include "utils/uav-file-utils.h"
#include "utils/uav-string-utils.h"
#include "utils/uav-time-utils.h"

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;
using namespace uav;

namespace {

int g_pass = 0;
int g_fail = 0;
const std::string kTestRoot = "/tmp/uav_logger_test";

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
    try { ok = fn(); }
    catch (const std::exception& ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        ok = false;
    }
    if (ok) { std::cout << "[ PASS ] " << name << "\n\n"; ++g_pass; }
    else    { std::cout << "[ FAIL ] " << name << "\n\n"; ++g_fail; }
}

bool FileContains(const std::string& path, const std::string& needle) {
    std::string contents = utils::FileUtils::ReadTextFile(path);
    return contents.find(needle) != std::string::npos;
}

std::size_t CountNewlines(const std::string& path) {
    std::string contents = utils::FileUtils::ReadTextFile(path);
    return static_cast<std::size_t>(
        std::count(contents.begin(), contents.end(), '\n'));
}

// ===========================================================================
// Test 1: Log level utilities
// ===========================================================================
bool test_log_levels() {
    using namespace log;
    ASSERT_EQ(LogLevelChar(LogLevel::TRACE), 'T');
    ASSERT_EQ(LogLevelChar(LogLevel::INFO ), 'I');
    ASSERT_EQ(LogLevelChar(LogLevel::FATAL), 'F');

    ASSERT_EQ(std::string(LogLevelToString(LogLevel::WARN)), std::string("WARN"));

    ASSERT_EQ(LogLevelFromString("debug"),    LogLevel::DEBUG);
    ASSERT_EQ(LogLevelFromString("  INFO  "), LogLevel::INFO);
    ASSERT_EQ(LogLevelFromString("err"),      LogLevel::ERROR);
    ASSERT_EQ(LogLevelFromString("garbage"),  LogLevel::OFF);
    return true;
}

// ===========================================================================
// Test 2: Initialize + default channel files created on first write
// ===========================================================================
bool test_initialize_and_channels() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "init");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::TRACE,
                                   /*enable_console=*/false);

    ASSERT_TRUE(Logger::Instance().IsInitialized());
    ASSERT_EQ(Logger::Instance().LogDir(), dir);

    // Write into each mandatory channel.
    UAV_LOG_INFO(channels::CRYPTO,      "crypto channel test");
    UAV_LOG_INFO(channels::ROUTING,     "routing channel test");
    UAV_LOG_INFO(channels::MOBILITY,    "mobility channel test");
    UAV_LOG_INFO(channels::JAMMER,      "jammer channel test");
    UAV_LOG_INFO(channels::REKEY,       "rekey channel test");
    UAV_LOG_INFO(channels::PACKET,      "packet channel test");
    UAV_LOG_INFO(channels::FLOWMONITOR, "flowmon channel test");
    UAV_LOG_INFO(channels::SYSTEM,      "system channel test");

    Logger::Instance().Shutdown();

    // Verify the files exist with the expected content.
    struct { const char* file; const char* needle; } expects[] = {
        { "crypto.log",      "crypto channel test"   },
        { "routing.log",     "routing channel test"  },
        { "mobility.log",    "mobility channel test" },
        { "jammer.log",      "jammer channel test"   },
        { "rekey.log",       "rekey channel test"    },
        { "packet.log",      "packet channel test"   },
        { "flowmonitor.log", "flowmon channel test"  },
        { "system.log",      "system channel test"   },
    };
    for (auto& e : expects) {
        std::string full = utils::FileUtils::JoinPath(dir, e.file);
        ASSERT_TRUE(utils::FileUtils::Exists(full));
        ASSERT_TRUE(FileContains(full, e.needle));
        // Lines must include level char and channel tag.
        ASSERT_TRUE(FileContains(full, "[I]"));
    }
    return true;
}

// ===========================================================================
// Test 3: Filtering — global and per-channel
// ===========================================================================
bool test_filtering() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "filter");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::INFO, /*console=*/false);

    // Global filter blocks DEBUG.
    UAV_LOG_DEBUG(channels::CRYPTO, "should NOT appear (global=INFO)");
    UAV_LOG_INFO (channels::CRYPTO, "should appear (info)");
    UAV_LOG_WARN (channels::CRYPTO, "should appear (warn)");

    // Channel-level override raises crypto to ERROR.
    Logger::Instance().SetChannelLevel(channels::CRYPTO, LogLevel::ERROR);
    UAV_LOG_INFO (channels::CRYPTO, "should NOT appear (channel=ERROR)");
    UAV_LOG_WARN (channels::CRYPTO, "should NOT appear (channel=ERROR)");
    UAV_LOG_ERROR(channels::CRYPTO, "should appear (error)");

    // Routing channel uses global default.
    UAV_LOG_INFO(channels::ROUTING, "routing-info-visible");

    Logger::Instance().Shutdown();

    std::string crypto = utils::FileUtils::JoinPath(dir, "crypto.log");
    ASSERT_TRUE(!FileContains(crypto, "should NOT appear"));
    ASSERT_TRUE(FileContains(crypto, "should appear (info)"));
    ASSERT_TRUE(FileContains(crypto, "should appear (warn)"));
    ASSERT_TRUE(FileContains(crypto, "should appear (error)"));

    std::string routing = utils::FileUtils::JoinPath(dir, "routing.log");
    ASSERT_TRUE(FileContains(routing, "routing-info-visible"));

    // Reset crypto to default for subsequent tests.
    Logger::Instance().SetChannelLevel(channels::CRYPTO, LogLevel::TRACE);
    return true;
}

// ===========================================================================
// Test 4: Stream-style and printf-style macros
// ===========================================================================
bool test_macros() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "macros");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::DEBUG, /*console=*/false);

    int x = 42;
    double y = 3.14;
    UAV_LOG_DEBUG (channels::SYSTEM, "x=" << x << " y=" << y);
    UAV_LOGF_INFO (channels::SYSTEM, "formatted x=%d y=%.2f", x, y);
    UAV_LOG_WARN  (channels::SYSTEM, "warning line");
    UAV_LOG_ERROR (channels::SYSTEM, "error line");

    Logger::Instance().Shutdown();

    std::string p = utils::FileUtils::JoinPath(dir, "system.log");
    ASSERT_TRUE(FileContains(p, "x=42 y=3.14"));
    ASSERT_TRUE(FileContains(p, "formatted x=42 y=3.14"));
    ASSERT_TRUE(FileContains(p, "warning line"));
    ASSERT_TRUE(FileContains(p, "error line"));
    ASSERT_TRUE(FileContains(p, "[D]"));
    ASSERT_TRUE(FileContains(p, "[I]"));
    ASSERT_TRUE(FileContains(p, "[W]"));
    ASSERT_TRUE(FileContains(p, "[E]"));
    return true;
}

// ===========================================================================
// Test 5: Custom channel + bind-to-file
// ===========================================================================
bool test_custom_channel() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "custom");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::TRACE, /*console=*/false);
    Logger::Instance().BindChannelToFile("my-custom", "custom.log");

    UAV_LOG_INFO("my-custom", "hello from custom channel");

    Logger::Instance().Shutdown();

    std::string p = utils::FileUtils::JoinPath(dir, "custom.log");
    ASSERT_TRUE(utils::FileUtils::Exists(p));
    ASSERT_TRUE(FileContains(p, "hello from custom channel"));
    ASSERT_TRUE(FileContains(p, "[my-custom]"));
    return true;
}

// ===========================================================================
// Test 6: Thread safety — concurrent writers
// ===========================================================================
bool test_thread_safety() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "threads");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::TRACE, /*console=*/false);

    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    std::atomic<int> errors{0};

    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([t, &errors]() {
            try {
                for (int i = 0; i < kPerThread; ++i) {
                    UAV_LOGF_INFO(channels::PACKET,
                        "tid=%d seq=%d", t, i);
                }
            } catch (...) { ++errors; }
        });
    }
    for (auto& th : ts) th.join();

    Logger::Instance().Shutdown();

    ASSERT_EQ(errors.load(), 0);

    std::string p = utils::FileUtils::JoinPath(dir, "packet.log");
    std::size_t lines = CountNewlines(p);
    // We expect at least kThreads * kPerThread lines (could be more from
    // any leftover earlier writes — shouldn't be, since we wiped dir).
    ASSERT_EQ(lines, static_cast<std::size_t>(kThreads * kPerThread));
    return true;
}

// ===========================================================================
// Test 7: CSV logger — header, positional row, named row, escape
// ===========================================================================
bool test_csv_logger() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "csv");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::TRACE, /*console=*/false);

    std::string path = utils::FileUtils::JoinPath(dir, "metrics.csv");
    auto csv = CsvLogger::Open(path, { "time_s", "node_id", "value", "note" });
    ASSERT_TRUE(csv->IsOpen());

    csv->AppendRow({ "1.0", "5",  "100", "ok" });
    csv->AppendRow({ "2.5", "12", "250", "with, comma" });
    csv->AppendRow({ "3.0", "7",  "55",  "with \"quote\"" });
    csv->Row().Set("time_s",  4.5)
              .Set("node_id", 9)
              .Set("value",   400)
              .Set("note",    std::string("line\nbreak"))
              .Commit();

    csv->Flush();
    csv->Close();

    ASSERT_EQ(csv->RowsWritten(), static_cast<utils::u64>(4));

    std::string contents = utils::FileUtils::ReadTextFile(path);
    // Header
    ASSERT_TRUE(contents.find("time_s,node_id,value,note\n") != std::string::npos);
    // Comma must be quoted
    ASSERT_TRUE(contents.find("\"with, comma\"") != std::string::npos);
    // Embedded quote must be doubled
    ASSERT_TRUE(contents.find("\"with \"\"quote\"\"\"") != std::string::npos);
    // Newline must be quoted (the field appears mid-row)
    ASSERT_TRUE(contents.find("\"line\nbreak\"") != std::string::npos);

    // Re-open should NOT rewrite header.
    auto csv2 = CsvLogger::Open(path, { "time_s", "node_id", "value", "note" });
    csv2->AppendRow({ "5.0", "1", "1", "x" });
    csv2->Close();

    std::string contents2 = utils::FileUtils::ReadTextFile(path);
    // Count header occurrences — must be exactly 1.
    std::size_t count = 0, pos = 0;
    while ((pos = contents2.find("time_s,node_id", pos)) != std::string::npos) {
        ++count;
        pos += 1;
    }
    ASSERT_EQ(count, 1u);
    return true;
}

// ===========================================================================
// Test 8: Logger never throws — invalid args, missing channel
// ===========================================================================
bool test_no_throw() {
    using namespace log;
    std::string dir = utils::FileUtils::JoinPath(kTestRoot, "noexc");
    std::error_code ec;
    fs::remove_all(dir, ec);

    Logger::Instance().Initialize(dir, LogLevel::TRACE, /*console=*/false);

    bool threw = false;
    try {
        // null fmt — logger should silently no-op.
        Logger::Instance().Logf(LogLevel::INFO, channels::SYSTEM,
            __FILE__, __LINE__, __func__, nullptr);
        // Brand-new channel — must auto-bind.
        UAV_LOG_INFO("never-seen-before", "auto-bound");
    } catch (...) {
        threw = true;
    }
    ASSERT_TRUE(!threw);
    Logger::Instance().Shutdown();
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "====================================================\n";
    std::cout << "Phase 1 Module 4 — Logging Framework\n";
    std::cout << "UAV Secure FANET / NS-3.43\n";
    std::cout << "====================================================\n\n";

    // Ensure clean test root.
    std::error_code ec;
    fs::remove_all(kTestRoot, ec);

    RunTest("log_levels",            test_log_levels);
    RunTest("initialize_and_channels", test_initialize_and_channels);
    RunTest("filtering",             test_filtering);
    RunTest("macros",                test_macros);
    RunTest("custom_channel",        test_custom_channel);
    RunTest("thread_safety",         test_thread_safety);
    RunTest("csv_logger",            test_csv_logger);
    RunTest("no_throw",              test_no_throw);

    // Cleanup
    fs::remove_all(kTestRoot, ec);

    std::cout << "====================================================\n";
    std::cout << "Results: " << g_pass << " passed, " << g_fail << " failed\n";
    std::cout << "====================================================\n";

    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}