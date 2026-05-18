/**
 * utils/uav-time-utils.cc
 */

#include "uav-time-utils.h"

#include <chrono>
#include <thread>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace uav {
namespace utils {

// ===========================================================================
// TimeUtils
// ===========================================================================

u64 TimeUtils::NowEpochMicros() {
    using namespace std::chrono;
    auto now = system_clock::now().time_since_epoch();
    return static_cast<u64>(duration_cast<microseconds>(now).count());
}

u64 TimeUtils::NowSteadyMicros() {
    using namespace std::chrono;
    auto now = steady_clock::now().time_since_epoch();
    return static_cast<u64>(duration_cast<microseconds>(now).count());
}

std::string TimeUtils::NowIso8601() {
    return FormatEpochMicros(NowEpochMicros());
}

std::string TimeUtils::NowFileSafe() {
    using namespace std::chrono;
    auto epoch = system_clock::now().time_since_epoch();
    auto secs  = duration_cast<seconds>(epoch).count();
    auto us    = duration_cast<microseconds>(epoch).count() % 1'000'000LL;

    std::time_t t = static_cast<std::time_t>(secs);
    std::tm tm_utc{};
    gmtime_r(&t, &tm_utc);

    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y%m%d_%H%M%S")
        << "_" << std::setw(6) << std::setfill('0') << us;
    return oss.str();
}

std::string TimeUtils::FormatEpochMicros(u64 epoch_us) {
    using namespace std::chrono;
    std::time_t secs = static_cast<std::time_t>(epoch_us / 1'000'000ULL);
    u64 us_part      = epoch_us % 1'000'000ULL;

    std::tm tm_utc{};
    gmtime_r(&secs, &tm_utc);

    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S")
        << "." << std::setw(6) << std::setfill('0') << us_part
        << "Z";
    return oss.str();
}

void TimeUtils::SleepMicros(u64 us) {
    std::this_thread::sleep_for(std::chrono::microseconds(us));
}

void TimeUtils::SleepMillis(u64 ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

u64 TimeUtils::ElapsedMicros(TimePoint start, TimePoint end) {
    using namespace std::chrono;
    return static_cast<u64>(duration_cast<microseconds>(end - start).count());
}

bool TimeUtils::WithinSkew(u64 a_us, u64 b_us, u64 max_skew_us) {
    u64 diff = (a_us > b_us) ? (a_us - b_us) : (b_us - a_us);
    return diff <= max_skew_us;
}

// ===========================================================================
// ScopedTimer
// ===========================================================================

ScopedTimer::ScopedTimer(std::string label)
    : m_label(std::move(label))
    , m_start(SteadyClock::now())
    , m_stopped(false)
{}

ScopedTimer::~ScopedTimer() {
    if (!m_stopped) {
        u64 us = ElapsedMicros();
        // Stderr output is replaced by logger in Module 4.
        std::cerr << "[ScopedTimer] " << m_label
                  << " elapsed=" << us << "us\n";
    }
}

u64 ScopedTimer::Stop() {
    u64 us = ElapsedMicros();
    m_stopped = true;
    return us;
}

u64 ScopedTimer::ElapsedMicros() const {
    return TimeUtils::ElapsedMicros(m_start, SteadyClock::now());
}

} // namespace utils
} // namespace uav