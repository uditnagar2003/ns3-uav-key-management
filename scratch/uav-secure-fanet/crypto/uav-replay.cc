/**
 * crypto/uav-replay.cc
 */

#include "uav-replay.h"
#include "uav-byte-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <cstring>
#include <algorithm>

namespace uav {
namespace crypto {

// ===========================================================================
// ReplayToken
// ===========================================================================

ReplayToken ReplayToken::Generate(utils::u64 sequence_num) {
    ReplayToken t;
    t.timestamp_us = utils::TimeUtils::NowEpochMicros();
    t.nonce        = OpenSSLRand::RandomNonce128();
    t.sequence_num = sequence_num;
    return t;
}

utils::ByteBuffer ReplayToken::Serialize() const {
    utils::ByteBuffer buf;
    buf.reserve(WIRE_SIZE);

    // [timestamp_us(8)][nonce(16)][sequence_num(8)] = 32 bytes
    utils::ByteUtils::AppendU64BE(buf, timestamp_us);
    utils::ByteUtils::AppendBytes(buf, nonce.data(), nonce.size());
    utils::ByteUtils::AppendU64BE(buf, sequence_num);

    return buf;
}

ReplayToken ReplayToken::Deserialize(const utils::ByteBuffer& buf) {
    return Deserialize(buf.data(), buf.size());
}

ReplayToken ReplayToken::Deserialize(const utils::u8* data,
                                      std::size_t len) {
    if (len < WIRE_SIZE) {
        UAV_THROW(utils::SerializationException,
            "ReplayToken::Deserialize: need "
            + std::to_string(WIRE_SIZE)
            + " bytes, got "
            + std::to_string(len));
    }

    ReplayToken t;
    const utils::u8* p = data;

    t.timestamp_us = utils::ByteUtils::ReadU64BE(p);
    p += 8;

    std::memcpy(t.nonce.data(), p, 16);
    p += 16;

    t.sequence_num = utils::ByteUtils::ReadU64BE(p);

    return t;
}

// ===========================================================================
// ReplayCheckResult string
// ===========================================================================

const char* ReplayCheckResultToString(ReplayCheckResult r) {
    switch (r) {
        case ReplayCheckResult::ACCEPTED:         return "ACCEPTED";
        case ReplayCheckResult::REPLAY_TIMESTAMP: return "REPLAY_TIMESTAMP";
        case ReplayCheckResult::REPLAY_NONCE:     return "REPLAY_NONCE";
        case ReplayCheckResult::REPLAY_SEQUENCE:  return "REPLAY_SEQUENCE";
        case ReplayCheckResult::REPLAY_OLD_SEQ:   return "REPLAY_OLD_SEQ";
    }
    return "UNKNOWN";
}

// ===========================================================================
// ReplayCache
// ===========================================================================

ReplayCache::ReplayCache(utils::u64 max_skew_us,
                          utils::u32 window_size)
    : m_max_skew_us(max_skew_us)
    , m_window_size(window_size)
{}

// ---------------------------------------------------------------------------
// CheckAndRecord / CheckOnly / CheckOrThrow
// ---------------------------------------------------------------------------

ReplayCheckResult ReplayCache::CheckAndRecord(
    utils::u32         sender_id,
    const ReplayToken& token,
    utils::u64         now_us)
{
    return DoCheck(sender_id, token, now_us, /*record=*/true);
}

ReplayCheckResult ReplayCache::CheckOnly(
    utils::u32         sender_id,
    const ReplayToken& token,
    utils::u64         now_us) const
{
    return const_cast<ReplayCache*>(this)->DoCheck(
        sender_id, token, now_us, /*record=*/false);
}

void ReplayCache::CheckOrThrow(
    utils::u32         sender_id,
    const ReplayToken& token,
    utils::u64         now_us)
{
    auto result = CheckAndRecord(sender_id, token, now_us);
    if (result != ReplayCheckResult::ACCEPTED) {
        UAV_THROW(utils::CryptoException,
            std::string("Replay attack detected: ")
            + ReplayCheckResultToString(result)
            + " sender=" + std::to_string(sender_id)
            + " seq="    + std::to_string(token.sequence_num));
    }
}

// ---------------------------------------------------------------------------
// DoCheck — core logic
// ---------------------------------------------------------------------------

ReplayCheckResult ReplayCache::DoCheck(
    utils::u32         sender_id,
    const ReplayToken& token,
    utils::u64         now_us,
    bool               record)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    // Use wall clock if not provided
    if (now_us == 0) {
        now_us = utils::TimeUtils::NowEpochMicros();
    }

    // Layer 1: Timestamp check
    if (!CheckTimestamp(token.timestamp_us, now_us)) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "Replay: TIMESTAMP out of window "
            "sender=" << sender_id
            << " pkt_ts=" << token.timestamp_us
            << " now=" << now_us
            << " skew=" << m_max_skew_us);
        return ReplayCheckResult::REPLAY_TIMESTAMP;
    }

    // Get or create sender state
    auto& state = m_senders[sender_id];

    // Layer 2: Nonce check
    if (!CheckNonce(state, token.nonce)) {
        UAV_LOG_WARN(uav::log::channels::PACKET,
            "Replay: NONCE duplicate sender=" << sender_id
            << " seq=" << token.sequence_num);
        return ReplayCheckResult::REPLAY_NONCE;
    }

    // Layer 3: Sequence number check
    if (state.last_seq > 0) {
        // Check if too old (outside window)
        if (token.sequence_num + m_window_size <= state.last_seq) {
            UAV_LOG_WARN(uav::log::channels::PACKET,
                "Replay: OLD_SEQ sender=" << sender_id
                << " seq=" << token.sequence_num
                << " last=" << state.last_seq);
            return ReplayCheckResult::REPLAY_OLD_SEQ;
        }

        // Check if within window and already seen
        if (!CheckSequence(state, token.sequence_num)) {
            UAV_LOG_WARN(uav::log::channels::PACKET,
                "Replay: SEQUENCE duplicate sender=" << sender_id
                << " seq=" << token.sequence_num);
            return ReplayCheckResult::REPLAY_SEQUENCE;
        }
    }

    // All checks passed — record if requested
    if (record) {
        RecordNonce(state, token.nonce);
        RecordSequence(state, token.sequence_num);
        state.last_seen_us = now_us;
    }

    return ReplayCheckResult::ACCEPTED;
}

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

bool ReplayCache::CheckTimestamp(utils::u64 pkt_us,
                                  utils::u64 now_us) const {
    utils::u64 diff = (pkt_us > now_us)
                    ? (pkt_us - now_us)
                    : (now_us - pkt_us);
    return diff <= m_max_skew_us;
}

bool ReplayCache::CheckNonce(const SenderState&     state,
                              const utils::Nonce128& nonce) const {
    for (const auto& cached : state.nonce_cache) {
        // Check if this nonce slot is in use
        // (all-zero means unused slot)
        bool slot_used = false;
        for (auto b : cached) {
            if (b != 0) { slot_used = true; break; }
        }
        if (slot_used && cached == nonce) {
            return false;  // duplicate nonce
        }
    }
    return true;  // nonce is fresh
}

bool ReplayCache::CheckSequence(const SenderState& state,
                                 utils::u64         seq) const {
    if (seq > state.last_seq) {
        return true;  // new sequence — always fresh
    }

    // Within window — check bitmap
    utils::u64 diff = state.last_seq - seq;
    if (diff >= 64) {
        return false;  // outside window
    }

    // Check if bit is already set (already seen)
    utils::u64 bit = (utils::u64(1) << diff);
    return (state.window_bitmap & bit) == 0;
}

// ---------------------------------------------------------------------------
// Record helpers
// ---------------------------------------------------------------------------

void ReplayCache::RecordNonce(SenderState&           state,
                               const utils::Nonce128& nonce) {
    // Ring buffer — overwrite oldest entry
    state.nonce_cache[state.nonce_head] = nonce;
    state.nonce_head =
        (state.nonce_head + 1) % SenderState::NONCE_CACHE_SIZE;
}

void ReplayCache::RecordSequence(SenderState& state,
                                  utils::u64   seq) {
    if (seq > state.last_seq) {
        // Advance window
        utils::u64 advance = seq - state.last_seq;
        if (advance >= 64) {
            state.window_bitmap = 0;
        } else {
            state.window_bitmap <<= advance;
        }
        // Mark current position (bit 0 = last_seq)
        state.window_bitmap |= 1ULL;
        state.last_seq = seq;
    } else {
        // Within window — mark as seen
        utils::u64 diff = state.last_seq - seq;
        if (diff < 64) {
            state.window_bitmap |= (utils::u64(1) << diff);
        }
    }
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

void ReplayCache::ResetSender(utils::u32 sender_id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_senders.erase(sender_id);
}

void ReplayCache::Reset() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_senders.clear();
}

void ReplayCache::Evict(utils::u64 max_age_us) {
    std::lock_guard<std::mutex> lk(m_mtx);
    utils::u64 now = utils::TimeUtils::NowEpochMicros();
    auto it = m_senders.begin();
    while (it != m_senders.end()) {
        if (it->second.last_seen_us > 0 &&
            (now - it->second.last_seen_us) > max_age_us) {
            it = m_senders.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t ReplayCache::SenderCount() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_senders.size();
}

bool ReplayCache::HasSender(utils::u32 sender_id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_senders.count(sender_id) > 0;
}

// ===========================================================================
// SequenceCounter
// ===========================================================================

utils::u64 SequenceCounter::Next() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_counter++;
}

void SequenceCounter::Reset(utils::u64 val) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_counter = val;
}

} // namespace crypto
} // namespace uav