/**
 * crypto/uav-replay.h
 *
 * Replay attack protection for UAV Secure FANET packets.
 *
 * REPLAY ATTACK:
 *   An attacker captures a valid packet and retransmits it later.
 *   Without replay protection, the receiver would accept it as fresh.
 *
 * THREE-LAYER PROTECTION (per project spec):
 *
 *   Layer 1 — Timestamp:
 *     Every packet carries a 64-bit epoch timestamp (microseconds).
 *     Receiver rejects packets outside ±REPLAY_SKEW_US window.
 *     Default skew: 5 seconds (5,000,000 µs).
 *
 *   Layer 2 — Nonce:
 *     Every packet carries a 128-bit random nonce.
 *     Receiver maintains a nonce cache and rejects duplicates.
 *     Cache keyed by (sender_id, nonce).
 *
 *   Layer 3 — Sequence number:
 *     Every packet carries a monotonically increasing 64-bit sequence.
 *     Receiver maintains a sliding window per sender.
 *     Window size: 64 (project spec).
 *     Accepts: seq in [last_seq - window, last_seq + 1]
 *     Rejects: seq <= (last_seq - window) or already-seen seq
 *
 * REPLAY CACHE:
 *   Maintained at both UAV and SKDC nodes.
 *   One ReplayCache instance per node.
 *   Automatic expiry of stale entries (timestamp-based).
 *
 * THREAD SAFETY:
 *   ReplayCache uses std::mutex — safe for concurrent access.
 */

#ifndef UAV_REPLAY_H
#define UAV_REPLAY_H

#include "uav-types.h"
#include "uav-error.h"
#include "uav-time-utils.h"
#include "uav-openssl-rand.h"

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <bitset>

namespace uav {
namespace crypto {

// ===========================================================================
// ReplayToken — per-packet anti-replay fields
// Embedded in every packet header (plaintext, serialized)
// ===========================================================================
struct ReplayToken {
    utils::u64    timestamp_us;    // epoch microseconds (UTC)
    utils::Nonce128 nonce;         // 128-bit random nonce
    utils::u64    sequence_num;    // monotonic per-sender counter

    /// Generate a fresh token for a new outgoing packet.
    static ReplayToken Generate(utils::u64 sequence_num);

    /// Serialize to 32 bytes: [timestamp(8)][nonce(16)][seq(8)]
    utils::ByteBuffer Serialize() const;

    /// Deserialize from 32 bytes. Throws on wrong size.
    static ReplayToken Deserialize(const utils::ByteBuffer& buf);
    static ReplayToken Deserialize(const utils::u8* data,
                                   std::size_t len);

    /// Serialized size in bytes
    static constexpr std::size_t WIRE_SIZE = 32;
};

// ===========================================================================
// ReplayCheckResult — outcome of CheckAndRecord()
// ===========================================================================
enum class ReplayCheckResult : utils::u8 {
    ACCEPTED          = 0,  // fresh packet — accept
    REPLAY_TIMESTAMP  = 1,  // timestamp outside skew window
    REPLAY_NONCE      = 2,  // nonce already seen
    REPLAY_SEQUENCE   = 3,  // sequence number replayed
    REPLAY_OLD_SEQ    = 4,  // sequence number too old
};

const char* ReplayCheckResultToString(ReplayCheckResult r);

// ===========================================================================
// SenderState — per-sender sliding window + nonce cache
// ===========================================================================
struct SenderState {
    utils::u64 last_seq        = 0;
    utils::u64 window_bitmap   = 0;   // 64-bit sliding window
    utils::u64 last_seen_us    = 0;   // last valid timestamp

    // Nonce cache — fixed-size ring (last 64 nonces)
    static constexpr std::size_t NONCE_CACHE_SIZE = 64;
    std::vector<utils::Nonce128> nonce_cache;
    std::size_t                  nonce_head = 0;

    SenderState() : nonce_cache(NONCE_CACHE_SIZE) {}
};

// ===========================================================================
// ReplayCache — per-node replay protection state
// ===========================================================================
class ReplayCache {
public:
    /// @param max_skew_us   Maximum allowed clock skew (default 5s)
    /// @param window_size   Sliding window size (default 64)
    explicit ReplayCache(
        utils::u64 max_skew_us  = 5'000'000ULL,
        utils::u32 window_size  = 64);

    // -----------------------------------------------------------------------
    // Check and Record — main API
    // -----------------------------------------------------------------------

    /// Check a received token against replay state for sender_id.
    /// If accepted, records the token to prevent future replay.
    ///
    /// @param sender_id  Node ID of the packet sender
    /// @param token      ReplayToken from packet header
    /// @param now_us     Current time (epoch µs). 0 = use wall clock.
    ///
    /// @returns ACCEPTED if fresh, replay code otherwise
    ReplayCheckResult CheckAndRecord(
        utils::u32           sender_id,
        const ReplayToken&   token,
        utils::u64           now_us = 0);

    /// Check only (do not record). Used for pre-validation.
    ReplayCheckResult CheckOnly(
        utils::u32           sender_id,
        const ReplayToken&   token,
        utils::u64           now_us = 0) const;

    /// Check and throw CryptoException on replay.
    void CheckOrThrow(
        utils::u32           sender_id,
        const ReplayToken&   token,
        utils::u64           now_us = 0);

    // -----------------------------------------------------------------------
    // State management
    // -----------------------------------------------------------------------

    /// Reset state for a specific sender (e.g. after handover).
    void ResetSender(utils::u32 sender_id);

    /// Reset all state.
    void Reset();

    /// Remove senders whose last_seen_us is older than max_age_us.
    void Evict(utils::u64 max_age_us = 60'000'000ULL);

    /// Number of tracked senders.
    std::size_t SenderCount() const;

    /// True if sender has any recorded state.
    bool HasSender(utils::u32 sender_id) const;

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    utils::u64 MaxSkewUs()   const { return m_max_skew_us;  }
    utils::u32 WindowSize()  const { return m_window_size;  }

    void SetMaxSkewUs(utils::u64 us)  { m_max_skew_us = us; }
    void SetWindowSize(utils::u32 w)  { m_window_size = w;  }

private:
    ReplayCheckResult DoCheck(
        utils::u32           sender_id,
        const ReplayToken&   token,
        utils::u64           now_us,
        bool                 record);

    bool CheckTimestamp(utils::u64 pkt_us,
                        utils::u64 now_us) const;

    bool CheckNonce(const SenderState&  state,
                    const utils::Nonce128& nonce) const;

    bool CheckSequence(const SenderState& state,
                       utils::u64         seq) const;

    void RecordNonce(SenderState&           state,
                     const utils::Nonce128& nonce);

    void RecordSequence(SenderState& state,
                        utils::u64   seq);

    mutable std::mutex                              m_mtx;
    std::unordered_map<utils::u32, SenderState>     m_senders;
    utils::u64                                      m_max_skew_us;
    utils::u32                                      m_window_size;
};

// ===========================================================================
// SequenceCounter — per-sender outgoing sequence number generator
// ===========================================================================
class SequenceCounter {
public:
    explicit SequenceCounter(utils::u64 initial = 1)
        : m_counter(initial) {}

    /// Get next sequence number (atomically increments).
    utils::u64 Next();

    /// Peek current without incrementing.
    utils::u64 Current() const { return m_counter; }

    /// Reset to value (e.g. after handover).
    void Reset(utils::u64 val = 1);

private:
    mutable std::mutex m_mtx;
    utils::u64         m_counter;
};

} // namespace crypto
} // namespace uav

#endif // UAV_REPLAY_H