//! Time-bucketed replay filter for obfs4 handshake MACs.
//!
//! Prevents active probing attacks: an adversary who captures a valid
//! client handshake cannot replay it to fingerprint the server as obfs4.
//!
//! ## Design
//!
//! Mirrors the Go reference `replayfilter.ReplayFilter`:
//! - Two rotating buckets (current epoch hour + previous epoch hour)
//! - On each new connection, the 16-byte handshake MAC is checked against
//!   both buckets. If found → replay, reject with random delay.
//! - If not found → insert into current bucket and proceed.
//! - When the epoch hour rolls over, `prev = current; current = new empty`.
//!
//! This gives a ~2-hour replay protection window, matching the ±1h clock
//! skew tolerance in the MAC verification.
//!
//! ## Memory safety under flood attacks
//!
//! Each bucket is capped at [`MAX_BUCKET_SIZE`] entries (1.6 MB at 16 B/MAC).
//! When the cap is reached, new MACs are *not* inserted — the connection is
//! allowed but not tracked.  This is a deliberate trade-off: an attacker who
//! can flood the filter with 100 000 unique MACs *per epoch hour* can then
//! replay connections in that same window.  However:
//!
//! - The attacker must sustain ≥ 100 000 unique-MAC connections/hour (~28/s)
//!   to overflow a bucket — trivially detectable at the network level.
//! - The alternative (unbounded growth) risks OOM on mobile clients.
//! - [`ReplayFilter::evictions`] exposes the counter so callers can log or alert.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of MACs stored in a single epoch bucket.
///
/// At 16 bytes per MAC this is ~1.6 MB per bucket (3.2 MB total for both
/// buckets).  Chosen to be generous for legitimate traffic (a busy relay
/// handles < 1 000 connections/hour) while capping attacker-controlled growth.
pub const MAX_BUCKET_SIZE: usize = 100_000;

/// Time-bucketed replay filter. Must be shared via `Arc<Mutex<ReplayFilter>>`
/// across concurrent `accept()` calls.
pub struct ReplayFilter {
    current_epoch: u64,
    current_bucket: HashSet<[u8; 16]>,
    prev_bucket: HashSet<[u8; 16]>,
    /// Total MACs dropped due to bucket capacity being reached.
    ///
    /// A non-zero count may indicate a flood attack.  Callers can read this
    /// with [`ReplayFilter::evictions`] and emit a warning metric.
    evictions: u64,
}

impl ReplayFilter {
    /// Create a new empty replay filter.
    pub fn new() -> Self {
        ReplayFilter {
            current_epoch: epoch_hour(),
            current_bucket: HashSet::new(),
            prev_bucket: HashSet::new(),
            evictions: 0,
        }
    }

    /// Test whether `mac` was seen before, and if not, record it.
    ///
    /// Returns `true` if this is a **replay** (already seen) → caller should
    /// reject the connection.
    /// Returns `false` if this is a new MAC → connection is allowed.
    ///
    /// If the current bucket is at [`MAX_BUCKET_SIZE`], the MAC is *not*
    /// stored (graceful degradation under flood) and [`ReplayFilter::evictions`]
    /// is incremented.
    pub fn test_and_set(&mut self, mac: [u8; 16]) -> bool {
        self.maybe_rotate();

        if self.current_bucket.contains(&mac) || self.prev_bucket.contains(&mac) {
            return true; // replay detected
        }

        if self.current_bucket.len() < MAX_BUCKET_SIZE {
            self.current_bucket.insert(mac);
        } else {
            // Bucket full — allow but do not track (graceful degradation).
            self.evictions += 1;
        }
        false
    }

    /// Returns the number of MACs that were dropped because the bucket was full.
    ///
    /// A non-zero value may indicate a flood / DoS attack.
    #[inline]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Rotate buckets if the epoch hour has changed.
    fn maybe_rotate(&mut self) {
        let now = epoch_hour();
        if now != self.current_epoch {
            self.prev_bucket = std::mem::take(&mut self.current_bucket);
            self.current_epoch = now;
        }
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_mac_is_not_replay() {
        let mut f = ReplayFilter::new();
        let mac = [1u8; 16];
        assert!(!f.test_and_set(mac));
    }

    #[test]
    fn second_same_mac_is_replay() {
        let mut f = ReplayFilter::new();
        let mac = [2u8; 16];
        assert!(!f.test_and_set(mac));
        assert!(f.test_and_set(mac));
    }

    #[test]
    fn different_macs_not_replay() {
        let mut f = ReplayFilter::new();
        for i in 0u8..=10 {
            let mac = [i; 16];
            assert!(!f.test_and_set(mac), "mac {i} should not be a replay");
        }
    }

    #[test]
    fn rotation_clears_old_current_into_prev() {
        let mut f = ReplayFilter::new();
        let mac = [42u8; 16];

        // Insert in current epoch
        assert!(!f.test_and_set(mac));

        // Simulate epoch rollover
        f.current_epoch -= 1;
        f.maybe_rotate();

        // mac should now be in prev_bucket — still a replay
        assert!(f.test_and_set(mac));
    }

    #[test]
    fn after_two_rotations_mac_is_forgotten() {
        let mut f = ReplayFilter::new();
        let mac = [7u8; 16];
        assert!(!f.test_and_set(mac));

        // Two epoch rollovers
        f.current_epoch -= 1;
        f.maybe_rotate(); // mac moves to prev_bucket
        f.current_epoch -= 1;
        f.maybe_rotate(); // prev_bucket is replaced → mac forgotten

        // Now the same MAC should be accepted again
        assert!(!f.test_and_set(mac));
    }

    #[test]
    fn bucket_cap_prevents_unbounded_growth() {
        let mut f = ReplayFilter::new();
        // Fill to cap
        for i in 0u64..MAX_BUCKET_SIZE as u64 {
            let mut mac = [0u8; 16];
            mac[..8].copy_from_slice(&i.to_le_bytes());
            assert!(!f.test_and_set(mac));
        }
        assert_eq!(f.current_bucket.len(), MAX_BUCKET_SIZE);
        assert_eq!(f.evictions(), 0);

        // One more unique MAC — should not be inserted, eviction counted
        let overflow_mac = [0xff; 16];
        assert!(!f.test_and_set(overflow_mac)); // allowed (not a replay)
        assert_eq!(f.current_bucket.len(), MAX_BUCKET_SIZE); // no growth
        assert_eq!(f.evictions(), 1);

        // Evicted MAC is not protected — same MAC is allowed again (no replay detection)
        assert!(!f.test_and_set(overflow_mac));
        assert_eq!(f.evictions(), 2);
    }

    #[test]
    fn evictions_reset_after_rotation() {
        let mut f = ReplayFilter::new();
        // Overflow the bucket
        for i in 0u64..=MAX_BUCKET_SIZE as u64 {
            let mut mac = [0u8; 16];
            mac[..8].copy_from_slice(&i.to_le_bytes());
            f.test_and_set(mac);
        }
        assert_eq!(f.evictions(), 1);

        // After rotation new current bucket is empty — eviction counter is cumulative
        f.current_epoch -= 1;
        f.maybe_rotate();
        assert_eq!(f.current_bucket.len(), 0);
        // Counter is cumulative (intentional — operators can track total flood volume)
        assert_eq!(f.evictions(), 1);
    }
}
