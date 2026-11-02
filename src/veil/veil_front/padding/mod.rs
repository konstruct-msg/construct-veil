//! Padding for veil-front — shape-level defense (length bucketing, chaff, jitter).
//!
//! **Division of labor:** veil-front is a dumb byte ferry — it does shape-level
//! defense but cannot do semantic batching of application messages. Semantic
//! batching of presence/receipts/typing is an app-layer concern.
//!
//! Governing asymmetry: delay hurts an interactive app far more than bandwidth —
//! prefer spending bytes over latency. The only mode is the front-loaded chaff in
//! [`mode0_front`] (~0 latency, ~33% bandwidth).

pub mod mode0_front;

use std::time::Instant;

use construct_veil_protocol::{Frame, LENGTH_BUCKETS, pick_bucket};

/// Round a size up to the nearest length bucket.
///
/// Thin wrapper over [`pick_bucket`] using the canonical `LENGTH_BUCKETS`
/// table from `construct_veil_protocol`. Kept for ergonomic call sites.
pub fn bucket_size(size: usize) -> usize {
    pick_bucket(LENGTH_BUCKETS, size)
}

/// Trait for a chaff scheduler.
///
/// The scheduler decides when and how much chaff to inject.
/// It is informed about payload writes (so it can yield to them) and
/// produces chaff frames when the connection is idle.
pub trait ChaffScheduler: Send + 'static {
    /// Record that a payload frame was just sent, at wall-clock instant `now`.
    /// The scheduler should defer chaff to avoid HOL blocking. `now` is injected
    /// by the caller (sans-IO): the scheduler reads no clock of its own, so its
    /// timing is deterministic under test.
    fn on_payload_sent(&mut self, now: Instant, payload_len: usize);

    /// Poll for the next frame to send, as of wall-clock instant `now`.
    ///
    /// - Returns `Some(chaff_frame)` if the scheduler wants to inject chaff now.
    /// - Returns `None` if the scheduler is waiting (for a payload, or for time).
    ///
    /// The caller MUST check for pending payload frames first.
    /// Chaff is only sent when there is no payload to send. `now` is injected by
    /// the caller (sans-IO) rather than read from the system clock.
    fn poll_chaff(&mut self, now: Instant) -> Option<Frame>;

    /// Whether the scheduler has any pending chaff.
    fn has_pending(&self) -> bool;

    /// Total chaff bytes injected so far (for metrics).
    fn chaff_bytes_sent(&self) -> u64;

    /// Total payload bytes sent so far (for overhead calculation).
    fn payload_bytes_sent(&self) -> u64;

    /// Current overhead ratio (chaff / payload). Returns 0.0 if no payload sent.
    fn overhead_ratio(&self) -> f64 {
        let payload = self.payload_bytes_sent();
        if payload == 0 {
            return 0.0;
        }
        self.chaff_bytes_sent() as f64 / payload as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_size_rounds_up() {
        assert_eq!(bucket_size(0), 64);
        assert_eq!(bucket_size(1), 64);
        assert_eq!(bucket_size(64), 64);
        assert_eq!(bucket_size(65), 128);
        assert_eq!(bucket_size(100), 128);
        assert_eq!(bucket_size(128), 128);
        assert_eq!(bucket_size(129), 192);
        assert_eq!(bucket_size(500), 512);
        assert_eq!(bucket_size(1000), 1024);
        assert_eq!(bucket_size(10000), 12288);
    }

    #[test]
    fn bucket_size_preserves_large() {
        assert_eq!(bucket_size(20000), 20000);
    }
}
