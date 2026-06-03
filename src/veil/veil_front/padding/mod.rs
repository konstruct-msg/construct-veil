//! Padding modes for veil-front — shape-level defense (length bucketing, chaff, jitter).
//!
//! **Division of labor:** veil-front is a dumb byte ferry — it does shape-level
//! defense but cannot do semantic batching of application messages. Semantic
//! batching of presence/receipts/typing is an app-layer concern.
//!
//! Governing asymmetry: delay hurts an interactive app far more than bandwidth —
//! prefer spending bytes over latency.
//!
//! # Modes
//!
//! | Mode | Name | Description | Latency | Bandwidth |
//! |------|------|-------------|---------|-----------|
//! | 0 | FRONT-style | Front-loaded chaff at connection start, length bucketing | ~0 | ~33% |
//! | 1 | Idle cover | Low-rate background chaff during idle periods | negligible | low |
//! | 2 | Constant-rate | Fixed cadence regardless of payload (desktop only) | low | high |

pub mod mode0_front;

use bytes::Bytes;
use construct_veil_protocol::{FRAME_TYPE_CHAFF, FRAME_TYPE_DATA, Frame};

/// Padding mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PaddingMode {
    /// Front-loaded chaff + length bucketing (mobile-safe default).
    #[default]
    Front = 0,
    /// Low-rate background chaff during idle periods.
    Idle = 1,
    /// Constant-rate cover traffic (desktop only).
    ConstantRate = 2,
}

impl PaddingMode {
    /// Parse from a u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Front),
            1 => Some(Self::Idle),
            2 => Some(Self::ConstantRate),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Front => "front",
            Self::Idle => "idle",
            Self::ConstantRate => "constant-rate",
        }
    }
}

/// Length buckets for TLS record padding (RFC 8446 §5.4).
/// Frames are padded to the nearest bucket size.
///
/// These buckets are chosen to cover the range of typical gRPC frame sizes
/// while minimizing the number of distinct length values visible to DPI.
pub const LENGTH_BUCKETS: &[usize] = &[
    64, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384,
];

/// TLS 1.3 per-record overhead (header + AEAD tag + inner content type).
/// Used to compute application-data padding that results in bucketed TLS records.
///
/// TLS record: `[5 header][encrypted(plaintext + 1 content_type + AEAD_tag(16))]`
const TLS_RECORD_OVERHEAD: usize = 5 + 1 + 16;

/// Round a size up to the nearest length bucket.
///
/// If the size exceeds the largest bucket, it is returned as-is.
pub fn bucket_size(size: usize) -> usize {
    for &bucket in LENGTH_BUCKETS {
        if size <= bucket {
            return bucket;
        }
    }
    size
}

/// Bucket a TLS record by padding the application data.
///
/// Given `data_len` bytes of application data, returns the target application
/// data length that, after TLS encryption, produces a TLS record in the nearest
/// `LENGTH_BUCKETS` bucket.
///
/// This implements RFC 8446 §5.4 record padding at the application layer:
/// the caller writes `data + padding` to the TLS stream, and rustls encrypts
/// it into a single record whose total length matches a bucket.
pub fn tls_record_bucket(data_len: usize) -> usize {
    // The TLS record size = data_len + TLS_RECORD_OVERHEAD.
    // We want this to match a LENGTH_BUCKET.
    let record_size = data_len + TLS_RECORD_OVERHEAD;
    let target_record = bucket_size(record_size);
    // Target application data = target record - overhead.
    target_record.saturating_sub(TLS_RECORD_OVERHEAD)
}

/// Trait for a chaff scheduler.
///
/// The scheduler decides when and how much chaff to inject.
/// It is informed about payload writes (so it can yield to them) and
/// produces chaff frames when the connection is idle.
pub trait ChaffScheduler: Send + 'static {
    /// Record that a payload frame was just sent.
    /// The scheduler should defer chaff to avoid HOL blocking.
    fn on_payload_sent(&mut self, payload_len: usize);

    /// Poll for the next frame to send.
    ///
    /// - Returns `Some(chaff_frame)` if the scheduler wants to inject chaff now.
    /// - Returns `None` if the scheduler is waiting (for a payload, or for time).
    ///
    /// The caller MUST check for pending payload frames first.
    /// Chaff is only sent when there is no payload to send.
    fn poll_chaff(&mut self) -> Option<Frame>;

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

/// Create a chaff frame with random payload, bucketed to a target size.
pub fn make_chaff_frame(target_size: usize) -> Frame {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::from_entropy();
    let mut payload = vec![0u8; target_size];
    rng.fill(&mut payload[..]);

    Frame::new(FRAME_TYPE_CHAFF, Bytes::from(payload))
}

/// Wrap a payload frame with length bucketing.
///
/// If the payload is smaller than the nearest bucket, it is padded
/// with zero bytes (the receiver ignores padding after the frame content).
/// For DATA frames, the padding is part of the payload — the receiver
/// must know the actual data length (handled by the h2c framing above veil-front).
pub fn bucket_data_frame(payload: Bytes) -> Frame {
    let target = bucket_size(payload.len());
    if payload.len() >= target {
        // Already at or above bucket size — no padding needed.
        return Frame::new(FRAME_TYPE_DATA, payload);
    }

    // Pad with random bytes (not zeros — zeros look suspicious to classifiers).
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::from_entropy();
    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(&payload);
    let padding_len = target - payload.len();
    let mut pad_bytes = vec![0u8; padding_len];
    rng.fill(&mut pad_bytes[..]);
    padded.extend_from_slice(&pad_bytes);

    Frame::new(FRAME_TYPE_DATA, Bytes::from(padded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::{FRAME_TYPE_CHAFF, FRAME_TYPE_DATA};

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

    #[test]
    fn padding_mode_from_u8() {
        assert_eq!(PaddingMode::from_u8(0), Some(PaddingMode::Front));
        assert_eq!(PaddingMode::from_u8(1), Some(PaddingMode::Idle));
        assert_eq!(PaddingMode::from_u8(2), Some(PaddingMode::ConstantRate));
        assert_eq!(PaddingMode::from_u8(3), None);
        assert_eq!(PaddingMode::from_u8(255), None);
    }

    #[test]
    fn chaff_frame_has_correct_type() {
        let frame = make_chaff_frame(128);
        assert_eq!(frame.frame_type, FRAME_TYPE_CHAFF);
        assert_eq!(frame.payload.len(), 128);
    }

    #[test]
    fn bucket_data_frame_pads_small() {
        let payload = Bytes::from(&b"hello"[..]);
        let frame = bucket_data_frame(payload.clone());
        assert_eq!(frame.frame_type, FRAME_TYPE_DATA);
        // Padded to nearest bucket (64).
        assert_eq!(frame.payload.len(), 64);
        // Original payload is at the start.
        assert_eq!(&frame.payload[..5], &b"hello"[..]);
    }

    #[test]
    fn bucket_data_frame_no_pad_large() {
        let payload = Bytes::from(vec![0xAB; 16384]); // At the largest bucket
        let frame = bucket_data_frame(payload.clone());
        assert_eq!(frame.payload.len(), 16384); // No padding needed
    }

    #[test]
    fn tls_record_bucket_accounts_for_overhead() {
        // 0 bytes of app data → TLS record = 0 + 22 = 22 → bucket to 64
        // So target app data = 64 - 22 = 42
        assert_eq!(tls_record_bucket(0), 42); // 42 + 22 = 64

        // 100 bytes of app data → TLS record = 100 + 22 = 122 → bucket to 128
        // So target app data = 128 - 22 = 106
        assert_eq!(tls_record_bucket(100), 106); // 106 + 22 = 128

        // 500 bytes → TLS record = 522 → bucket to 512... no, 522 > 512 → 768
        // Wait: 500 + 22 = 522. Bucket for 522 is 768. So target = 768 - 22 = 746.
        assert_eq!(tls_record_bucket(500), 746); // 746 + 22 = 768
    }

    #[test]
    fn tls_record_bucket_preserves_large() {
        // 20000 bytes → TLS record = 20022 → beyond largest bucket → returns 20000
        assert_eq!(tls_record_bucket(20000), 20000);
    }
}
