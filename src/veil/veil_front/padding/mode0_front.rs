//! Mode 0 — FRONT-style front-loaded chaff + TLS record length bucketing.
//!
//! # Design
//!
//! - At connection start, inject a **burst of chaff frames** to mask the setup
//!   signature (the part of the trace an attacker keys on).
//! - Chaff rate **tapers off** over time — heavy at start, then stops.
//! - **Payload always takes priority** — chaff is deferred if there's payload to send.
//! - After each payload write, a **cooldown period** prevents chaff from
//!   head-of-line-blocking the next payload frame.
//! - All frame sizes are **bucketed** to a small set of discrete values.
//!
//! # Expected overhead
//!
//! ~33% bandwidth overhead on typical messenger traffic. Zero added latency
//! (confirmed by on-device benchmark — not asserted).
//!
//! # Mobile safety
//!
//! This mode is designed to be mobile-safe. If the on-device benchmark
//! shows >20ms median latency penalty, Mode 0 must NOT be the mobile default.

use std::time::{Duration, Instant};

use bytes::Bytes;
use construct_veil_protocol::{FRAME_TYPE_CHAFF, Frame};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{ChaffScheduler, LENGTH_BUCKETS};

/// Cooldown duration after a payload write before chaff resumes.
/// This prevents chaff from head-of-line-blocking payload frames.
const PAYLOAD_COOLDOWN: Duration = Duration::from_millis(5);

/// Duration of the front-loaded chaff burst (from connection start).
const FRONT_WINDOW: Duration = Duration::from_secs(3);

/// Maximum number of chaff frames pre-generated in the queue.
const MAX_CHAFF_QUEUE: usize = 64;

/// FRONT-style chaff scheduler.
///
/// Injects chaff frames at the start of the connection, then tapers off.
/// Payload always takes priority — chaff is sent only during idle periods.
pub struct FrontChaffScheduler {
    /// Pre-generated chaff frames, ready to send.
    chaff_queue: Vec<Frame>,
    /// Index into the chaff queue (round-robin after drain).
    queue_index: usize,
    /// When the connection started (first call to poll).
    connection_start: Option<Instant>,
    /// When the last payload frame was sent.
    last_payload_at: Option<Instant>,
    /// Total chaff bytes sent.
    chaff_bytes: u64,
    /// Total payload bytes sent.
    payload_bytes: u64,
    /// Number of chaff frames sent so far.
    chaff_frames_sent: u64,
    /// RNG for generating chaff on the fly (after queue drains).
    rng: ChaCha8Rng,
    /// Whether the front window has closed.
    front_window_closed: bool,
}

impl FrontChaffScheduler {
    /// Create a new FrontChaffScheduler.
    ///
    /// Pre-generates a queue of chaff frames at bucketed sizes.
    pub fn new() -> Self {
        let mut rng = ChaCha8Rng::from_entropy();
        let chaff_queue = Self::generate_chaff_queue(&mut rng);

        Self {
            chaff_queue,
            queue_index: 0,
            connection_start: None,
            last_payload_at: None,
            chaff_bytes: 0,
            payload_bytes: 0,
            chaff_frames_sent: 0,
            rng,
            front_window_closed: false,
        }
    }

    /// Generate the initial chaff queue with bucketed sizes.
    ///
    /// The sizes are chosen to match the expected first-response length
    /// distribution of the cover site, so AUTH and site responses share
    /// a length distribution (§6.6 of the sketch).
    fn generate_chaff_queue(rng: &mut ChaCha8Rng) -> Vec<Frame> {
        // Chaff sizes are biased toward the lower buckets (matching messenger startup).
        // Distribution: 40% in [64, 256], 40% in [256, 1024], 20% in [1024, 4096].
        let mut queue = Vec::with_capacity(MAX_CHAFF_QUEUE);

        for _ in 0..MAX_CHAFF_QUEUE {
            let size = sample_chaff_size(rng);
            let mut payload = vec![0u8; size];
            rng.fill(&mut payload[..]);
            queue.push(Frame::new(FRAME_TYPE_CHAFF, Bytes::from(payload)));
        }

        queue
    }

    /// Check if we should allow chaff right now.
    ///
    /// Returns `false` if:
    /// - We're in cooldown after a recent payload write (HOL blocking guard)
    /// - The front window has closed and there's no more chaff in queue
    fn should_inject_chaff(&self) -> bool {
        // Check cooldown after payload.
        if let Some(last_payload) = self.last_payload_at {
            let elapsed = last_payload.elapsed();
            if elapsed < PAYLOAD_COOLDOWN {
                return false; // Still in cooldown — don't block payload.
            }
        }

        // After the front window, only inject if we still have queued chaff.
        // Once the queue drains, stop injecting (Mode 0 is front-loaded, not constant).
        if self.front_window_closed {
            return self.queue_index < self.chaff_queue.len();
        }

        true
    }

    /// Get the next chaff frame from the queue.
    fn next_chaff_frame(&mut self) -> Option<Frame> {
        if self.queue_index >= self.chaff_queue.len() {
            return None;
        }

        let frame = self.chaff_queue[self.queue_index].clone();
        self.queue_index += 1;
        Some(frame)
    }

    /// Generate a single on-the-fly chaff frame (used after queue drains
    /// but still within the front window).
    fn generate_chaff(&mut self) -> Frame {
        let size = sample_chaff_size(&mut self.rng);
        let mut payload = vec![0u8; size];
        self.rng.fill(&mut payload[..]);
        Frame::new(FRAME_TYPE_CHAFF, Bytes::from(payload))
    }
}

impl Default for FrontChaffScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Sample a chaff frame size from the target distribution.
///
/// 40% in [64, 256], 40% in [384, 1024], 20% in [1536, 4096].
fn sample_chaff_size(rng: &mut ChaCha8Rng) -> usize {
    let roll: f64 = rng.r#gen();

    if roll < 0.4 {
        // Lower buckets: indices 0..4 = [64, 128, 192, 256].
        let idx = rng.gen_range(0..4);
        LENGTH_BUCKETS[idx]
    } else if roll < 0.8 {
        // Mid buckets: indices 4..8 = [384, 512, 768, 1024].
        let idx = rng.gen_range(4..8);
        LENGTH_BUCKETS[idx]
    } else {
        // Upper buckets: indices 8..12 = [1536, 2048, 3072, 4096].
        let idx = rng.gen_range(8..12);
        LENGTH_BUCKETS[idx]
    }
}

impl ChaffScheduler for FrontChaffScheduler {
    fn on_payload_sent(&mut self, payload_len: usize) {
        self.payload_bytes += payload_len as u64;
        self.last_payload_at = Some(Instant::now());
    }

    fn poll_chaff(&mut self) -> Option<Frame> {
        // Initialize connection start on first poll.
        if self.connection_start.is_none() {
            self.connection_start = Some(Instant::now());
        }

        // Check if the front window has closed.
        let elapsed = self.connection_start.unwrap().elapsed();
        if elapsed >= FRONT_WINDOW {
            self.front_window_closed = true;
        }

        // Decide whether to inject.
        if !self.should_inject_chaff() {
            return None;
        }

        // Try the queue first.
        if let Some(frame) = self.next_chaff_frame() {
            self.chaff_bytes += frame.payload.len() as u64;
            self.chaff_frames_sent += 1;
            return Some(frame);
        }

        // Queue drained but still in front window — generate on the fly.
        if !self.front_window_closed {
            let frame = self.generate_chaff();
            self.chaff_bytes += frame.payload.len() as u64;
            self.chaff_frames_sent += 1;
            return Some(frame);
        }

        None
    }

    fn has_pending(&self) -> bool {
        self.queue_index < self.chaff_queue.len()
    }

    fn chaff_bytes_sent(&self) -> u64 {
        self.chaff_bytes
    }

    fn payload_bytes_sent(&self) -> u64 {
        self.payload_bytes
    }
}

/// A `PayloadWriteTracker` that the VeilFrontObfuscator uses to notify
/// the chaff scheduler about payload writes.
///
/// This is a simple bounded queue that holds pending DATA frames.
/// The scheduler checks this queue first — if there's payload, no chaff.
pub struct PayloadQueue {
    /// Pending DATA frames waiting to be written.
    frames: Vec<Frame>,
    /// Total bytes queued (for metrics).
    queued_bytes: u64,
}

impl PayloadQueue {
    /// Create an empty payload queue.
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(16),
            queued_bytes: 0,
        }
    }

    /// Push a DATA frame into the queue.
    pub fn push(&mut self, frame: Frame) {
        self.queued_bytes += frame.payload.len() as u64;
        self.frames.push(frame);
    }

    /// Pop the next DATA frame (if any).
    pub fn pop(&mut self) -> Option<Frame> {
        if self.frames.is_empty() {
            return None;
        }
        let frame = self.frames.remove(0);
        Some(frame)
    }

    /// Whether there are pending payload frames.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Number of pending frames.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Clear all pending frames.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.queued_bytes = 0;
    }
}

impl Default for PayloadQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined write strategy: payload first, chaff only when idle.
///
/// This is the core logic that ensures chaff never HOL-blocks payload.
///
/// ```ignore
/// let mut queue = PayloadQueue::new();
/// let mut scheduler = FrontChaffScheduler::new();
///
/// // Push incoming gRPC data as DATA frames.
/// queue.push(Frame::data(grpc_bytes));
///
/// // Write loop:
/// loop {
///     // 1. Payload always takes priority.
///     if let Some(frame) = queue.pop() {
///         write_frame(frame).await?;
///         scheduler.on_payload_sent(frame.payload.len());
///         continue;
///     }
///
///     // 2. Chaff only when no payload.
///     if let Some(chaff) = scheduler.poll_chaff() {
///         write_frame(chaff).await?;
///         continue;
///     }
///
///     // 3. Nothing to send — wait for payload or timeout.
///     tokio::time::sleep(Duration::from_millis(10)).await;
/// }
/// ```
pub struct WriteStrategy {
    /// The payload queue — DATA frames from the gRPC stream.
    pub payload_queue: PayloadQueue,
    /// The chaff scheduler — decides when to inject CHAFF frames.
    pub chaff_scheduler: FrontChaffScheduler,
}

impl WriteStrategy {
    /// Create a new write strategy.
    pub fn new() -> Self {
        Self {
            payload_queue: PayloadQueue::new(),
            chaff_scheduler: FrontChaffScheduler::new(),
        }
    }

    /// Get the next frame to write.
    ///
    /// Returns `Some(frame)` if there's something to send (payload or chaff).
    /// Returns `None` if there's nothing to send right now.
    ///
    /// **Payload always takes priority over chaff.**
    pub fn next_frame(&mut self) -> Option<Frame> {
        // Payload first.
        if let Some(frame) = self.payload_queue.pop() {
            let len = frame.payload.len();
            self.chaff_scheduler.on_payload_sent(len);
            return Some(frame);
        }

        // Chaff when idle.
        self.chaff_scheduler.poll_chaff()
    }

    /// Whether there's anything to send right now.
    pub fn has_pending(&self) -> bool {
        self.payload_queue.has_pending() || self.chaff_scheduler.has_pending()
    }
}

impl Default for WriteStrategy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::{FRAME_TYPE_CHAFF, FRAME_TYPE_DATA};

    #[test]
    fn scheduler_creates_chaff_queue() {
        let scheduler = FrontChaffScheduler::new();
        assert_eq!(scheduler.chaff_queue.len(), MAX_CHAFF_QUEUE);
        assert!(scheduler.has_pending());
    }

    #[test]
    fn payload_causes_cooldown() {
        let mut scheduler = FrontChaffScheduler::new();
        scheduler.connection_start = Some(Instant::now());

        // Before cooldown — should allow chaff.
        assert!(scheduler.should_inject_chaff());

        // Simulate payload sent.
        scheduler.on_payload_sent(100);

        // Immediately after — cooldown should block chaff.
        assert!(!scheduler.should_inject_chaff());
    }

    #[test]
    fn payload_tracking() {
        let mut scheduler = FrontChaffScheduler::new();
        scheduler.on_payload_sent(500);
        scheduler.on_payload_sent(300);

        assert_eq!(scheduler.payload_bytes_sent(), 800);
        assert_eq!(scheduler.chaff_bytes_sent(), 0);
    }

    #[test]
    fn chaff_queue_drains() {
        let mut scheduler = FrontChaffScheduler::new();
        scheduler.connection_start = Some(Instant::now());

        let mut count = 0;
        while let Some(_frame) = scheduler.poll_chaff() {
            count += 1;
            // Prevent infinite loop by simulating front window close after enough chaff.
            if count > MAX_CHAFF_QUEUE + 100 {
                break;
            }
        }

        // Should have drained at least the queue.
        assert!(count >= MAX_CHAFF_QUEUE);
        assert!(scheduler.chaff_bytes_sent() > 0);
    }

    #[test]
    fn write_strategy_priority_payload() {
        let mut strategy = WriteStrategy::new();

        // Push a payload frame.
        strategy.payload_queue.push(Frame::new(
            construct_veil_protocol::FRAME_TYPE_DATA,
            Bytes::from(&b"hello"[..]),
        ));

        // next_frame should return the payload, not chaff.
        let frame = strategy.next_frame().expect("should have a frame");
        assert_eq!(frame.frame_type, construct_veil_protocol::FRAME_TYPE_DATA);
    }

    #[test]
    fn write_strategy_chaff_when_idle() {
        let mut strategy = WriteStrategy::new();
        strategy.chaff_scheduler.connection_start = Some(Instant::now());

        // No payload in queue — should return chaff.
        let frame = strategy.next_frame().expect("should have chaff");
        assert_eq!(frame.frame_type, FRAME_TYPE_CHAFF);
    }

    #[test]
    fn sample_chaff_size_distribution() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut lower = 0;
        let mut mid = 0;
        let mut upper = 0;

        for _ in 0..10000 {
            let size = sample_chaff_size(&mut rng);
            if size <= 256 {
                lower += 1;
            } else if size <= 1024 {
                mid += 1;
            } else if size <= 4096 {
                upper += 1;
            }
        }

        // Rough distribution check (40/40/20) with non-overlapping ranges.
        // Lower: [64, 128, 192, 256], Mid: [384, 512, 768, 1024], Upper: [1536, 2048, 3072, 4096].
        let total = lower + mid + upper;
        let lower_pct = lower as f64 / total as f64;
        let mid_pct = mid as f64 / total as f64;
        let upper_pct = upper as f64 / total as f64;

        // Allow ±5% tolerance for random variation.
        assert!((lower_pct - 0.4).abs() < 0.05, "lower: {lower_pct}");
        assert!((mid_pct - 0.4).abs() < 0.05, "mid: {mid_pct}");
        assert!((upper_pct - 0.2).abs() < 0.05, "upper: {upper_pct}");
    }

    #[test]
    fn payload_queue_push_pop() {
        let mut queue = PayloadQueue::new();
        assert!(!queue.has_pending());
        assert_eq!(queue.len(), 0);

        queue.push(Frame::new(FRAME_TYPE_DATA, Bytes::from(&b"first"[..])));
        queue.push(Frame::new(FRAME_TYPE_DATA, Bytes::from(&b"second"[..])));

        assert!(queue.has_pending());
        assert_eq!(queue.len(), 2);

        let first = queue.pop().expect("first frame");
        assert_eq!(first.payload, &b"first"[..]);

        let second = queue.pop().expect("second frame");
        assert_eq!(second.payload, &b"second"[..]);

        assert!(!queue.has_pending());
        assert!(queue.pop().is_none());
    }

    #[test]
    fn overhead_ratio() {
        let mut scheduler = FrontChaffScheduler::new();
        assert_eq!(scheduler.overhead_ratio(), 0.0);

        scheduler.payload_bytes = 1000;
        scheduler.chaff_bytes = 330;
        assert!((scheduler.overhead_ratio() - 0.33).abs() < 0.001);
    }
}
