//! Mode 0 — FRONT-style front-loaded chaff + TLS record length bucketing.
//!
//! # Design
//!
//! - How much chaff a connection sends, and when, is **sampled for that connection**: the number
//!   of frames, the window they fall in and each frame's moment. A fixed burst would itself be the
//!   mark of the protocol.
//! - Chaff is front-loaded: moments are Rayleigh-distributed in the window, then nothing.
//! - **Payload always takes priority** — chaff due while there is payload waits.
//! - After each payload write, a **cooldown period** prevents chaff from
//!   head-of-line-blocking the next payload frame.
//! - All frame sizes are **bucketed** to a small set of discrete values.
//!
//! Prior art: FRONT (Gong & Wang, USENIX Security 2020) samples the dummy count and the window per
//! trace and draws moments from a Rayleigh distribution. Ours are smaller — a messenger wakes often
//! and for little — and one-sided. `construct-docs/decisions/veil-chaff-volume-is-sampled-per-connection.md`.
//!
//! Until 2026-11-23 every connection sent one frame per 20 ms of idle for 3 s: ~116 KB up on 129 of
//! 168 measured sessions, whatever it carried — more than the payload of a background wake, and a
//! constant.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;
use construct_veil_protocol::{FRAME_TYPE_CHAFF, Frame};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{ChaffScheduler, LENGTH_BUCKETS};

/// Cooldown duration after a payload write before chaff resumes.
/// This prevents chaff from head-of-line-blocking payload frames.
const PAYLOAD_COOLDOWN: Duration = Duration::from_millis(5);

/// A connection sends this many chaff frames at most; the number is uniform from 0.
const MAX_CHAFF_FRAMES: usize = 32;

/// The window is uniform between these.
const MIN_WINDOW: Duration = Duration::from_secs(1);
const MAX_WINDOW: Duration = Duration::from_secs(4);

/// FRONT-style chaff scheduler.
///
/// Injects chaff frames at the start of the connection, at moments sampled for it.
/// Payload always takes priority — chaff is sent only during idle periods.
pub struct FrontChaffScheduler {
    /// When each frame is due, from the connection's start, in order.
    due: Vec<Duration>,
    /// How many of them were sent.
    sent: usize,
    /// When the connection started (first call to `next_due`).
    connection_start: Option<Instant>,
    /// When the last payload frame was sent.
    last_payload_at: Option<Instant>,
    /// Total chaff bytes sent.
    chaff_bytes: u64,
    /// Total payload bytes sent.
    payload_bytes: u64,
    /// RNG for frame sizes and contents.
    rng: ChaCha8Rng,
}

impl FrontChaffScheduler {
    /// A scheduler with a plan sampled for one connection.
    pub fn new() -> Self {
        Self::from_rng(ChaCha8Rng::from_entropy())
    }

    fn from_rng(mut rng: ChaCha8Rng) -> Self {
        let due = sample_plan(&mut rng);
        Self {
            due,
            sent: 0,
            connection_start: None,
            last_payload_at: None,
            chaff_bytes: 0,
            payload_bytes: 0,
            rng,
        }
    }

    /// Whether this scheduler is finished: every planned frame was sent, so it will never produce
    /// another. A driver may then wait for payload alone, with no timer.
    pub fn is_done(&self) -> bool {
        self.sent >= self.due.len()
    }

    /// How long until the next frame may go: zero when it may go now, `None` when none is left.
    /// The connection starts at the first call.
    pub fn next_due(&mut self, now: Instant) -> Option<Duration> {
        let start = *self.connection_start.get_or_insert(now);
        let due = *self.due.get(self.sent)?;
        let mut at = start + due;
        if let Some(last_payload) = self.last_payload_at {
            at = at.max(last_payload + PAYLOAD_COOLDOWN);
        }
        Some(at.saturating_duration_since(now))
    }
}

impl Default for FrontChaffScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// The moments of one connection's chaff, in order: their number uniform in `0..=MAX_CHAFF_FRAMES`,
/// the window uniform in `MIN_WINDOW..=MAX_WINDOW`, each moment Rayleigh with the scale half the
/// window (its mean at 0.63 of it), and none later than the window.
fn sample_plan(rng: &mut impl Rng) -> Vec<Duration> {
    let count = rng.gen_range(0..=MAX_CHAFF_FRAMES);
    let window = rng.gen_range(MIN_WINDOW.as_secs_f64()..=MAX_WINDOW.as_secs_f64());
    let mut due: Vec<Duration> = (0..count)
        .map(|_| {
            // Inverse transform, cut at the window: `u` stops where the distribution reaches it.
            let reach = 1.0 - (-2.0f64).exp();
            let u = rng.gen_range(0.0..reach);
            Duration::from_secs_f64(window / 2.0 * (-2.0 * (1.0 - u).ln()).sqrt())
        })
        .collect();
    due.sort_unstable();
    due
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
    fn on_payload_sent(&mut self, now: Instant, payload_len: usize) {
        self.payload_bytes += payload_len as u64;
        self.last_payload_at = Some(now);
    }

    fn poll_chaff(&mut self, now: Instant) -> Option<Frame> {
        if self.next_due(now)? > Duration::ZERO {
            return None;
        }
        let size = sample_chaff_size(&mut self.rng);
        let mut payload = vec![0u8; size];
        self.rng.fill(&mut payload[..]);
        self.sent += 1;
        self.chaff_bytes += size as u64;
        Some(Frame::new(FRAME_TYPE_CHAFF, Bytes::from(payload)))
    }

    fn has_pending(&self) -> bool {
        !self.is_done()
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
    frames: VecDeque<Frame>,
    /// Total bytes queued (for metrics).
    queued_bytes: u64,
}

impl PayloadQueue {
    /// Create an empty payload queue.
    pub fn new() -> Self {
        Self {
            frames: VecDeque::with_capacity(16),
            queued_bytes: 0,
        }
    }

    /// Push a DATA frame into the queue.
    pub fn push(&mut self, frame: Frame) {
        self.queued_bytes += frame.payload.len() as u64;
        self.frames.push_back(frame);
    }

    /// Pop the next DATA frame (if any).
    pub fn pop(&mut self) -> Option<Frame> {
        self.frames.pop_front()
    }

    /// Whether there are pending payload frames.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Number of pending frames.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether there are no pending frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
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
    /// **Payload always takes priority over chaff.** `now` is the injected clock
    /// (sans-IO): the strategy reads no system clock, so payload/chaff timing is
    /// deterministic under test. Callers pass `Instant::now()` in production.
    pub fn next_frame(&mut self, now: Instant) -> Option<Frame> {
        // Payload first.
        if let Some(frame) = self.payload_queue.pop() {
            let len = frame.payload.len();
            self.chaff_scheduler.on_payload_sent(now, len);
            return Some(frame);
        }

        // Chaff when idle.
        self.chaff_scheduler.poll_chaff(now)
    }

    /// Whether there's anything to send right now.
    pub fn has_pending(&self) -> bool {
        self.payload_queue.has_pending() || self.chaff_scheduler.has_pending()
    }

    /// How long until something is due without new payload: zero now, `None` never — no payload
    /// queued and the chaff all sent.
    pub fn next_due(&mut self, now: Instant) -> Option<Duration> {
        if self.payload_queue.has_pending() {
            return Some(Duration::ZERO);
        }
        self.chaff_scheduler.next_due(now)
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

    fn seeded(seed: u64) -> FrontChaffScheduler {
        FrontChaffScheduler::from_rng(ChaCha8Rng::seed_from_u64(seed))
    }

    /// What an idle connection sends, polled as a driver does: at each moment asked for.
    fn run_idle(mut s: FrontChaffScheduler) -> (Vec<Duration>, u64) {
        let t0 = Instant::now();
        let mut now = t0;
        let mut at = Vec::new();
        while let Some(wait) = s.next_due(now) {
            now += wait;
            assert!(s.poll_chaff(now).is_some(), "due is due");
            at.push(now - t0);
        }
        assert!(s.is_done() && s.poll_chaff(now).is_none());
        (at, s.chaff_bytes_sent())
    }

    /// The number, the window and the moments differ from one connection to the next, inside their
    /// bounds, over the whole range. Mutations: a fixed count, a fixed window, even spacing.
    #[test]
    fn each_connection_has_its_own_plan() {
        let plans: Vec<Vec<Duration>> = (0..2000).map(|seed| run_idle(seeded(seed)).0).collect();
        let counts: Vec<usize> = plans.iter().map(Vec::len).collect();
        for n in 0..=MAX_CHAFF_FRAMES {
            assert!(counts.contains(&n), "{n} frames never happens");
        }
        assert!(counts.iter().all(|&n| n <= MAX_CHAFF_FRAMES));
        assert!(plans.iter().flatten().all(|&t| t <= MAX_WINDOW));

        let mean = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
        assert!((14.5..17.5).contains(&mean), "mean {mean}");
        // Windows differ: some connections end their chaff within one second, some after three.
        let last: Vec<Duration> = plans
            .iter()
            .filter(|p| p.len() > 20)
            .map(|p| p[p.len() - 1])
            .collect();
        assert!(last.iter().any(|&t| t < Duration::from_millis(1400)));
        assert!(last.iter().any(|&t| t > Duration::from_millis(3200)));
        // Moments are spread, not a rhythm: the gaps of one plan are not equal.
        let full = plans.iter().find(|p| p.len() > 20).unwrap();
        let gaps: Vec<_> = full.windows(2).map(|w| w[1] - w[0]).collect();
        let (min, max) = (gaps.iter().min().unwrap(), gaps.iter().max().unwrap());
        assert!(*max > *min * 5, "{min:?} {max:?}");
    }

    /// Front-loaded: the middle of a long plan falls before the middle of the window. Mutation:
    /// moments uniform in the window reach further.
    #[test]
    fn moments_follow_rayleigh_in_the_window() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut all = Vec::new();
        for _ in 0..4000 {
            let plan = sample_plan(&mut rng);
            all.extend(plan.iter().map(Duration::as_secs_f64));
        }
        let mean = all.iter().sum::<f64>() / all.len() as f64;
        // E[window]=2.5 s; a Rayleigh of scale w/2 cut at w has its mean at 0.53 of w.
        assert!((1.22..1.42).contains(&mean), "{mean}");
        let early = all.iter().filter(|&&t| t < 0.1).count() as f64 / all.len() as f64;
        assert!(early < 0.02, "a Rayleigh starts at zero density: {early}");
    }

    /// What a connection costs on average, and that it is no constant: the point of it.
    #[test]
    fn the_volume_is_small_and_varies() {
        let bytes: Vec<u64> = (0..2000).map(|seed| run_idle(seeded(seed)).1).collect();
        let mean = bytes.iter().sum::<u64>() as f64 / bytes.len() as f64;
        assert!((11_000.0..17_000.0).contains(&mean), "mean {mean}");
        let near_mean = bytes
            .iter()
            .filter(|&&b| (b as f64 - mean).abs() < mean * 0.2)
            .count();
        assert!(
            near_mean < bytes.len() / 4,
            "{near_mean} of {} near the mean",
            bytes.len()
        );
    }

    /// Chaff due during the cooldown after payload waits it out, and is not lost.
    #[test]
    fn payload_causes_cooldown() {
        let t0 = Instant::now();
        let mut s = (0..).map(seeded).find(|s| s.due.len() > 2).unwrap();
        s.connection_start = Some(t0);
        let due = t0 + s.due[0];
        s.on_payload_sent(due, 100);
        assert!(s.has_pending());
        assert_eq!(s.next_due(due), Some(PAYLOAD_COOLDOWN));
        assert!(s.poll_chaff(due).is_none());
        assert!(s.poll_chaff(due + PAYLOAD_COOLDOWN).is_some());
        assert_eq!(s.sent, 1);
    }

    /// Nothing goes before its moment. Mutation: ignore the plan's time.
    #[test]
    fn nothing_goes_before_its_moment() {
        let t0 = Instant::now();
        let mut s = (0..).map(seeded).find(|s| s.due.len() > 2).unwrap();
        assert!(s.poll_chaff(t0).is_none() || s.due[0].is_zero());
        let due = s.due[0];
        assert!(s.poll_chaff(t0 + due - Duration::from_micros(1)).is_none());
        assert!(s.poll_chaff(t0 + due).is_some());
    }

    #[test]
    fn payload_tracking() {
        let now = Instant::now();
        let mut scheduler = FrontChaffScheduler::new();
        scheduler.on_payload_sent(now, 500);
        scheduler.on_payload_sent(now, 300);

        assert_eq!(scheduler.payload_bytes_sent(), 800);
        assert_eq!(scheduler.chaff_bytes_sent(), 0);
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
        let frame = strategy
            .next_frame(Instant::now())
            .expect("should have a frame");
        assert_eq!(frame.frame_type, construct_veil_protocol::FRAME_TYPE_DATA);
    }

    #[test]
    fn write_strategy_chaff_when_idle() {
        let now = Instant::now();
        let mut strategy = WriteStrategy::new();
        strategy.chaff_scheduler = (0..).map(seeded).find(|s| !s.due.is_empty()).unwrap();
        strategy.chaff_scheduler.connection_start = Some(now);

        // No payload in queue — should return chaff at its moment.
        let due = now + strategy.next_due(now).expect("chaff is planned");
        let frame = strategy.next_frame(due).expect("should have chaff");
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
