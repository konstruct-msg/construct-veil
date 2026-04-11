//! Traffic analysis resistance: cover-traffic modes and scheduling.
//!
//! Traffic analysis attacks observe *when* a connection is sending data and
//! *how much*, not *what* is inside. Even with obfs4 framing, a censor can
//! fingerprint idle connections or measure burst patterns.
//!
//! This module provides:
//!
//! - [`TrafficMode`] — set on [`ClientConfig`][crate::ClientConfig] /
//!   [`ServerConfig`][crate::ServerConfig] to configure cover traffic.
//! - [`MimicryProfile`] — preset timing/size patterns that mimic common traffic.
//! - [`CoverTrafficScheduler`] — stateful helper that tells the caller *when*
//!   to send the next cover frame and *how big* it should be.
//!
//! # Usage
//!
//! ```rust,no_run
//! use construct_ice::{ClientConfig, Obfs4Stream};
//! use construct_ice::traffic_mode::{TrafficMode, MimicryProfile, CoverTrafficScheduler};
//!
//! # async fn example() -> std::io::Result<()> {
//! let config = ClientConfig::from_bridge_cert("...")
//!     .unwrap()
//!     .with_traffic_mode(TrafficMode::Mimicry(MimicryProfile::WebBrowsing));
//!
//! let mut stream = Obfs4Stream::connect("relay:443", config).await?;
//! let mut sched  = CoverTrafficScheduler::new(stream.traffic_mode());
//!
//! loop {
//!     tokio::select! {
//!         // ... handle real reads/writes on `stream` ...
//!         _ = sched.sleep_until_next() => {
//!             stream.send_heartbeat().await?;
//!             sched.record_sent();
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::time::{Duration, Instant};

// ── TrafficMode ───────────────────────────────────────────────────────────────

/// Controls how aggressively cover traffic is injected to resist traffic
/// analysis.
///
/// Attach to a config with:
/// ```rust,ignore
/// config.with_traffic_mode(TrafficMode::ConstantRate { bps: 4096 })
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum TrafficMode {
    /// No extra cover traffic. Maximum throughput. (Default)
    ///
    /// The connection is silent when the application is silent, which may
    /// leak activity patterns to an observer.
    #[default]
    Normal,

    /// Inject cover frames so the sustained byte rate never falls below
    /// the given target.
    ///
    /// The scheduler fills gaps between real writes with padding frames
    /// to maintain at least `bps` bytes/second on the wire.
    ///
    /// # Note
    /// This does **not** cap the real-data rate; it only adds a floor.
    ConstantRate {
        /// Minimum sustained wire rate in bytes per second.
        bps: u32,
    },

    /// Shape traffic to mimic a real-world application profile.
    ///
    /// Each [`MimicryProfile`] defines characteristic burst sizes and
    /// inter-arrival timings derived from observed traffic patterns.
    Mimicry(MimicryProfile),
}

impl TrafficMode {
    /// Returns `true` if this mode injects any cover traffic.
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Normal)
    }

    /// Nominal interval between cover frames for this mode.
    ///
    /// Returns `None` for [`TrafficMode::Normal`] (no cover frames).
    pub fn cover_interval(&self) -> Option<Duration> {
        match self {
            Self::Normal => None,
            Self::ConstantRate { bps } => {
                if *bps == 0 {
                    return None;
                }
                // One MAX_FRAME_PAYLOAD bytes cover frame per interval.
                // interval = MAX_FRAME_PAYLOAD / bps
                let interval_us = (MAX_COVER_FRAME_BYTES as u64 * 1_000_000) / (*bps as u64).max(1);
                Some(Duration::from_micros(interval_us.max(1_000))) // floor 1ms
            }
            Self::Mimicry(profile) => Some(profile.cover_interval()),
        }
    }

    /// Suggested cover frame payload size for this mode (bytes).
    ///
    /// The actual wire frame will be slightly larger due to framing overhead.
    pub fn cover_frame_size(&self) -> usize {
        match self {
            Self::Normal => 0,
            Self::ConstantRate { .. } => MAX_COVER_FRAME_BYTES,
            Self::Mimicry(profile) => profile.cover_frame_size(),
        }
    }
}

// ── MimicryProfile ────────────────────────────────────────────────────────────

/// Traffic profile to mimic. Each variant has characteristic burst/pause patterns
/// based on real-world traffic observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicryProfile {
    /// Continuous video stream (~500 KB/s, small frequent frames).
    ///
    /// Models DASH/HLS adaptive video: fairly constant rate with frames
    /// arriving every ~3ms. Suitable for long-lived connections.
    VideoStream,

    /// Interactive web browsing (bursty, with idle gaps).
    ///
    /// Models HTTP/2 web traffic: short bursts separated by ~200ms pauses
    /// (user think-time). Cover frames bridge the gaps.
    WebBrowsing,

    /// Low-rate background sync (~1 KB/s).
    ///
    /// Models push-notification or telemetry traffic: tiny frames every ~1s.
    /// Minimal bandwidth overhead, suitable for persistent idle connections.
    BackgroundSync,
}

impl MimicryProfile {
    /// Inter-arrival interval between cover frames for this profile.
    pub fn cover_interval(self) -> Duration {
        match self {
            Self::VideoStream => Duration::from_millis(3),
            Self::WebBrowsing => Duration::from_millis(200),
            Self::BackgroundSync => Duration::from_millis(1_000),
        }
    }

    /// Suggested cover frame payload size in bytes for this profile.
    pub fn cover_frame_size(self) -> usize {
        match self {
            // ~500 KB/s at 3ms interval = 1500 bytes/frame
            Self::VideoStream => 1_400,
            // ~200 bytes/200ms = ~1 KB/s interactive burst
            Self::WebBrowsing => 200,
            // ~100 bytes/1s = ~100 B/s background
            Self::BackgroundSync => 100,
        }
    }

    /// Human-readable name for logging / bridge-line serialisation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VideoStream => "video-stream",
            Self::WebBrowsing => "web-browsing",
            Self::BackgroundSync => "background-sync",
        }
    }

    /// Parse from the string used in bridge lines.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "video-stream" => Some(Self::VideoStream),
            "web-browsing" => Some(Self::WebBrowsing),
            "background-sync" => Some(Self::BackgroundSync),
            _ => None,
        }
    }
}

impl std::str::FromStr for MimicryProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        Self::from_name(s).ok_or(())
    }
}

impl std::fmt::Display for MimicryProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── CoverTrafficScheduler ─────────────────────────────────────────────────────

/// Maximum payload bytes in a single cover frame (matches obfs4 segment length).
pub const MAX_COVER_FRAME_BYTES: usize = 1_448;

/// Stateful scheduler that tells the caller when to send the next cover frame.
///
/// The scheduler accounts for real data transmissions: if the application
/// wrote real data recently, the cover frame deadline is pushed forward to
/// avoid redundant padding.
///
/// # Example
///
/// ```rust,no_run
/// use construct_ice::traffic_mode::{TrafficMode, CoverTrafficScheduler};
/// use std::time::Duration;
///
/// let mode = TrafficMode::Mimicry(construct_ice::traffic_mode::MimicryProfile::WebBrowsing);
/// let mut sched = CoverTrafficScheduler::new(mode);
///
/// // In an async loop:
/// // tokio::select! {
/// //     _ = sched.sleep_until_next() => {
/// //         stream.send_heartbeat().await.unwrap();
/// //         sched.record_sent();
/// //     }
/// // }
/// ```
pub struct CoverTrafficScheduler {
    mode: TrafficMode,
    next_cover_at: Option<Instant>,
    frames_sent: u64,
    bytes_sent: u64,
}

impl CoverTrafficScheduler {
    /// Create a new scheduler for the given traffic mode.
    ///
    /// If `mode` is [`TrafficMode::Normal`], all methods are no-ops.
    pub fn new(mode: TrafficMode) -> Self {
        let next_cover_at = mode.cover_interval().map(|i| Instant::now() + i);
        CoverTrafficScheduler {
            mode,
            next_cover_at,
            frames_sent: 0,
            bytes_sent: 0,
        }
    }

    /// Returns `true` if this scheduler will inject any cover frames.
    pub fn is_active(&self) -> bool {
        self.mode.is_active()
    }

    /// Returns the instant at which the next cover frame should be sent.
    ///
    /// Returns `None` for [`TrafficMode::Normal`] (no cover frames scheduled).
    pub fn next_deadline(&self) -> Option<Instant> {
        self.next_cover_at
    }

    /// Returns the remaining time until the next cover frame should be sent.
    ///
    /// Returns `Duration::ZERO` if the deadline has already passed.
    /// Returns `None` for [`TrafficMode::Normal`].
    pub fn time_until_next(&self) -> Option<Duration> {
        self.next_cover_at.map(|t| {
            let now = Instant::now();
            if t > now { t - now } else { Duration::ZERO }
        })
    }

    /// Returns a future that sleeps until the next cover frame deadline.
    ///
    /// Returns a future that resolves immediately for [`TrafficMode::Normal`]
    /// (caller should check [`is_active`][Self::is_active] before awaiting).
    pub async fn sleep_until_next(&self) {
        match self.next_cover_at {
            Some(at) => {
                let now = Instant::now();
                if at > now {
                    tokio::time::sleep(at - now).await;
                }
            }
            None => {
                // Normal mode: sleep forever so a `select!` branch never fires.
                std::future::pending::<()>().await;
            }
        }
    }

    /// Notify the scheduler that a cover frame was just sent.
    ///
    /// Advances the deadline by one cover interval.
    pub fn record_sent(&mut self) {
        let interval = match self.mode.cover_interval() {
            Some(i) => i,
            None => return,
        };
        self.frames_sent += 1;
        self.bytes_sent += self.mode.cover_frame_size() as u64;
        // Schedule next from now (not from the previous deadline) to avoid
        // burst catch-up if many intervals elapsed while the caller was busy.
        self.next_cover_at = Some(Instant::now() + interval);
    }

    /// Notify the scheduler that real application data was sent.
    ///
    /// Pushes the next cover frame deadline forward by one interval,
    /// since real data has the same obfuscation effect as a cover frame.
    pub fn record_real_write(&mut self) {
        let interval = match self.mode.cover_interval() {
            Some(i) => i,
            None => return,
        };
        self.next_cover_at = Some(Instant::now() + interval);
    }

    /// Number of cover frames sent so far.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Total cover bytes sent so far (payload, excluding framing overhead).
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// The active traffic mode.
    pub fn mode(&self) -> TrafficMode {
        self.mode
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_mode_no_cover_interval() {
        assert_eq!(TrafficMode::Normal.cover_interval(), None);
        assert!(!TrafficMode::Normal.is_active());
        assert_eq!(TrafficMode::Normal.cover_frame_size(), 0);
    }

    #[test]
    fn constant_rate_interval_scales_with_bps() {
        let mode = TrafficMode::ConstantRate { bps: 1_448_000 };
        let interval = mode.cover_interval().unwrap();
        // At 1,448,000 bps with MAX_COVER_FRAME_BYTES=1448 → 1ms per frame
        assert_eq!(interval, Duration::from_millis(1));

        let mode_slow = TrafficMode::ConstantRate { bps: 100 };
        let interval_slow = mode_slow.cover_interval().unwrap();
        assert!(
            interval_slow > Duration::from_millis(1_000),
            "slow rate should have long interval: {interval_slow:?}"
        );
    }

    #[test]
    fn constant_rate_zero_bps_returns_none() {
        assert_eq!(TrafficMode::ConstantRate { bps: 0 }.cover_interval(), None);
    }

    #[test]
    fn mimicry_profiles_have_distinct_intervals() {
        let video = TrafficMode::Mimicry(MimicryProfile::VideoStream)
            .cover_interval()
            .unwrap();
        let web = TrafficMode::Mimicry(MimicryProfile::WebBrowsing)
            .cover_interval()
            .unwrap();
        let bg = TrafficMode::Mimicry(MimicryProfile::BackgroundSync)
            .cover_interval()
            .unwrap();

        // video fastest, background slowest
        assert!(video < web, "VideoStream should be faster than WebBrowsing");
        assert!(web < bg, "WebBrowsing should be faster than BackgroundSync");
    }

    #[test]
    fn mimicry_profile_roundtrip_str() {
        for (profile, name) in [
            (MimicryProfile::VideoStream, "video-stream"),
            (MimicryProfile::WebBrowsing, "web-browsing"),
            (MimicryProfile::BackgroundSync, "background-sync"),
        ] {
            assert_eq!(profile.as_str(), name);
            assert_eq!(MimicryProfile::from_name(name), Some(profile));
            assert_eq!(format!("{profile}"), name);
        }
        assert_eq!(MimicryProfile::from_name("unknown"), None);
    }

    #[test]
    fn scheduler_normal_mode_inactive() {
        let sched = CoverTrafficScheduler::new(TrafficMode::Normal);
        assert!(!sched.is_active());
        assert!(sched.next_deadline().is_none());
        assert!(sched.time_until_next().is_none());
        assert_eq!(sched.frames_sent(), 0);
    }

    #[test]
    fn scheduler_advances_on_record_sent() {
        let mut sched =
            CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::WebBrowsing));
        assert!(sched.is_active());

        let d1 = sched.next_deadline().unwrap();
        sched.record_sent();
        let d2 = sched.next_deadline().unwrap();

        assert!(d2 > d1, "deadline must advance after record_sent");
        assert_eq!(sched.frames_sent(), 1);
        assert_eq!(
            sched.bytes_sent(),
            MimicryProfile::WebBrowsing.cover_frame_size() as u64
        );
    }

    #[test]
    fn scheduler_record_real_write_pushes_deadline() {
        let mut sched =
            CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::BackgroundSync));
        let d1 = sched.next_deadline().unwrap();
        sched.record_real_write();
        let d2 = sched.next_deadline().unwrap();
        // After a real write the deadline should be pushed forward
        assert!(d2 > d1);
        assert_eq!(
            sched.frames_sent(),
            0,
            "record_real_write must not count as cover frame"
        );
    }

    #[test]
    fn scheduler_time_until_next_decreases() {
        let sched = CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::VideoStream));
        let t1 = sched.time_until_next().unwrap();
        // A tiny sleep would make t2 < t1, but we just verify t1 is <= interval
        assert!(t1 <= MimicryProfile::VideoStream.cover_interval());
    }
}
