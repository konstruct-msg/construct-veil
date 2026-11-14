//! How many tunnels are open at once and how long they live — counts only, no identifiers.
//!
//! Sizing the unlinkable-access mechanism needs both (construct-docs
//! decisions/veil-relay-sees-no-stable-device-id.md §5, todo 311 step 1): the number of tunnels
//! open together is the anonymity set a reconnect after a network change hides in, and the
//! lifetimes say how often a client opens a new one — one token per connection under AUTH v4.
//! Reported in the per-minute `connection summary`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Tunnels open right now.
static OPEN: AtomicU64 = AtomicU64::new(0);
/// The most open at once since the last summary.
static OPEN_PEAK: AtomicU64 = AtomicU64::new(0);
/// Tunnels closed since the last summary, by lifetime: < 1 min, < 10 min, longer.
static CLOSED: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Lifetime bucket edges for [`CLOSED`].
const SHORT: Duration = Duration::from_secs(60);
const MEDIUM: Duration = Duration::from_secs(600);

/// One open tunnel: counted while it lives, its lifetime recorded when dropped.
pub(crate) struct OpenTunnel {
    since: Instant,
}

impl OpenTunnel {
    pub(crate) fn open() -> Self {
        let now_open = OPEN.fetch_add(1, Ordering::Relaxed) + 1;
        OPEN_PEAK.fetch_max(now_open, Ordering::Relaxed);
        Self {
            since: Instant::now(),
        }
    }
}

impl Drop for OpenTunnel {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Ordering::Relaxed);
        CLOSED[bucket(self.since.elapsed())].fetch_add(1, Ordering::Relaxed);
    }
}

/// Which [`CLOSED`] bucket a tunnel that lived `lifetime` falls in.
fn bucket(lifetime: Duration) -> usize {
    if lifetime < SHORT {
        0
    } else if lifetime < MEDIUM {
        1
    } else {
        2
    }
}

/// The window's figures, read for the summary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub open: u64,
    pub open_peak: u64,
    pub closed_lt_1m: u64,
    pub closed_lt_10m: u64,
    pub closed_ge_10m: u64,
}

impl Window {
    /// Nothing was open and nothing closed: an idle relay stays quiet.
    pub(crate) fn is_idle(&self) -> bool {
        [
            self.open_peak,
            self.closed_lt_1m,
            self.closed_lt_10m,
            self.closed_ge_10m,
        ]
        .iter()
        .all(|&n| n == 0)
    }
}

/// Read the window and start the next: the peak restarts from what is open now, the closed
/// counts from zero.
pub(crate) fn take() -> Window {
    let open = OPEN.load(Ordering::Relaxed);
    Window {
        open,
        open_peak: OPEN_PEAK.swap(open, Ordering::Relaxed),
        closed_lt_1m: CLOSED[0].swap(0, Ordering::Relaxed),
        closed_lt_10m: CLOSED[1].swap(0, Ordering::Relaxed),
        closed_ge_10m: CLOSED[2].swap(0, Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetimes_fall_in_their_buckets_at_the_edges() {
        assert_eq!(bucket(Duration::ZERO), 0);
        assert_eq!(bucket(SHORT - Duration::from_millis(1)), 0);
        assert_eq!(bucket(SHORT), 1);
        assert_eq!(bucket(MEDIUM - Duration::from_millis(1)), 1);
        assert_eq!(bucket(MEDIUM), 2);
    }

    /// Any open or closed tunnel makes the window worth a line — each field alone, and two
    /// equal ones together (where an XOR would cancel).
    #[test]
    fn a_window_with_any_tunnel_is_not_idle() {
        let w = |p, a, b, c| Window {
            open: 0,
            open_peak: p,
            closed_lt_1m: a,
            closed_lt_10m: b,
            closed_ge_10m: c,
        };
        assert!(w(0, 0, 0, 0).is_idle());
        for (p, a, b, c) in [
            (1, 0, 0, 0),
            (0, 1, 0, 0),
            (0, 0, 1, 0),
            (0, 0, 0, 1),
            (1, 1, 0, 0),
            (0, 0, 2, 2),
        ] {
            assert!(!w(p, a, b, c).is_idle(), "{p} {a} {b} {c}");
        }
    }

    /// One test for the statics: the counters are process-wide, and a second test touching
    /// them in parallel would race this one.
    #[test]
    fn open_peak_and_closed_follow_the_tunnels() {
        let _ = take();
        let a = OpenTunnel::open();
        let b = OpenTunnel::open();
        let c = OpenTunnel::open();
        drop(b);
        let w = take();
        assert_eq!((w.open, w.open_peak), (2, 3), "two open, three at the peak");
        assert_eq!(
            (w.closed_lt_1m, w.closed_lt_10m, w.closed_ge_10m),
            (1, 0, 0)
        );
        assert!(!w.is_idle());

        // The next window's peak starts from what is still open, not from zero.
        let w = take();
        assert_eq!((w.open, w.open_peak, w.closed_lt_1m), (2, 2, 0));

        drop(a);
        drop(c);
        let w = take();
        assert_eq!((w.open, w.open_peak, w.closed_lt_1m), (0, 2, 2));
        let w = take();
        assert_eq!(
            w,
            Window {
                open: 0,
                open_peak: 0,
                closed_lt_1m: 0,
                closed_lt_10m: 0,
                closed_ge_10m: 0
            }
        );
        assert!(w.is_idle(), "nothing open, nothing closed");
    }
}
