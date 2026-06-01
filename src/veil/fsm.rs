//! Pure FSM — states, events, effects, and the reducer.
//!
//! The FSM is a **pure function**: `(state, event, scores, config, now) → (state, effects)`.
//! No I/O, no tokio::spawn, no file access. Fully unit-testable.

#![allow(missing_docs)]

use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
};

// ── Method identification ────────────────────────────────────────────────────

/// Unique identifier for an obfuscation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodId {
    /// obfs4 — TLS/obfuscated TCP to relay bridge.
    Obfs4 = 0,
    /// WebTunnel — HTTP/2 + WebSocket Upgrade on :443.
    WebTunnel = 1,
    /// Masque — HTTP/3 DATAGRAM (future).
    Masque = 2,
    /// VeilFront — honest-front HTTPS relay with session-bound ticket auth.
    /// Client opens standard TLS 1.3, sends auth record in first application data.
    /// Relay routes to tunnel (valid ticket) or real site (everything else).
    VeilFront = 3,
}

impl MethodId {
    /// All known methods, in priority order for scoring.
    pub fn all() -> &'static [Self] {
        &[Self::Obfs4, Self::WebTunnel, Self::Masque, Self::VeilFront]
    }

    /// Convert to the bitmask bit position.
    pub fn bit(&self) -> u32 {
        *self as u32
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Obfs4 => "obfs4",
            Self::WebTunnel => "webtunnel",
            Self::Masque => "masque",
            Self::VeilFront => "veil-front",
        }
    }
}

impl std::fmt::Display for MethodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── Network fingerprint ──────────────────────────────────────────────────────

/// Opaque network identifier used as the key for per-network scoring.
///
/// Computed by the caller (Swift/Kotlin) from SSID, BSSID, carrier info, etc.
/// ICE treats this as opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkFingerprint {
    bytes: Vec<u8>,
}

impl NetworkFingerprint {
    /// Create from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Short hex display (first 4 bytes).
    pub fn short_hex(&self) -> String {
        self.bytes
            .iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

impl Default for NetworkFingerprint {
    /// Default fingerprint used when caller doesn't provide one.
    fn default() -> Self {
        Self { bytes: vec![0; 16] }
    }
}

// ── Scoring outcomes ─────────────────────────────────────────────────────────

/// Outcome recorded in persistent scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreOutcome {
    /// Probe succeeded.
    Success { latency_ms: u32 },
    /// Probe failed.
    Failure { reason: ProbeFailureReason },
}

// ── Failure classification ───────────────────────────────────────────────────

/// Why a probe or transport connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailureReason {
    /// TLS handshake_failure / alert 40 — method blocked by DPI.
    FingerprintBlocked,
    /// Non-101 on WebSocket upgrade — WebTunnel choked by transparent proxy.
    WebTunnelDecoyResponse,
    /// Certificate expired or verification failed.
    TlsCertProblem,
    /// Connection refused / timeout — network issue.
    ConnectionFailed,
    /// Handshake completed but no payload arrived within timeout.
    Timeout,
    /// Unknown / uncategorized failure.
    Unknown,
}

/// Why the active transport degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailureKind {
    /// TLS handshake_failure / alert 40. Method blocked by DPI.
    FingerprintBlocked,
    /// HTTP non-101 on WebSocket upgrade. WebTunnel choked by transparent proxy.
    WebTunnelDecoyResponse,
    /// Cert expired / verify failed.
    TlsCertProblem,
    /// Stream timeout — traffic not flowing.
    StreamTimeout,
    /// Unknown — degradation counter, but not hard-fail.
    Unknown,
}

// ── FSM states ───────────────────────────────────────────────────────────────

/// Probe attempt tracking within Probing state.
#[derive(Debug, Clone)]
pub struct ProbeAttempt {
    /// When this probe was started.
    pub started_at: Instant,
}

/// The current state of the ICE session FSM.
#[derive(Debug, Clone)]
pub enum VeilState {
    /// Not running. Waiting for a Start event.
    Idle,

    /// Probing top-K obfuscators in parallel.
    Probing {
        /// Methods currently being probed.
        candidates: Vec<MethodId>,
        /// Track when each probe started.
        attempts: HashMap<MethodId, ProbeAttempt>,
        /// When probing began.
        started_at: Instant,
    },

    /// One obfuscator won the probe race. Active connection.
    Active {
        method: MethodId,
        port: u16,
        started_at: Instant,
        consecutive_failures: u8,
    },

    /// Active but experiencing transport errors.
    /// Rotates to probing when `consecutive_failures >= degraded_threshold`.
    Degraded {
        method: MethodId,
        port: u16,
        consecutive_failures: u8,
    },

    /// All probes failed. Waiting before retry.
    Cooldown { until: Instant },
}

impl VeilState {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Probing { .. } => "probing",
            Self::Active { .. } => "active",
            Self::Degraded { .. } => "degraded",
            Self::Cooldown { .. } => "cooldown",
        }
    }
}

// ── FSM events ───────────────────────────────────────────────────────────────

/// Events that drive the FSM transitions.
#[derive(Debug, Clone)]
pub enum VeilEvent {
    /// Caller requests ICE to start.
    Start {
        relay: String,
        bundle: String,
        fingerprint: NetworkFingerprint,
        allowed_methods: MethodSet,
    },

    /// Caller requests ICE to stop.
    Stop,

    /// A probe succeeded with the given latency.
    ProbeSucceeded {
        method: MethodId,
        port: u16,
        latency_ms: u32,
    },

    /// A probe failed.
    ProbeFailed {
        method: MethodId,
        reason: ProbeFailureReason,
    },

    /// All parallel probes failed without success.
    AllProbesFailed,

    /// Transport failure reported by caller (e.g. RPC timeout, TLS reset).
    TransportFailure { kind: TransportFailureKind },

    /// Cooldown timer elapsed.
    CooldownElapsed,
}

// ── FSM effects ──────────────────────────────────────────────────────────────

/// Effects emitted by the FSM. The caller / ProbeOrchestrator executes them.
#[derive(Debug, Clone)]
pub enum VeilEffect {
    /// Start parallel probes for the given methods.
    StartProbes {
        methods: Vec<MethodId>,
        relay: String,
        bundle: String,
    },

    /// Cancel all probes except the winner.
    CancelOtherProbes { winner: MethodId },

    /// Shut down the currently active method entirely.
    StopActive,

    /// Schedule a CooldownElapsed event after the given duration.
    ScheduleCooldown { duration: Duration },

    /// Record a score outcome for a method on a specific network.
    RecordScore {
        method: MethodId,
        fingerprint: NetworkFingerprint,
        outcome: ScoreOutcome,
    },
}

// ── Method set (allowed methods bitmask) ─────────────────────────────────────

/// Bitmask of allowed obfuscation methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSet(pub u32);

impl MethodSet {
    /// All methods enabled (bitmask = 0 per spec convention).
    pub fn all() -> Self {
        Self(0)
    }

    /// Empty set — no methods allowed.
    pub fn none() -> Self {
        Self(u32::MAX) // using MAX as "none" since 0 = all
    }

    /// Create from a bitmask where bit N = MethodId(N).
    /// A bit value of 0 means enabled, 1 means disabled.
    /// This matches the spec: `allowed_methods: u32, 0 = all enabled`.
    pub fn from_bitmask(bits: u32) -> Self {
        Self(bits)
    }

    /// Check if a method is allowed.
    pub fn contains(&self, method: MethodId) -> bool {
        // 0 = all enabled, so if bitmask is 0, everything is allowed.
        if self.0 == 0 {
            return true;
        }
        // If the bit for this method is set (1), it's disabled.
        (self.0 & method.bit()) == 0
    }

    /// Iterate over all allowed methods.
    pub fn iter_allowed(&self) -> impl Iterator<Item = MethodId> {
        MethodId::all()
            .iter()
            .copied()
            .filter(|m| self.contains(*m))
    }
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Fully parameterizable VEIL configuration.
#[derive(Debug, Clone)]
pub struct VeilConfig {
    /// How many obfuscators to probe in parallel.
    pub top_k_probes: usize,
    /// Delay between probe starts (happy-eyeballs stagger).
    pub inter_probe_delay: Duration,
    /// Hard timeout per probe.
    pub probe_timeout: Duration,
    /// Transport failures in Degraded before rotation.
    pub degraded_threshold: u8,
    /// Cooldown duration after all probes fail.
    pub cooldown_duration: Duration,
    /// TTL for permanently_blocked entries.
    pub block_ttl: Duration,
    /// Max fingerprints in PersistentScores.
    pub max_fingerprints: usize,
}

impl Default for VeilConfig {
    fn default() -> Self {
        Self {
            top_k_probes: 2,
            inter_probe_delay: Duration::from_millis(150),
            probe_timeout: Duration::from_secs(8),
            degraded_threshold: 2,
            cooldown_duration: Duration::from_secs(30),
            block_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
            max_fingerprints: 50,
        }
    }
}

impl VeilConfig {
    /// Config that probes sequentially (top_k=1) — legacy fallback behaviour.
    pub fn legacy() -> Self {
        Self {
            top_k_probes: 1,
            ..Self::default()
        }
    }
}

// ── Scoring: select probe candidates ─────────────────────────────────────────

/// Trait for accessing scores from the FSM (decoupled from SQLite).
pub trait ScoreLookup {
    /// Get score for a (fingerprint, method) pair. Returns None if no data.
    fn get(&self, fingerprint: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry>;

    /// Check if a method is permanently blocked on this network.
    fn is_permanently_blocked(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
        block_ttl: Duration,
        now: SystemTime,
    ) -> bool;
}

/// A score entry for scoring computation.
#[derive(Debug, Clone, Default)]
pub struct ScoreEntry {
    pub successes: u32,
    pub failures: u32,
    pub last_success_at: Option<SystemTime>,
    pub last_failure_at: Option<SystemTime>,
    pub median_latency_ms: u32,
    pub blocked_at: Option<SystemTime>,
    pub consecutive_failures: u8,
}

/// Select top-K probe candidates based on scores.
pub fn select_probe_candidates(
    fingerprint: &NetworkFingerprint,
    allowed: MethodSet,
    scores: &dyn ScoreLookup,
    cfg: &VeilConfig,
    now: SystemTime,
) -> Vec<MethodId> {
    let mut scored: Vec<(MethodId, f64)> = Vec::new();

    for method in allowed.iter_allowed() {
        // Skip permanently blocked methods (unless everything is blocked).
        if scores.is_permanently_blocked(fingerprint, method, cfg.block_ttl, now) {
            continue;
        }

        let score = compute_score(scores, fingerprint, method, now);
        scored.push((method, score));
    }

    // Sort by score descending.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take top-K.
    let top_k = cfg.top_k_probes.min(scored.len());
    let mut candidates: Vec<MethodId> = scored.iter().take(top_k).map(|(m, _)| *m).collect();

    // If zero candidates (everything blocked), try the least-recently-blocked method.
    if candidates.is_empty() {
        let mut blocked_methods: Vec<(MethodId, Option<SystemTime>)> = allowed
            .iter_allowed()
            .filter_map(|m| {
                let entry = scores.get(fingerprint, m);
                entry.and_then(|e| e.blocked_at.map(|t| (m, Some(t))))
            })
            .collect();
        blocked_methods.sort_by_key(|&(_, t)| t);
        if let Some((m, _)) = blocked_methods.first() {
            candidates.push(*m);
        } else {
            // Fallback: allow any method from the allowed set.
            if let Some(first) = allowed.iter_allowed().next() {
                candidates.push(first);
            }
        }
    }

    candidates
}

/// Compute score for a (fingerprint, method) pair.
///
/// score = base_quality − recent_failure_penalty − latency_penalty + recency_bonus
fn compute_score(
    scores: &dyn ScoreLookup,
    fingerprint: &NetworkFingerprint,
    method: MethodId,
    now: SystemTime,
) -> f64 {
    let entry = match scores.get(fingerprint, method) {
        Some(e) => e,
        None => return 50.0, // base_quality for new method (no data)
    };

    let total = entry.successes as f64 + entry.failures as f64;
    if total == 0.0 {
        return 50.0; // No data yet
    }

    // base_quality: EWMA-style success rate mapped to [0, 100]
    let base_quality = (entry.successes as f64 / total) * 100.0;

    // recent_failure_penalty: -20 per failure in last 5 minutes, linear decay over 1 hour
    let recent_failure_penalty = compute_recent_failure_penalty(&entry, now);

    // latency_penalty: min(20, (median_latency_ms - 1000) / 100)
    let latency_penalty = if entry.median_latency_ms > 1000 {
        ((entry.median_latency_ms as f64 - 1000.0) / 100.0).min(20.0)
    } else {
        0.0
    };

    // recency_bonus: +5 if last success < 1 hour ago
    let recency_bonus = entry
        .last_success_at
        .and_then(|t| now.duration_since(t).ok())
        .map(|d| {
            if d < Duration::from_secs(3600) {
                5.0
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    base_quality - recent_failure_penalty - latency_penalty + recency_bonus
}

/// Compute recent failure penalty.
/// Each failure in last 5 minutes = -20, decays linearly over 1 hour.
fn compute_recent_failure_penalty(entry: &ScoreEntry, now: SystemTime) -> f64 {
    let last_failure = match entry.last_failure_at {
        Some(t) => t,
        None => return 0.0,
    };

    let elapsed = match now.duration_since(last_failure) {
        Ok(d) => d,
        Err(_) => return 0.0, // future timestamp — ignore
    };

    let five_minutes = Duration::from_secs(300);
    let one_hour = Duration::from_secs(3600);

    if elapsed > one_hour {
        return 0.0;
    }

    if elapsed <= five_minutes {
        // Each recent failure = -20
        // We don't track individual failures, so use consecutive_failures as proxy
        (entry.consecutive_failures as f64) * 20.0
    } else {
        // Linear decay from 5 min to 1 hour
        let decay = 1.0 - (elapsed.as_secs_f64() - 300.0) / (3600.0 - 300.0);
        (entry.consecutive_failures as f64) * 20.0 * decay.max(0.0)
    }
}

// ── The reducer (pure) ──────────────────────────────────────────────────────

/// The FSM reducer: `(state, event, scores, config, now) → (state, effects)`.
///
/// Pure function — no I/O, no side effects.
#[allow(clippy::too_many_lines)]
pub fn reduce(
    state: VeilState,
    event: VeilEvent,
    scores: &dyn ScoreLookup,
    cfg: &VeilConfig,
    now: Instant,
    now_sys: SystemTime,
) -> (VeilState, Vec<VeilEffect>) {
    match (&state, event) {
        // ── Idle ─────────────────────────────────────────────────────────
        (
            VeilState::Idle,
            VeilEvent::Start {
                relay,
                bundle,
                ref fingerprint,
                allowed_methods,
            },
        ) => {
            let candidates =
                select_probe_candidates(fingerprint, allowed_methods, scores, cfg, now_sys);

            let attempts: HashMap<MethodId, ProbeAttempt> = candidates
                .iter()
                .map(|m| (*m, ProbeAttempt { started_at: now }))
                .collect();

            let new_state = VeilState::Probing {
                candidates: candidates.clone(),
                attempts,
                started_at: now,
            };

            let effects = vec![VeilEffect::StartProbes {
                methods: candidates,
                relay,
                bundle,
            }];

            (new_state, effects)
        }

        (VeilState::Idle, VeilEvent::Stop) => (VeilState::Idle, vec![]),

        (VeilState::Idle, _) => {
            // Ignore all other events in Idle.
            (state, vec![])
        }

        // ── Probing ──────────────────────────────────────────────────────
        (
            VeilState::Probing {
                candidates,
                attempts: _,
                started_at: _,
            },
            VeilEvent::ProbeSucceeded {
                method,
                port,
                latency_ms,
            },
        ) => {
            if !candidates.contains(&method) {
                // Probe from a different session — ignore.
                return (state, vec![]);
            }

            let new_state = VeilState::Active {
                method,
                port,
                started_at: now,
                consecutive_failures: 0,
            };

            let mut effects = vec![VeilEffect::CancelOtherProbes { winner: method }];

            // We don't have the fingerprint here — the effect will be enriched
            // by the orchestrator who knows the current fingerprint.
            // The RecordScore effect is emitted without fingerprint info;
            // the caller fills it in.
            effects.push(VeilEffect::RecordScore {
                method,
                fingerprint: NetworkFingerprint::default(), // placeholder — caller fills
                outcome: ScoreOutcome::Success { latency_ms },
            });

            (new_state, effects)
        }

        (
            VeilState::Probing {
                candidates,
                attempts,
                started_at,
            },
            VeilEvent::ProbeFailed { method, reason },
        ) => {
            if !candidates.contains(&method) {
                return (state, vec![]);
            }

            // Remove this method from candidates.
            let new_candidates: Vec<MethodId> = candidates
                .iter()
                .filter(|&&m| m != method)
                .copied()
                .collect();

            if new_candidates.is_empty() {
                // All probes failed.
                let until = now + cfg.cooldown_duration;
                let new_state = VeilState::Cooldown { until };
                let effects = vec![VeilEffect::ScheduleCooldown {
                    duration: cfg.cooldown_duration,
                }];
                return (new_state, effects);
            }

            // Still have live candidates.
            let mut new_attempts = attempts.clone();
            new_attempts.remove(&method);

            let new_state = VeilState::Probing {
                candidates: new_candidates,
                attempts: new_attempts,
                started_at: *started_at,
            };

            let effects = vec![VeilEffect::RecordScore {
                method,
                fingerprint: NetworkFingerprint::default(),
                outcome: ScoreOutcome::Failure { reason },
            }];

            (new_state, effects)
        }

        (
            VeilState::Probing {
                candidates: _,
                attempts: _,
                started_at: _,
            },
            VeilEvent::AllProbesFailed,
        ) => {
            let until = now + cfg.cooldown_duration;
            let new_state = VeilState::Cooldown { until };
            let effects = vec![VeilEffect::ScheduleCooldown {
                duration: cfg.cooldown_duration,
            }];

            (new_state, effects)
        }

        (VeilState::Probing { .. }, VeilEvent::Stop) => {
            let effects = vec![VeilEffect::StopActive];
            (VeilState::Idle, effects)
        }

        (VeilState::Probing { .. }, _) => {
            // Ignore other events.
            (state, vec![])
        }

        // ── Active ───────────────────────────────────────────────────────
        (
            VeilState::Active {
                method,
                port,
                started_at,
                consecutive_failures,
            },
            VeilEvent::TransportFailure { kind },
        ) => {
            match kind {
                TransportFailureKind::FingerprintBlocked
                | TransportFailureKind::WebTunnelDecoyResponse => {
                    // Immediate rotation.
                    let new_state = VeilState::Degraded {
                        method: *method,
                        port: *port,
                        consecutive_failures: u8::MAX, // Force re-probe
                    };
                    (new_state, vec![])
                }
                TransportFailureKind::TlsCertProblem => {
                    // Don't record as method failure — it's a bundle issue.
                    (state, vec![])
                }
                TransportFailureKind::StreamTimeout | TransportFailureKind::Unknown => {
                    let new_fails = consecutive_failures.saturating_add(1);
                    if new_fails >= cfg.degraded_threshold {
                        (
                            VeilState::Degraded {
                                method: *method,
                                port: *port,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    } else {
                        (
                            VeilState::Active {
                                method: *method,
                                port: *port,
                                started_at: *started_at,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    }
                }
            }
        }

        (VeilState::Active { .. }, VeilEvent::Stop) => {
            (VeilState::Idle, vec![VeilEffect::StopActive])
        }

        (VeilState::Active { .. }, _) => {
            // Ignore other events in Active.
            (state, vec![])
        }

        // ── Degraded ─────────────────────────────────────────────────────
        (
            VeilState::Degraded {
                method,
                port,
                consecutive_failures,
            },
            VeilEvent::TransportFailure { kind },
        ) => {
            match kind {
                TransportFailureKind::TlsCertProblem => (state, vec![]),
                _ => {
                    let new_fails = consecutive_failures.saturating_add(1);
                    if *consecutive_failures >= cfg.degraded_threshold {
                        // Threshold already reached — move to probing without current method.
                        let effects = vec![VeilEffect::StopActive];
                        (VeilState::Idle, effects)
                    } else {
                        (
                            VeilState::Degraded {
                                method: *method,
                                port: *port,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    }
                }
            }
        }

        (VeilState::Degraded { .. }, VeilEvent::Stop) => {
            (VeilState::Idle, vec![VeilEffect::StopActive])
        }

        (VeilState::Degraded { .. }, _) => (state, vec![]),

        // ── Cooldown ─────────────────────────────────────────────────────
        (VeilState::Cooldown { until }, VeilEvent::CooldownElapsed) => {
            if now >= *until {
                (VeilState::Idle, vec![])
            } else {
                // Too early — stay in cooldown.
                (state, vec![])
            }
        }

        (VeilState::Cooldown { .. }, VeilEvent::Stop) => (VeilState::Idle, vec![]),

        (VeilState::Cooldown { .. }, _) => {
            // Ignore other events during cooldown.
            (state, vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    fn now_sys() -> SystemTime {
        SystemTime::now()
    }

    /// No-op score lookup for basic tests.
    struct NoScores;
    impl ScoreLookup for NoScores {
        fn get(&self, _fp: &NetworkFingerprint, _method: MethodId) -> Option<ScoreEntry> {
            None
        }
        fn is_permanently_blocked(
            &self,
            _fp: &NetworkFingerprint,
            _method: MethodId,
            _ttl: Duration,
            _now: SystemTime,
        ) -> bool {
            false
        }
    }

    // ── Idle transitions ──────────────────────────────────────────────────

    #[test]
    fn idle_start_goes_to_probing() {
        let state = VeilState::Idle;
        let (new_state, effects) = reduce(
            state,
            VeilEvent::Start {
                relay: "relay:443".into(),
                bundle: "cert=abc".into(),
                fingerprint: NetworkFingerprint::default(),
                allowed_methods: MethodSet::all(),
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Probing { ref candidates, .. } => {
                assert_eq!(candidates.len(), 2); // top_k=2 by default
            }
            _ => panic!("expected Probing, got {:?}", new_state),
        }

        assert_eq!(effects.len(), 1);
        match &effects[0] {
            VeilEffect::StartProbes {
                methods,
                relay,
                bundle,
            } => {
                assert_eq!(relay, "relay:443");
                assert_eq!(bundle, "cert=abc");
                assert_eq!(methods.len(), 2);
            }
            _ => panic!("expected StartProbes effect"),
        }
    }

    #[test]
    fn idle_stop_stays_idle() {
        let (new_state, effects) = reduce(
            VeilState::Idle,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.is_empty());
    }

    // ── Probing transitions ───────────────────────────────────────────────

    #[test]
    fn probing_probe_succeeded_goes_to_active() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::ProbeSucceeded {
                method: MethodId::Obfs4,
                port: 12345,
                latency_ms: 500,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Active { method, port, .. } => {
                assert_eq!(method, MethodId::Obfs4);
                assert_eq!(port, 12345);
            }
            _ => panic!("expected Active, got {:?}", new_state),
        }

        // Should emit CancelOtherProbes + RecordScore
        assert_eq!(effects.len(), 2);
        assert!(
            matches!(&effects[0], VeilEffect::CancelOtherProbes { winner } if *winner == MethodId::Obfs4)
        );
    }

    #[test]
    fn probing_probe_failed_removes_candidate() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates: candidates.clone(),
            attempts,
            started_at: now(),
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::ProbeFailed {
                method: MethodId::WebTunnel,
                reason: ProbeFailureReason::FingerprintBlocked,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Probing { ref candidates, .. } => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0], MethodId::Obfs4);
            }
            _ => panic!("expected Probing, got {:?}", new_state),
        }
    }

    #[test]
    fn probing_last_candidate_failed_goes_to_cooldown() {
        let candidates = vec![MethodId::Obfs4];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::ProbeFailed {
                method: MethodId::Obfs4,
                reason: ProbeFailureReason::ConnectionFailed,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, VeilEffect::ScheduleCooldown { .. }))
        );
    }

    #[test]
    fn probing_all_probes_failed_goes_to_cooldown() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::AllProbesFailed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, VeilEffect::ScheduleCooldown { .. }))
        );
    }

    #[test]
    fn probing_stop_goes_to_idle() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Active transitions ────────────────────────────────────────────────

    #[test]
    fn active_stream_timeout_increments_failures() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, _) = reduce(
            state.clone(),
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Active {
                consecutive_failures,
                ..
            } => {
                assert_eq!(consecutive_failures, 1);
            }
            _ => panic!("expected Active, got {:?}", new_state),
        }
    }

    #[test]
    fn active_fingerprint_blocked_immediate_rotation() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::FingerprintBlocked,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(
            new_state,
            VeilState::Degraded {
                consecutive_failures: u8::MAX,
                ..
            }
        ));
    }

    #[test]
    fn active_tls_cert_problem_no_state_change() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, effects) = reduce(
            state.clone(),
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::TlsCertProblem,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Active { .. }));
        assert!(effects.is_empty());
    }

    #[test]
    fn active_degraded_threshold_reached() {
        let cfg = VeilConfig {
            degraded_threshold: 2,
            ..VeilConfig::default()
        };
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 1,
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &cfg,
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Degraded { .. }));
    }

    #[test]
    fn active_stop_goes_to_idle() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Degraded transitions ──────────────────────────────────────────────

    #[test]
    fn degraded_more_failures_idle() {
        let state = VeilState::Degraded {
            method: MethodId::Obfs4,
            port: 12345,
            consecutive_failures: 2,
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        // Threshold reached (2 >= 2) → goes to Idle with StopActive.
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Cooldown transitions ──────────────────────────────────────────────

    #[test]
    fn cooldown_elapsed_goes_to_idle() {
        let until = now() - Duration::from_secs(1); // already elapsed
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state,
            VeilEvent::CooldownElapsed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Idle));
    }

    #[test]
    fn cooldown_not_yet_elapsed_stays_cooldown() {
        let until = now() + Duration::from_secs(30);
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state.clone(),
            VeilEvent::CooldownElapsed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
    }

    #[test]
    fn cooldown_stop_goes_to_idle() {
        let until = now() + Duration::from_secs(30);
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
    }

    // ── Candidate selection ───────────────────────────────────────────────

    #[test]
    fn select_candidates_returns_top_k() {
        struct MockScores;
        impl ScoreLookup for MockScores {
            fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
                match method {
                    MethodId::Obfs4 => Some(ScoreEntry {
                        successes: 10,
                        failures: 1,
                        last_success_at: Some(SystemTime::now() - Duration::from_secs(60)),
                        last_failure_at: None,
                        median_latency_ms: 800,
                        blocked_at: None,
                        consecutive_failures: 0,
                    }),
                    MethodId::WebTunnel => Some(ScoreEntry {
                        successes: 2,
                        failures: 5,
                        last_success_at: None,
                        last_failure_at: Some(SystemTime::now() - Duration::from_secs(3600)),
                        median_latency_ms: 2000,
                        blocked_at: None,
                        consecutive_failures: 3,
                    }),
                    _ => None,
                }
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                _method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                false
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &MockScores,
            &cfg,
            now_sys(),
        );

        assert_eq!(candidates.len(), 2);
        // Obfs4 should be first (higher score).
        assert_eq!(candidates[0], MethodId::Obfs4);
    }

    #[test]
    fn select_candidates_skips_permanently_blocked() {
        struct BlockedScores;
        impl ScoreLookup for BlockedScores {
            fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
                match method {
                    MethodId::WebTunnel => Some(ScoreEntry {
                        successes: 0,
                        failures: 10,
                        last_success_at: None,
                        last_failure_at: Some(SystemTime::now()),
                        median_latency_ms: 0,
                        blocked_at: Some(SystemTime::now() - Duration::from_secs(3600)),
                        consecutive_failures: 10,
                    }),
                    _ => None,
                }
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                method == MethodId::WebTunnel
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &BlockedScores,
            &cfg,
            now_sys(),
        );

        // WebTunnel should be skipped; Obfs4 and Masque (both no data = 50.0) remain.
        assert_eq!(candidates.len(), 2);
        assert!(!candidates.contains(&MethodId::WebTunnel));
        // Obfs4 should be first (tied score, but appears earlier in MethodId::all()).
        assert_eq!(candidates[0], MethodId::Obfs4);
    }

    #[test]
    fn select_candidates_empty_fallback() {
        struct AllBlockedScores;
        impl ScoreLookup for AllBlockedScores {
            fn get(&self, _fp: &NetworkFingerprint, _method: MethodId) -> Option<ScoreEntry> {
                Some(ScoreEntry {
                    successes: 0,
                    failures: 5,
                    last_success_at: None,
                    last_failure_at: Some(SystemTime::now()),
                    median_latency_ms: 0,
                    blocked_at: Some(SystemTime::now() - Duration::from_secs(86400)),
                    consecutive_failures: 5,
                })
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                _method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                true
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &AllBlockedScores,
            &cfg,
            now_sys(),
        );

        // Should pick the least-recently-blocked method as a fallback.
        assert!(!candidates.is_empty());
    }

    // ── Legacy (top_k=1) behaviour ────────────────────────────────────────

    #[test]
    fn legacy_config_selects_one_candidate() {
        let cfg = VeilConfig::legacy();
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &NoScores,
            &cfg,
            now_sys(),
        );

        assert_eq!(candidates.len(), 1);
    }

    // ── Method set ────────────────────────────────────────────────────────

    #[test]
    fn method_set_all_allows_everything() {
        let ms = MethodSet::all();
        assert!(ms.contains(MethodId::Obfs4));
        assert!(ms.contains(MethodId::WebTunnel));
        assert!(ms.contains(MethodId::Masque));
    }

    #[test]
    fn method_set_disables_specific_method() {
        let ms = MethodSet::from_bitmask(MethodId::WebTunnel.bit());
        assert!(ms.contains(MethodId::Obfs4));
        assert!(!ms.contains(MethodId::WebTunnel));
    }
}
