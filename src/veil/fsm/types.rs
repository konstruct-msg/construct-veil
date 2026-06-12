//! FSM types — states, events, effects, configuration, and identifiers.

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
        // Distinct bit flag per method. NOTE: must be `1 << discriminant`, not the
        // bare discriminant — `MethodSet` ANDs these (`self.0 & method.bit()`), so a
        // bare discriminant (Obfs4=0, VeilFront=3=0b11) collides and corrupts any
        // non-zero allowed-set bitmask.
        1u32 << (*self as u32)
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
