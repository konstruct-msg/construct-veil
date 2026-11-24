//! FSM types — states, events, effects, configuration, and identifiers.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

// ── Method identification ────────────────────────────────────────────────────

/// Unique identifier for an obfuscation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodId {
    // Obfs4 and WebTunnel have no adapter since 2026-10-22 (decision
    // veil-front-only-retire-obfs4). The ids stay: the discriminants are the bitmask ABI
    // of `VeilStartRequest::allowed_methods` and `VeilStartResult::method`, and the
    // reducer's tests race them as stand-in methods.
    /// obfs4 — retired, no adapter.
    Obfs4 = 0,
    /// WebTunnel — retired, no adapter.
    WebTunnel = 1,
    /// Masque — HTTP/3 DATAGRAM (never built).
    Masque = 2,
    /// VeilFront — honest-front HTTPS relay with session-bound ticket auth.
    /// Client opens standard TLS 1.3, sends auth record in first application data.
    /// Relay routes to tunnel (valid ticket) or real site (everything else).
    VeilFront = 3,
}

impl MethodId {
    /// All known methods, in probe order.
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

// ── Failure classification ───────────────────────────────────────────────────

/// Why a probe or transport connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailureReason {
    /// TLS handshake_failure / alert 40 — method blocked by DPI.
    FingerprintBlocked,
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
        allowed_methods: MethodSet,
    },

    /// Caller requests ICE to stop.
    Stop,

    /// A probe succeeded.
    ProbeSucceeded { method: MethodId, port: u16 },

    /// A probe failed.
    ProbeFailed { method: MethodId },

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
    },

    /// Cancel all probes except the winner.
    CancelOtherProbes { winner: MethodId },

    /// Shut down the currently active method entirely.
    StopActive,

    /// Schedule a CooldownElapsed event after the given duration.
    ScheduleCooldown { duration: Duration },
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
}

impl Default for VeilConfig {
    fn default() -> Self {
        Self {
            top_k_probes: 2,
            inter_probe_delay: Duration::from_millis(150),
            probe_timeout: Duration::from_secs(8),
            degraded_threshold: 2,
            cooldown_duration: Duration::from_secs(30),
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
