//! Obfuscator trait — interface each obfuscation method must implement.
//!
//! Adding a new method (e.g. Masque) requires:
//! 1. Implement `Obfuscator` for the new type.
//! 2. Add a variant to `MethodId`.
//! 3. Register with `VeilCoordinator::register()`.
//!
//! No changes needed to Swift/Kotlin clients.

use std::future::Future;

use tokio_util::sync::CancellationToken;

use crate::veil::fsm::MethodId;

/// Handle returned by an obfuscator after starting a probe.
///
/// The probe establishes a test tunnel to the relay. Awaiting `first_byte`
/// confirms the tunnel works end-to-end (handshake + initial server response).
/// If the probe wins the race, the caller starts a proxy on a new local
/// listener — the test tunnel is disposable.
pub struct ObfuscatorHandle {
    /// Resolves when the first useful byte passes through the tunnel
    /// (handshake completed + server responded). If this errors, the probe failed.
    pub first_byte: std::pin::Pin<Box<dyn Future<Output = Result<(), ObfuscatorError>> + Send>>,
    /// Shut down the probe/test connection (idempotent, best-effort).
    pub shutdown: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl ObfuscatorHandle {
    /// Create a handle from the given futures.
    pub fn new(
        first_byte: impl Future<Output = Result<(), ObfuscatorError>> + Send + 'static,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            first_byte: Box::pin(first_byte),
            shutdown: Box::pin(shutdown),
        }
    }
}

/// Error from an obfuscator operation.
#[derive(Debug, thiserror::Error)]
pub enum ObfuscatorError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Connection refused by relay.
    #[error("connection refused")]
    ConnectionRefused,

    /// TLS handshake or verification error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Protocol handshake failed (obfs4 or WebSocket upgrade).
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// Probe timed out before first byte.
    #[error("timeout")]
    Timeout,

    /// Probe was cancelled by the orchestrator.
    #[error("cancelled")]
    Cancelled,

    /// TLS alert 40 / handshake_failure — method blocked by DPI.
    #[error("fingerprint blocked (DPI)")]
    FingerprintBlocked,

    /// Non-101 response on WebSocket upgrade — transparent proxy interception.
    #[error("webtunnel decoy response (transparent proxy)")]
    WebTunnelDecoyResponse,

    /// Certificate expired, pin mismatch, or verification failed.
    #[error("certificate problem: {0}")]
    CertProblem(String),

    /// Uncategorized error.
    #[error("unknown error: {0}")]
    Unknown(String),
}

/// Convert a generic error into an ObfuscatorError.
impl From<Box<dyn std::error::Error + Send + Sync>> for ObfuscatorError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ObfuscatorError::Unknown(e.to_string())
    }
}

/// VeilFront AUTH v3 (key-bound capability, ticket B1) parameters.
///
/// Both fields empty means "not configured" — the veil-front adapter falls back
/// to the existing AUTH v2 bearer ticket (`ProbeRequest::veil_front_ticket_b64`).
/// No flag-day: a build can carry both and the adapter picks v3 whenever it's
/// present. See `decisions/veil-ticket-provisioning-system.md` (B1).
#[derive(Clone, Default)]
pub struct VeilFrontAuthV3 {
    /// Base64-encoded `CapabilityV2` blob (key-bound capability).
    pub capability_v2_b64: String,
    /// Hex-encoded 32-byte Ed25519 `veil_sk` seed. The holder's private key —
    /// never sent anywhere; used locally to sign the TLS exporter.
    pub veil_sk_hex: String,
}

/// Information passed to an obfuscator to start a probe.
#[derive(Clone, Default)]
pub struct ProbeRequest {
    /// Relay address (e.g. "relay.example.com:443").
    pub relay_addr: String,
    /// Bridge/cert bundle string (e.g. "cert=<base64> iat-mode=0").
    pub bundle: String,
    /// TLS SNI hostname (for TLS-wrapped modes). Empty = no SNI.
    pub tls_sni: String,
    /// SPKI hex pin (for TLS pinning). Empty = no pinning.
    pub spki_hex: String,
    /// WebTunnel: HTTP Host header. May differ from `tls_sni` for CDN fronting.
    pub host_header: String,
    /// WebTunnel: WebSocket base path.
    pub wt_base_path: String,
    /// VeilFront: base64-encoded 65-byte ticket blob (AUTH v2, bearer capability).
    /// Empty string = no ticket (probe will fail, as expected without auth) unless
    /// `auth_v3` is configured instead.
    pub veil_front_ticket_b64: String,
    /// VeilFront: AUTH v3 (key-bound capability) parameters. Takes priority over
    /// `veil_front_ticket_b64` when configured.
    pub auth_v3: VeilFrontAuthV3,
}

/// Trait that every obfuscation method must implement.
///
/// Pure async interface — no shared state, no globals.
/// The `ProbeOrchestrator` calls `start()` for each parallel probe.
#[async_trait::async_trait]
pub trait Obfuscator: Send + Sync {
    /// Which method this implements.
    fn method_id(&self) -> MethodId;

    /// Start a probe: establish a test tunnel to the relay.
    ///
    /// Returns immediately with a handle; the caller awaits `handle.first_byte`
    /// to determine if the probe succeeded.
    ///
    /// If `cancel` is triggered, the probe should abort cleanly.
    /// The test tunnel is disposable — after probe success, the orchestrator
    /// starts a fresh proxy listener for actual traffic.
    async fn start(
        &self,
        req: &ProbeRequest,
        cancel: CancellationToken,
    ) -> Result<ObfuscatorHandle, ObfuscatorError>;
}
