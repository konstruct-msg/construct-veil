//! # construct-veil
//!
//! VEIL — (Variable Encoded Interface Layer) client transport for Construct Messenger.
//!
//! The only obfuscation transport is **veil-front**: a standard TLS 1.3
//! connection to an honest HTTPS front whose relay
//! (`crates/construct-veil-relay`) serves the real site to everyone except a
//! client presenting a valid capability in its first application data. The
//! wire format (tickets, AUTH records, framing) lives in
//! `crates/construct-veil-protocol`.
//!
//! obfs4 and WebTunnel were retired on 2026-06-12 (`decisions/veil-front-only-retire-obfs4`)
//! and their code removed on 2026-10-22.
//!
//! ## Layout
//!
//! - [`veil`] (feature `coordinator`) — the FSM that chooses and probes a method,
//!   per-network scoring, and the veil-front adapter (feature `utls`).
//! - `ffi` (feature `ffi`) — the C ABI the iOS and Android apps call
//!   (`veil_start`, `veil_front_ferry_fd`, …).
//! - [`tls_fingerprint`] (feature `tls`) — browser-shaped ClientHello profiles.

#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

#[cfg(any(feature = "ffi", feature = "coordinator"))]
pub(crate) mod accept;

#[cfg(feature = "ffi")]
#[allow(unsafe_code)]
pub mod ffi;

// Its only user is the veil-front adapter.
#[cfg(feature = "coordinator")]
pub(crate) mod tls_pinned;

#[cfg(feature = "tls")]
pub mod tls_fingerprint;

/// VEIL Coordinator — FSM-based obfuscator selection with happy-eyeballs probing,
/// per-network scoring, and persistent state.
#[cfg(feature = "coordinator")]
pub mod veil;

#[cfg(feature = "tls")]
pub use tls_fingerprint::TlsProfile;
