//! VEIL Coordinator — FSM-based obfuscator selection with happy-eyeballs probing.
//!
//! Per [`CONSTRUCT_ICE_FSM_SPEC`](docs/CONSTRUCT_ICE_FSM_SPEC.md), this module
//! implements:
//!
//! - **`ObfuscatorFSM`** — pure state machine describing the lifecycle of one ICE session.
//!   No I/O; emits [`VeilEffect`]s that the caller (or `ProbeOrchestrator`) executes.
//! - **`VeilConfig`** — fully parameterizable thresholds.
//! - **`MethodId`** — enum of available obfuscation methods.
//! - **`NetworkFingerprint`** — opaque network identifier for per-network scoring.
//! - **`PersistentScores`** — SQLite-backed per-network scoring store.
//! - **`VeilCoordinator`** — async orchestrator that drives the FSM and manages probes.
//!
//! # Usage
//!
//! ```ignore
//! let mut coordinator = VeilCoordinator::new(VeilConfig::default(), scores);
//! coordinator.register(Box::new(Obfs4Obfuscator::new()));
//! coordinator.register(Box::new(WebTunnelObfuscator::new()));
//! #[cfg(feature = "utls")]
//! coordinator.register(Box::new(VeilFrontObfuscator::new()));
//!
//! let result = coordinator.start_session(
//!     relay, bundle, fingerprint, MethodSet::all(),
//! ).await?;
//! // result.port is the local TCP port for gRPC
//! ```

#![allow(missing_docs)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::single_match)]

pub mod coordinator;
pub mod diag;
pub mod fsm;
pub mod obfuscator;
pub mod scoring;
pub mod veil_front; // Padding modes shared between client and relay

#[cfg(feature = "tls")]
pub mod obfs4_adapter;
#[cfg(feature = "utls")]
pub mod veil_front_adapter;
#[cfg(feature = "webtunnel")]
pub mod webtunnel_adapter;

pub use coordinator::*;
pub use fsm::*;
pub use obfuscator::*;
pub use scoring::*;

#[cfg(feature = "tls")]
pub use obfs4_adapter::Obfs4Obfuscator;
#[cfg(feature = "utls")]
pub use veil_front_adapter::VeilFrontObfuscator;
#[cfg(feature = "webtunnel")]
pub use webtunnel_adapter::WebTunnelObfuscator;
