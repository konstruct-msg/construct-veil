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
//! coordinator.register(Box::new(VeilFrontObfuscator::new()));
//!
//! let result = coordinator.start_session(relay, fingerprint, MethodSet::all()).await?;
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

#[cfg(feature = "utls")]
pub mod veil_front_adapter;

pub use coordinator::*;
pub use fsm::*;
pub use obfuscator::*;
pub use scoring::*;

#[cfg(feature = "utls")]
pub use veil_front_adapter::VeilFrontObfuscator;
