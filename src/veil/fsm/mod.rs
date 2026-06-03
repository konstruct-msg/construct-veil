//! Pure FSM — states, events, effects, and the reducer.
//!
//! The FSM is a **pure function**: `(state, event, scores, config, now) → (state, effects)`.
//! No I/O, no tokio::spawn, no file access. Fully unit-testable.

#![allow(missing_docs)]

mod reducer;
mod scoring;
mod types;

// Re-export everything for backward compatibility (`use crate::veil::fsm::*`).
pub use reducer::*;
pub use scoring::*;
pub use types::*;
