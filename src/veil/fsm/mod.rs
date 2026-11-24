//! Pure FSM — states, events, effects, and the reducer.
//!
//! The FSM is a **pure function**: `(state, event, config, now) → (state, effects)`.
//! No I/O, no tokio::spawn, no file access. Fully unit-testable.

#![allow(missing_docs)]

mod reducer;
mod types;

// Re-export everything for backward compatibility (`use crate::veil::fsm::*`).
pub use reducer::*;
pub use types::*;
