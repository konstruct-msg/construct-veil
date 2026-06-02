//! VeilFront — honest-front HTTPS obfuscation method.
//!
//! Client opens standard TLS 1.3 (uTLS + SPKI pin), sends an auth record
//! bound to the TLS session. Relay routes to tunnel (valid ticket) or
//! cover site (everything else) — constant-shape gate.

pub mod padding;
pub mod padding_mode0 {
    //! Mode 0 — FRONT-style front-loaded chaff scheduler.
    pub use super::padding::mode0_front::*;
}

pub use padding::mode0_front::{FrontChaffScheduler, PayloadQueue, WriteStrategy};
pub use padding::{ChaffScheduler, LENGTH_BUCKETS, PaddingMode, bucket_data_frame, bucket_size};
