//! Shared wire protocol types for veil-front.
//!
//! Used by both the client (`construct-veil`) and the relay (`construct-veil-relay`).
//! Contains ticket types, auth record codec, and frame encoding/decoding.
//!
//! # Wire format
//!
//! ```text
//! Frame = [type:u8][len:varint][payload:len bytes]
//!   type: 0x00 = AUTH, 0x01 = DATA, 0x02 = CHAFF
//! ```
//!
//! Auth record (inside TLS, first application data):
//! ```text
//! auth_rec = frame(0x00, ticket_id[16] || authcode[32])
//! ```
//!
//! # Security rules
//! - **Never** use `==` on authcode bytes — always `subtle::ConstantTimeEq`
//! - `AuthKey` and `Ticket` implement `ZeroizeOnDrop`
//! - `wire_ver` must be bumped on any wire format change

#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

mod auth;
mod framing;
mod ticket;
mod varint;

pub use auth::*;
pub use framing::*;
pub use ticket::*;
pub use varint::*;

// ── Wire protocol constants ────────────────────────────────────────────────

/// Current wire format version. Bump on any framing change.
pub const WIRE_VER: u8 = 1;

/// TLS exporter label for session binding.
pub const EXPORTER_LABEL: &str = "construct veil-front auth v1";

/// Length of the TLS exporter output in bytes.
pub const EXPORTER_LEN: usize = 32;

/// Suite ID for the classic (non-PQ) auth mode.
pub const SUITE_CLASSIC_V1: u8 = 0x01;

// ── Frame type bytes ───────────────────────────────────────────────────────

/// Frame type: authentication record (first application data after TLS handshake).
pub const FRAME_TYPE_AUTH: u8 = 0x00;

/// Frame type: ferried payload bytes (h2c traffic).
pub const FRAME_TYPE_DATA: u8 = 0x01;

/// Frame type: chaff / padding (silently dropped on receipt).
pub const FRAME_TYPE_CHAFF: u8 = 0x02;
