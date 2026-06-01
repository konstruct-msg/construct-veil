//! Ticket types — per-session authorisation tokens issued over the manifest channel.
//!
//! A ticket does **not** identify the client; it is fungible and can be used
//! from any IP. The `ticket_id` is an opaque server-side index into the
//! ticket store.
//!
//! # Wire format (manifest channel — JSON/base64)
//! ```text
//! ticket = {
//!   ticket_id:  16 bytes (base64),
//!   auth_key:   32 bytes (base64),
//!   not_before: u64 (Unix seconds),
//!   not_after:  u64 (Unix seconds),
//!   suite_id:   u8,
//! }
//! ```
//!
//! # Security
//! - `auth_key` is zeroised on drop
//! - Tickets are short-lived (PoC: 6 hours; production: TBD)
//! - `ticket_id` is random, not derived from client identity

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A veil-front ticket, issued over the authenticated manifest channel.
///
/// The ticket authorises the holder to open a tunnel. It is **not** bound to
/// any specific client — fungibility prevents correlation across IPs.
#[derive(Debug, Clone)]
pub struct Ticket {
    /// Opaque 16-byte index into the server ticket store.
    pub ticket_id: [u8; TICKET_ID_LEN],
    /// Per-ticket PSK, used as HMAC key for auth record derivation.
    pub auth_key: AuthKey,
    /// Unix timestamp — ticket is not valid before this time.
    pub not_before: u64,
    /// Unix timestamp — ticket is not valid after this time.
    pub not_after: u64,
    /// Crypto suite selector (CLASSIC v1 = 0x01).
    pub suite_id: u8,
}

/// Length of the ticket identifier in bytes.
pub const TICKET_ID_LEN: usize = 16;

/// The per-ticket PSK (32 bytes). Wrapped to ensure zeroisation.
#[derive(Clone)]
pub struct AuthKey(pub [u8; AUTH_KEY_LEN]);

/// Length of the auth key in bytes.
pub const AUTH_KEY_LEN: usize = 32;

impl AuthKey {
    /// Create a new AuthKey from raw bytes.
    pub fn new(bytes: [u8; AUTH_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; AUTH_KEY_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for AuthKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for AuthKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for AuthKey {}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthKey").field(&"[redacted]").finish()
    }
}

impl Ticket {
    /// Check whether the ticket is valid at the given Unix timestamp.
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
    }

    /// Check whether the ticket is currently valid.
    pub fn is_valid_now(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs();
        self.is_valid_at(now)
    }
}

/// Serialise a ticket to a byte blob (for manifest channel transport).
///
/// Format: `ticket_id[16] || auth_key[32] || not_before[8] || not_after[8] || suite_id[1]`
/// Total: 65 bytes.
pub fn ticket_to_bytes(ticket: &Ticket) -> [u8; TICKET_WIRE_LEN] {
    let mut out = [0u8; TICKET_WIRE_LEN];
    out[0..16].copy_from_slice(&ticket.ticket_id);
    out[16..48].copy_from_slice(ticket.auth_key.as_bytes());
    out[48..56].copy_from_slice(&ticket.not_before.to_le_bytes());
    out[56..64].copy_from_slice(&ticket.not_after.to_le_bytes());
    out[64] = ticket.suite_id;
    out
}

/// Length of the serialised ticket in bytes.
pub const TICKET_WIRE_LEN: usize = 65;

/// Deserialise a ticket from a 65-byte blob.
///
/// Returns `None` if the slice is not exactly 65 bytes.
pub fn ticket_from_bytes(data: &[u8]) -> Option<Ticket> {
    if data.len() != TICKET_WIRE_LEN {
        return None;
    }

    let mut ticket_id = [0u8; TICKET_ID_LEN];
    ticket_id.copy_from_slice(&data[0..16]);

    let mut auth_key_bytes = [0u8; AUTH_KEY_LEN];
    auth_key_bytes.copy_from_slice(&data[16..48]);

    let mut not_before_bytes = [0u8; 8];
    not_before_bytes.copy_from_slice(&data[48..56]);
    let not_before = u64::from_le_bytes(not_before_bytes);

    let mut not_after_bytes = [0u8; 8];
    not_after_bytes.copy_from_slice(&data[56..64]);
    let not_after = u64::from_le_bytes(not_after_bytes);

    let suite_id = data[64];

    Some(Ticket {
        ticket_id,
        auth_key: AuthKey::new(auth_key_bytes),
        not_before,
        not_after,
        suite_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ticket() -> Ticket {
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id[0] = 0xAB;
        ticket_id[15] = 0xCD;

        let auth_key = AuthKey::new([0x42u8; AUTH_KEY_LEN]);

        Ticket {
            ticket_id,
            auth_key,
            not_before: 1_000_000,
            not_after: 1_000_000 + 6 * 3600, // 6 hours
            suite_id: 0x01,
        }
    }

    #[test]
    fn ticket_validity_window() {
        let ticket = make_test_ticket();
        assert!(ticket.is_valid_at(1_000_000));
        assert!(ticket.is_valid_at(1_000_000 + 3600));
        assert!(ticket.is_valid_at(1_000_000 + 6 * 3600));
        assert!(!ticket.is_valid_at(999_999));
        assert!(!ticket.is_valid_at(1_000_000 + 6 * 3600 + 1));
    }

    #[test]
    fn ticket_roundtrip_bytes() {
        let original = make_test_ticket();
        let bytes = ticket_to_bytes(&original);
        assert_eq!(bytes.len(), TICKET_WIRE_LEN);

        let restored = ticket_from_bytes(&bytes).expect("deserialisation failed");
        assert_eq!(restored.ticket_id, original.ticket_id);
        assert_eq!(restored.auth_key.0, original.auth_key.0);
        assert_eq!(restored.not_before, original.not_before);
        assert_eq!(restored.not_after, original.not_after);
        assert_eq!(restored.suite_id, original.suite_id);
    }

    #[test]
    fn ticket_from_bytes_wrong_length() {
        assert!(ticket_from_bytes(&[0u8; 64]).is_none());
        assert!(ticket_from_bytes(&[0u8; 66]).is_none());
        assert!(ticket_from_bytes(&[]).is_none());
    }

    #[test]
    fn auth_key_debug_redacted() {
        let key = AuthKey::new([0xFF; 32]);
        let debug = format!("{:?}", key);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("FF"));
    }
}
