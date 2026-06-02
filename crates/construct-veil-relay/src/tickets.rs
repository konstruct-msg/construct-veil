//! Ticket store — in-memory ticket validation for the PoC.
//!
//! Production will use SQLite/Redis with rotation. For the PoC, tickets are
//! loaded from a JSON file at startup and validated in memory.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use construct_veil_protocol::ticket::{Ticket, ticket_from_bytes};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

/// A veil-front ticket store. Thread-safe, read-optimised.
#[derive(Clone)]
pub struct TicketStore {
    inner: Arc<RwLock<StoreInner>>,
}

struct StoreInner {
    /// Map from ticket_id (16 bytes as hex) to the full ticket.
    tickets: HashMap<String, Ticket>,
}

impl TicketStore {
    /// Create a new empty ticket store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                tickets: HashMap::new(),
            })),
        }
    }

    /// Add a ticket to the store (CLI/manual issuance for PoC).
    pub async fn insert(&self, ticket: Ticket) {
        let id_hex = hex::encode(ticket.ticket_id);
        self.inner.write().await.tickets.insert(id_hex, ticket);
    }

    /// Load tickets from a JSON file.
    ///
    /// File format: array of base64-encoded 65-byte ticket blobs.
    /// ```json
    /// ["<base64-ticket-1>", "<base64-ticket-2>"]
    /// ```
    pub async fn load_from_json(&self, path: &str) -> Result<usize, std::io::Error> {
        let content = tokio::fs::read_to_string(path).await?;
        let blobs: Vec<String> = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut count = 0;
        for b64 in &blobs {
            let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            if let Some(ticket) = ticket_from_bytes(&raw) {
                self.insert(ticket).await;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Validate an auth record against a known ticket and TLS exporter.
    ///
    /// Returns `Some(Ticket)` if the ticket exists, is within its validity window,
    /// and the authcode matches (constant-time comparison).
    ///
    /// Returns `None` if:
    /// - ticket_id not found in store
    /// - ticket expired
    /// - authcode mismatch
    ///
    /// **Never** uses `==` on authcode bytes — always constant-time compare.
    pub async fn validate(
        &self,
        ticket_id: &[u8; 16],
        authcode: &[u8; 32],
        exporter: &[u8; 32],
    ) -> Option<Ticket> {
        let id_hex = hex::encode(ticket_id);
        let ticket = self.inner.read().await.tickets.get(&id_hex)?.clone();

        // Check validity window.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs();

        if !ticket.is_valid_at(now) {
            return None;
        }

        // Recompute expected authcode.
        let expected = compute_authcode(&ticket, exporter);

        // Constant-time comparison — non-negotiable.
        if expected.ct_eq(authcode).into() {
            Some(ticket)
        } else {
            None
        }
    }

    /// Get the number of loaded tickets.
    pub async fn len(&self) -> usize {
        self.inner.read().await.tickets.len()
    }
}

impl Default for TicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the HMAC-SHA256 authcode for a ticket + exporter pair.
///
/// `authcode = HMAC-SHA256(auth_key, exporter || ticket_id || not_after)`
fn compute_authcode(ticket: &Ticket, exporter: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(ticket.auth_key.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");

    mac.update(exporter);
    mac.update(&ticket.ticket_id);
    mac.update(&ticket.not_after.to_le_bytes());

    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let mut authcode = [0u8; 32];
    authcode.copy_from_slice(&code_bytes);
    authcode
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::ticket::{AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN};

    fn make_test_ticket() -> Ticket {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs();

        Ticket {
            ticket_id: [0xDE; TICKET_ID_LEN],
            auth_key: AuthKey::new([0xAD; AUTH_KEY_LEN]),
            not_before: now - 3600,
            not_after: now + 6 * 3600,
            suite_id: 0x01,
        }
    }

    fn fake_exporter() -> [u8; 32] {
        let mut exp = [0u8; 32];
        exp[0] = 0xCA;
        exp
    }

    #[tokio::test]
    async fn validate_success() {
        let store = TicketStore::new();
        let ticket = make_test_ticket();
        store.insert(ticket.clone()).await;

        let exporter = fake_exporter();
        let authcode = compute_authcode(&ticket, &exporter);

        let result = store
            .validate(&ticket.ticket_id, &authcode, &exporter)
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn validate_wrong_exporter() {
        let store = TicketStore::new();
        let ticket = make_test_ticket();
        store.insert(ticket.clone()).await;

        let exporter = fake_exporter();
        let mut exporter2 = exporter;
        exporter2[0] ^= 0x01; // different TLS session

        let authcode = compute_authcode(&ticket, &exporter);

        // Authcode was computed with exporter1, but we validate with exporter2.
        let result = store
            .validate(&ticket.ticket_id, &authcode, &exporter2)
            .await;
        assert!(result.is_none()); // replay-proof!
    }

    #[tokio::test]
    async fn validate_unknown_ticket() {
        let store = TicketStore::new();
        let unknown_id = [0xFF; 16];
        let authcode = [0x00; 32];
        let exporter = fake_exporter();

        let result = store.validate(&unknown_id, &authcode, &exporter).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_tampered_authcode() {
        let store = TicketStore::new();
        let ticket = make_test_ticket();
        store.insert(ticket.clone()).await;

        let exporter = fake_exporter();
        let mut authcode = compute_authcode(&ticket, &exporter);
        authcode[0] ^= 0x01; // single-bit flip

        let result = store
            .validate(&ticket.ticket_id, &authcode, &exporter)
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_expired_ticket() {
        let store = TicketStore::new();
        let mut ticket = make_test_ticket();
        // Ticket expired 1 second ago.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ticket.not_before = now - 7200;
        ticket.not_after = now - 1;
        store.insert(ticket.clone()).await;

        let exporter = fake_exporter();
        let authcode = compute_authcode(&ticket, &exporter);

        let result = store
            .validate(&ticket.ticket_id, &authcode, &exporter)
            .await;
        assert!(result.is_none());
    }
}
