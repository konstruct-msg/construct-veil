//! Ticket store — in-memory ticket validation for the PoC.
//!
//! Production will use SQLite/Redis with rotation. For the PoC, tickets are
//! loaded from a JSON file at startup and validated in memory.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use construct_veil_protocol::AuthRecord;
use construct_veil_protocol::ticket::{Ticket, ticket_from_bytes};
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

    // ── Dynamic sync (SubscribeVeilTickets) ────────────────────────────────
    // The backend is the source of truth; the relay subscribes and applies these
    // live, with no restart. `tickets.json` (load_from_json) is only a
    // bootstrap/offline fallback used until the first SNAPSHOT arrives.

    /// Replace the entire store with a fresh snapshot (`SNAPSHOT`). Returns the
    /// new ticket count.
    pub async fn replace_all(&self, tickets: Vec<Ticket>) -> usize {
        let mut inner = self.inner.write().await;
        inner.tickets.clear();
        for t in tickets {
            inner.tickets.insert(hex::encode(t.ticket_id), t);
        }
        inner.tickets.len()
    }

    /// Insert or update tickets (`UPSERT`). Returns the number applied.
    pub async fn upsert_many(&self, tickets: Vec<Ticket>) -> usize {
        let mut inner = self.inner.write().await;
        let n = tickets.len();
        for t in tickets {
            inner.tickets.insert(hex::encode(t.ticket_id), t);
        }
        n
    }

    /// Remove tickets by id (`REVOKE`). Accepts raw id byte slices (as they arrive
    /// on the wire). Returns the number actually removed.
    pub async fn revoke_many(&self, ids: &[Vec<u8>]) -> usize {
        let mut inner = self.inner.write().await;
        let mut removed = 0;
        for id in ids {
            if inner.tickets.remove(&hex::encode(id)).is_some() {
                removed += 1;
            }
        }
        removed
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

        // Verify using the shared protocol codec — single source of truth for
        // the authcode derivation, constant-time compare inside `verify`.
        let record = AuthRecord {
            ticket_id: *ticket_id,
            authcode: *authcode,
        };
        if record.verify(&ticket, exporter) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::ticket::{AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN};

    /// Compute the authcode for a ticket + exporter via the shared protocol codec.
    fn compute_authcode(ticket: &Ticket, exporter: &[u8; 32]) -> [u8; 32] {
        AuthRecord::from_ticket(ticket, exporter).authcode
    }

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

    fn ticket_with_id(id_byte: u8) -> Ticket {
        let mut t = make_test_ticket();
        t.ticket_id = [id_byte; TICKET_ID_LEN];
        t
    }

    #[tokio::test]
    async fn replace_all_swaps_the_whole_set() {
        let store = TicketStore::new();
        store.insert(ticket_with_id(0x01)).await;
        store.insert(ticket_with_id(0x02)).await;
        assert_eq!(store.len().await, 2);

        // SNAPSHOT with a disjoint set replaces everything.
        let n = store
            .replace_all(vec![ticket_with_id(0x03), ticket_with_id(0x04)])
            .await;
        assert_eq!(n, 2);
        assert_eq!(store.len().await, 2);

        let exporter = fake_exporter();
        // Old ticket gone, new ticket present.
        let old = ticket_with_id(0x01);
        assert!(store
            .validate(&old.ticket_id, &compute_authcode(&old, &exporter), &exporter)
            .await
            .is_none());
        let new = ticket_with_id(0x03);
        assert!(store
            .validate(&new.ticket_id, &compute_authcode(&new, &exporter), &exporter)
            .await
            .is_some());
    }

    #[tokio::test]
    async fn upsert_and_revoke_apply_deltas() {
        let store = TicketStore::new();
        store.insert(ticket_with_id(0x01)).await;

        let added = store.upsert_many(vec![ticket_with_id(0x02), ticket_with_id(0x03)]).await;
        assert_eq!(added, 2);
        assert_eq!(store.len().await, 3);

        // Revoke one existing + one unknown id → only the existing one counts.
        let removed = store
            .revoke_many(&[vec![0x02; TICKET_ID_LEN], vec![0xEE; TICKET_ID_LEN]])
            .await;
        assert_eq!(removed, 1);
        assert_eq!(store.len().await, 2);

        let exporter = fake_exporter();
        let revoked = ticket_with_id(0x02);
        assert!(store
            .validate(&revoked.ticket_id, &compute_authcode(&revoked, &exporter), &exporter)
            .await
            .is_none());
    }
}
