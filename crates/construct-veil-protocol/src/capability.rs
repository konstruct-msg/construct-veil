//! Backend-signed capability — a self-contained veil-front access token.
//!
//! # Why
//!
//! A capability replaces the relay-side ticket store. Instead of the relay holding
//! every ticket's `auth_key` and syncing the valid set from the backend, the client
//! presents a capability that the **issuer (home-server) has signed**. The relay
//! holds only the issuer's Ed25519 **public key** and validates the capability
//! **offline** — no ticket DB, no sync, no relay-side secrets at rest. This makes
//! relays cheap and safe to run on untrusted/enthusiast hardware (seizure leaks
//! nothing reusable). See decisions/veil-ticket-provisioning-system.md.
//!
//! # B2 (this module) vs B1 (future)
//!
//! This is **B2 — signed bearer capability**: the capability still carries the
//! symmetric `auth_key`, and session binding is the unchanged
//! `HMAC(auth_key, exporter || ticket_id || not_after)` authcode (see `AuthRecord`).
//! Residual: an actively-malicious relay sees the presented `auth_key` during a
//! session and could replay it elsewhere — strictly less trust than storing every
//! key at rest, but not zero-trust. **B1** (planned) removes this by binding the
//! capability to a client public key and having the client sign the exporter, so
//! the relay never learns a reusable secret (AUTH frame v3).
//!
//! # Wire format
//!
//! ```text
//! signed message = "veil-cap-v1" || ticket_id[16] || auth_key[32]
//!                  || not_before[8 LE] || not_after[8 LE] || suite_id[1] || scope_utf8
//! sig            = Ed25519(issuer_seed, signed message)            // 64 bytes
//!
//! capability blob = ticket_id[16] || auth_key[32] || not_before[8 LE] || not_after[8 LE]
//!                   || suite_id[1] || scope_len[u8] || scope[scope_len] || sig[64]
//!
//! AUTH v2 payload = capability blob || authcode[32]
//! ```
//!
//! The AUTH v2 *payload* is wrapped by the normal `VeilFrontCodec` / `Frame`
//! (`Frame::auth_v2`, type `FRAME_TYPE_AUTH_V2`) — `AuthRecordV2` does not do its
//! own framing (mirrors how `AuthRecord` produces only the v1 payload).
//!
//! The signing key is domain-separated (`veil-cap-v1` prefix) so a capability
//! signature can never be confused with any other signature made by the same key
//! (e.g. the relay config-blob signature).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::auth::{AuthRecord, AUTHCODE_LEN};
use crate::ticket::{AuthKey, Ticket, AUTH_KEY_LEN, TICKET_ID_LEN};

/// Length of an Ed25519 signature in bytes.
pub const CAP_SIG_LEN: usize = 64;

/// Domain-separation prefix for the capability signing message.
pub const CAP_DOMAIN: &[u8] = b"veil-cap-v1";

/// Fixed-size portion of an encoded capability (everything except scope + sig).
const CAP_FIXED_LEN: usize = TICKET_ID_LEN + AUTH_KEY_LEN + 8 + 8 + 1 + 1; // 66

/// Derive the issuer's Ed25519 public key (32 bytes) from its 32-byte seed.
/// Used by the relay (config), the backend issuer, and tooling to agree on the
/// pubkey the relay must pin.
pub fn issuer_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A backend-signed, self-contained veil-front access capability.
#[derive(Debug, Clone)]
pub struct Capability {
    /// The ticket material (id, key, validity window, suite).
    pub ticket: Ticket,
    /// Relay scope this capability is valid on (matches the relay's --relay-id).
    /// Empty string = any scope.
    pub scope: String,
    /// Ed25519 signature by the issuer over the domain-separated message.
    pub sig: [u8; CAP_SIG_LEN],
}

impl Capability {
    /// Build the canonical, domain-separated message that the issuer signs.
    fn signing_message(ticket: &Ticket, scope: &str) -> Vec<u8> {
        let mut m = Vec::with_capacity(CAP_DOMAIN.len() + CAP_FIXED_LEN + scope.len());
        m.extend_from_slice(CAP_DOMAIN);
        m.extend_from_slice(&ticket.ticket_id);
        m.extend_from_slice(ticket.auth_key.as_bytes());
        m.extend_from_slice(&ticket.not_before.to_le_bytes());
        m.extend_from_slice(&ticket.not_after.to_le_bytes());
        m.push(ticket.suite_id);
        m.extend_from_slice(scope.as_bytes());
        m
    }

    /// Issue (sign) a capability with the issuer's Ed25519 seed (32-byte secret key).
    /// Used by the backend / the make-config-link tool.
    pub fn sign(ticket: Ticket, scope: String, issuer_seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(issuer_seed);
        let msg = Self::signing_message(&ticket, &scope);
        let sig = sk.sign(&msg).to_bytes();
        Self { ticket, scope, sig }
    }

    /// Verify the issuer signature against the issuer's Ed25519 public key (32 bytes).
    /// Offline — the relay needs only this public key.
    pub fn verify_signature(&self, issuer_pubkey: &[u8; 32]) -> bool {
        let vk = match VerifyingKey::from_bytes(issuer_pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let msg = Self::signing_message(&self.ticket, &self.scope);
        vk.verify_strict(&msg, &Signature::from_bytes(&self.sig)).is_ok()
    }

    /// Whether the capability's validity window contains `now_secs`.
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        self.ticket.is_valid_at(now_secs)
    }

    /// Encode the capability blob (no frame header).
    pub fn encode(&self) -> Bytes {
        let scope = self.scope.as_bytes();
        debug_assert!(scope.len() <= u8::MAX as usize, "scope too long");
        let mut buf = BytesMut::with_capacity(CAP_FIXED_LEN + scope.len() + CAP_SIG_LEN);
        buf.put_slice(&self.ticket.ticket_id);
        buf.put_slice(self.ticket.auth_key.as_bytes());
        buf.put_u64_le(self.ticket.not_before);
        buf.put_u64_le(self.ticket.not_after);
        buf.put_u8(self.ticket.suite_id);
        buf.put_u8(scope.len() as u8);
        buf.put_slice(scope);
        buf.put_slice(&self.sig);
        buf.freeze()
    }

    /// Decode a capability blob. Returns `None` on any malformation.
    pub fn decode(data: &mut impl Buf) -> Option<Self> {
        if data.remaining() < CAP_FIXED_LEN {
            return None;
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        data.copy_to_slice(&mut ticket_id);
        let mut auth_key = [0u8; AUTH_KEY_LEN];
        data.copy_to_slice(&mut auth_key);
        let not_before = data.get_u64_le();
        let not_after = data.get_u64_le();
        let suite_id = data.get_u8();
        let scope_len = data.get_u8() as usize;

        if data.remaining() < scope_len + CAP_SIG_LEN {
            return None;
        }
        let mut scope_bytes = vec![0u8; scope_len];
        data.copy_to_slice(&mut scope_bytes);
        let scope = String::from_utf8(scope_bytes).ok()?;

        let mut sig = [0u8; CAP_SIG_LEN];
        data.copy_to_slice(&mut sig);

        Some(Self {
            ticket: Ticket {
                ticket_id,
                auth_key: AuthKey::new(auth_key),
                not_before,
                not_after,
                suite_id,
            },
            scope,
            sig,
        })
    }

    /// Decode from a byte slice.
    pub fn decode_slice(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        Self::decode(&mut buf)
    }
}

/// AUTH v2 record — a capability plus the session-bound authcode.
///
/// `authcode` is the *same* HMAC as `AuthRecord` (`HMAC(auth_key, exporter ||
/// ticket_id || not_after)`), so the session-binding/replay-proof property is
/// unchanged; the difference from v1 is that the client presents the full signed
/// capability (so the relay validates offline) instead of a bare `ticket_id` the
/// relay must look up.
#[derive(Debug, Clone)]
pub struct AuthRecordV2 {
    /// The presented capability.
    pub capability: Capability,
    /// HMAC authenticator binding this AUTH to the TLS session.
    pub authcode: [u8; AUTHCODE_LEN],
}

impl AuthRecordV2 {
    /// Build an AUTH v2 record from a capability and the 32-byte TLS exporter.
    pub fn from_capability(capability: &Capability, exporter: &[u8]) -> Self {
        let authcode = AuthRecord::from_ticket(&capability.ticket, exporter).authcode;
        Self {
            capability: capability.clone(),
            authcode,
        }
    }

    /// Full validation: issuer signature valid, within validity window at `now_secs`,
    /// and the authcode matches the exporter (constant-time). Relay-side entry point.
    pub fn verify(&self, issuer_pubkey: &[u8; 32], exporter: &[u8], now_secs: u64) -> bool {
        if !self.capability.verify_signature(issuer_pubkey) {
            return false;
        }
        if !self.capability.is_valid_at(now_secs) {
            return false;
        }
        let expected = AuthRecord::from_ticket(&self.capability.ticket, exporter).authcode;
        expected.ct_eq(&self.authcode).into()
    }

    /// Encode the AUTH v2 *payload*: `capability_blob || authcode[32]`.
    /// Wrap this in `Frame::auth_v2(...)` for the wire.
    pub fn encode_payload(&self) -> Bytes {
        let cap = self.capability.encode();
        let mut buf = BytesMut::with_capacity(cap.len() + AUTHCODE_LEN);
        buf.put_slice(&cap);
        buf.put_slice(&self.authcode);
        buf.freeze()
    }

    /// Decode an AUTH v2 payload (`capability_blob || authcode[32]`), i.e. the
    /// `payload` of a `Frame` whose type is `FRAME_TYPE_AUTH_V2`. The capability is
    /// variable-length and the authcode is the fixed 32-byte trailer; the payload
    /// must end exactly after the authcode.
    pub fn decode_payload(payload: &[u8]) -> Option<Self> {
        let mut buf = payload;
        let capability = Capability::decode(&mut buf)?;
        if buf.remaining() != AUTHCODE_LEN {
            return None;
        }
        let mut authcode = [0u8; AUTHCODE_LEN];
        buf.copy_to_slice(&mut authcode);
        Some(Self {
            capability,
            authcode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_keypair() -> ([u8; 32], [u8; 32]) {
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        (seed, sk.verifying_key().to_bytes())
    }

    fn make_ticket() -> Ticket {
        Ticket {
            ticket_id: [0xAB; TICKET_ID_LEN],
            auth_key: AuthKey::new([0x42; AUTH_KEY_LEN]),
            not_before: 1_000_000,
            not_after: 1_000_000 + 60 * 24 * 3600,
            suite_id: 0x01,
        }
    }

    fn exporter() -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = 0xCA;
        e[1] = 0xFE;
        e
    }

    const NOW: u64 = 1_000_000 + 3600;

    #[test]
    fn sign_then_verify_signature() {
        let (seed, pk) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        assert!(cap.verify_signature(&pk));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let (seed, _) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        let other_pk = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        assert!(!cap.verify_signature(&other_pk));
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let (seed, pk) = issuer_keypair();
        let mut cap = Capability::sign(make_ticket(), "default".into(), &seed);
        cap.ticket.not_after += 1; // extend validity → must invalidate sig
        assert!(!cap.verify_signature(&pk));
    }

    #[test]
    fn tampered_scope_breaks_signature() {
        let (seed, pk) = issuer_keypair();
        let mut cap = Capability::sign(make_ticket(), "default".into(), &seed);
        cap.scope = "other".into();
        assert!(!cap.verify_signature(&pk));
    }

    #[test]
    fn capability_encode_decode_roundtrip() {
        let (seed, _) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "ru-relay".into(), &seed);
        let blob = cap.encode();
        let decoded = Capability::decode_slice(&blob).expect("decode");
        assert_eq!(decoded.ticket.ticket_id, cap.ticket.ticket_id);
        assert_eq!(decoded.ticket.auth_key.as_bytes(), cap.ticket.auth_key.as_bytes());
        assert_eq!(decoded.ticket.not_after, cap.ticket.not_after);
        assert_eq!(decoded.scope, "ru-relay");
        assert_eq!(decoded.sig, cap.sig);
    }

    #[test]
    fn auth_v2_verify_success() {
        let (seed, pk) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        let rec = AuthRecordV2::from_capability(&cap, &exporter());
        assert!(rec.verify(&pk, &exporter(), NOW));
    }

    #[test]
    fn auth_v2_rejects_wrong_exporter() {
        let (seed, pk) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        let rec = AuthRecordV2::from_capability(&cap, &exporter());
        let mut other = exporter();
        other[0] ^= 0x01;
        assert!(!rec.verify(&pk, &other, NOW));
    }

    #[test]
    fn auth_v2_rejects_expired() {
        let (seed, pk) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        let rec = AuthRecordV2::from_capability(&cap, &exporter());
        let after_expiry = cap.ticket.not_after + 1;
        assert!(!rec.verify(&pk, &exporter(), after_expiry));
    }

    #[test]
    fn auth_v2_rejects_forged_capability() {
        // No valid issuer signature → rejected even if authcode is internally consistent.
        let (_seed, pk) = issuer_keypair();
        let forged = Capability {
            ticket: make_ticket(),
            scope: "default".into(),
            sig: [0u8; CAP_SIG_LEN],
        };
        let rec = AuthRecordV2::from_capability(&forged, &exporter());
        assert!(!rec.verify(&pk, &exporter(), NOW));
    }

    #[test]
    fn auth_v2_payload_roundtrip() {
        let (seed, _) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        let rec = AuthRecordV2::from_capability(&cap, &exporter());
        let payload = rec.encode_payload();
        let decoded = AuthRecordV2::decode_payload(&payload).expect("decode");
        assert_eq!(decoded.authcode, rec.authcode);
        assert_eq!(decoded.capability.scope, "default");
        assert_eq!(decoded.capability.sig, cap.sig);
    }

    #[test]
    fn auth_v2_decode_payload_rejects_garbage() {
        // Too short to hold a capability + authcode.
        assert!(AuthRecordV2::decode_payload(&[0u8; 10]).is_none());
        // A bare capability with no authcode trailer.
        let (seed, _) = issuer_keypair();
        let cap = Capability::sign(make_ticket(), "default".into(), &seed);
        assert!(AuthRecordV2::decode_payload(&cap.encode()).is_none());
    }
}

#[cfg(test)]
mod golden {
    use super::*;

    /// Cross-repo interop anchor. The backend (construct-server `veil-service`)
    /// re-implements this exact signing message + blob layout; both pin the same
    /// vector. If either side drifts, this fails — and a drift would mean the relay
    /// rejects backend-issued capabilities on-device (hard to debug). Fixed inputs:
    /// seed=[7;32], ticket_id=[1;16], auth_key=[2;32], nb=0, na=100, suite=1, scope="ru".
    const GOLDEN_BLOB_HEX: &str = "0101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000640000000000000001027275e00cdb9124a3225a53aa46712bcdee0aab51b01c58f674b1b8d13898bd7dc33dec404cf0e035472ab64689a0163d4f68375b2546ccd83eb8536ecb5daea8130e";

    #[test]
    fn capability_blob_matches_golden_vector() {
        let cap = Capability::sign(
            Ticket {
                ticket_id: [1u8; TICKET_ID_LEN],
                auth_key: AuthKey::new([2u8; AUTH_KEY_LEN]),
                not_before: 0,
                not_after: 100,
                suite_id: 1,
            },
            "ru".into(),
            &[7u8; 32],
        );
        assert_eq!(hex::encode(cap.encode()), GOLDEN_BLOB_HEX);
    }
}
