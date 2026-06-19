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
//! # B2 (`Capability`/`AuthRecordV2`) vs B1 (`CapabilityV2`/`AuthRecordV3`)
//!
//! **B2 — signed bearer capability** (`Capability`): the capability still carries
//! the symmetric `auth_key`, and session binding is the unchanged
//! `HMAC(auth_key, exporter || ticket_id || not_after)` authcode (see `AuthRecord`).
//! Residual: an actively-malicious relay sees the presented `auth_key` during a
//! session and could replay it elsewhere — strictly less trust than storing every
//! key at rest, but not zero-trust.
//!
//! **B1 — key-bound capability** (`CapabilityV2`): removes that residual trust by
//! binding the capability to the holder's `veil_pk` and having the holder sign the
//! exporter (`AuthRecordV3`) instead of presenting a shared secret. Also adds a
//! `role` field (`ROLE_USER` / `ROLE_RELAY`) so a capability minted for an end-user
//! can never be presented as a chaining-relay capability (or vice versa) — needed
//! because relay chaining (`decisions/veil-relay-topology.md` §3) makes a relay a
//! capability holder too. B1 ships **before** chaining, not in parallel — see
//! `decisions/veil-ticket-provisioning-system.md`.
//!
//! # Wire format — B2
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
//!
//! # Wire format — B1
//!
//! ```text
//! signed message = "veil-cap-v2" || ticket_id[16] || veil_pk[32] || role[1]
//!                  || not_before[8 LE] || not_after[8 LE] || suite_id[1] || scope_utf8
//! sig            = Ed25519(issuer_seed, signed message)            // 64 bytes
//!
//! capability_v2 blob = ticket_id[16] || veil_pk[32] || role[1] || not_before[8 LE]
//!                      || not_after[8 LE] || suite_id[1] || scope_len[u8] || scope[scope_len]
//!                      || sig[64]
//!
//! client_sig  = Ed25519(veil_sk, "veil-auth-v1" || exporter || ticket_id[16] || not_after[8 LE])
//! AUTH v3 payload = capability_v2 blob || client_sig[64]
//! ```
//!
//! `veil-cap-v2` is a distinct domain prefix from `veil-cap-v1` — a B2 signature can
//! never validate as a B1 capability or vice versa, even with identical field values
//! (see `v1_and_v2_domains_do_not_cross_validate`). The AUTH v3 *payload* is wrapped
//! the same way as v2 (`Frame::auth_v3`, type `FRAME_TYPE_AUTH_V3`).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::auth::{AUTHCODE_LEN, AuthRecord};
use crate::ticket::{AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN, Ticket};

/// Length of a veil access keypair's public key in bytes (Ed25519).
pub const VEIL_PK_LEN: usize = 32;

/// Length of a client-side Ed25519 signature in bytes.
pub const CLIENT_SIG_LEN: usize = 64;

/// `role` value: this capability authorises an end-user client.
pub const ROLE_USER: u8 = 0;

/// `role` value: this capability authorises a chaining relay (`relay_domestic`
/// connecting to its upstream `relay_clean`). See
/// `decisions/veil-relay-topology.md` §3/§4.
pub const ROLE_RELAY: u8 = 1;

/// Domain-separation prefix for the key-bound (B1) capability signing message.
/// Distinct from `CAP_DOMAIN` (`veil-cap-v1`) so a v1 bearer-capability
/// signature can never be presented as a v2 key-bound one, or vice versa.
pub const CAP_V2_DOMAIN: &[u8] = b"veil-cap-v2";

/// Domain-separation prefix for the AUTH v3 client-signature message.
pub const AUTH_V3_SIG_DOMAIN: &[u8] = b"veil-auth-v1";

/// Fixed-size portion of an encoded `CapabilityV2` (everything except scope + sig).
const CAP_V2_FIXED_LEN: usize = TICKET_ID_LEN + VEIL_PK_LEN + 1 + 8 + 8 + 1 + 1; // 67

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
        vk.verify_strict(&msg, &Signature::from_bytes(&self.sig))
            .is_ok()
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

/// A backend-signed, **key-bound** veil-front access capability (B1).
///
/// Unlike [`Capability`] (B2), this binds a `veil_pk` instead of carrying a
/// bearer `auth_key` — the relay never learns a reusable secret. `role`
/// distinguishes a user capability from a relay capability (used by a
/// chaining `relay_domestic` to authenticate to its upstream `relay_clean`),
/// so a capability issued for one role can never validate as the other: the
/// signed message includes `role`, and `verify` takes the expected role
/// explicitly. See `decisions/veil-ticket-provisioning-system.md` (B1).
#[derive(Debug, Clone)]
pub struct CapabilityV2 {
    /// Opaque accounting/index identifier (not used for HMAC binding here —
    /// session binding is the client's Ed25519 signature, see [`AuthRecordV3`]).
    pub ticket_id: [u8; TICKET_ID_LEN],
    /// The holder's Ed25519 public key. The relay verifies the AUTH v3 client
    /// signature against this key; only the holder has the matching private key.
    pub veil_pk: [u8; VEIL_PK_LEN],
    /// `ROLE_USER` or `ROLE_RELAY`.
    pub role: u8,
    /// Unix timestamp — capability is not valid before this time.
    pub not_before: u64,
    /// Unix timestamp — capability is not valid after this time.
    pub not_after: u64,
    /// Crypto suite selector.
    pub suite_id: u8,
    /// Relay scope this capability is valid on. Empty string = any scope.
    pub scope: String,
    /// Ed25519 signature by the issuer over the domain-separated message.
    pub sig: [u8; CAP_SIG_LEN],
}

impl CapabilityV2 {
    /// Build the canonical, domain-separated message that the issuer signs.
    fn signing_message(
        ticket_id: &[u8; TICKET_ID_LEN],
        veil_pk: &[u8; VEIL_PK_LEN],
        role: u8,
        not_before: u64,
        not_after: u64,
        suite_id: u8,
        scope: &str,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(CAP_V2_DOMAIN.len() + CAP_V2_FIXED_LEN + scope.len());
        m.extend_from_slice(CAP_V2_DOMAIN);
        m.extend_from_slice(ticket_id);
        m.extend_from_slice(veil_pk);
        m.push(role);
        m.extend_from_slice(&not_before.to_le_bytes());
        m.extend_from_slice(&not_after.to_le_bytes());
        m.push(suite_id);
        m.extend_from_slice(scope.as_bytes());
        m
    }

    /// Issue (sign) a key-bound capability with the issuer's Ed25519 seed.
    /// Used by the backend issuer / relay-admission tooling.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        ticket_id: [u8; TICKET_ID_LEN],
        veil_pk: [u8; VEIL_PK_LEN],
        role: u8,
        not_before: u64,
        not_after: u64,
        suite_id: u8,
        scope: String,
        issuer_seed: &[u8; 32],
    ) -> Self {
        let sk = SigningKey::from_bytes(issuer_seed);
        let msg = Self::signing_message(
            &ticket_id, &veil_pk, role, not_before, not_after, suite_id, &scope,
        );
        let sig = sk.sign(&msg).to_bytes();
        Self {
            ticket_id,
            veil_pk,
            role,
            not_before,
            not_after,
            suite_id,
            scope,
            sig,
        }
    }

    /// Verify the issuer signature against the issuer's Ed25519 public key (32 bytes).
    /// Offline — the relay needs only this public key.
    pub fn verify_signature(&self, issuer_pubkey: &[u8; 32]) -> bool {
        let vk = match VerifyingKey::from_bytes(issuer_pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let msg = Self::signing_message(
            &self.ticket_id,
            &self.veil_pk,
            self.role,
            self.not_before,
            self.not_after,
            self.suite_id,
            &self.scope,
        );
        vk.verify_strict(&msg, &Signature::from_bytes(&self.sig))
            .is_ok()
    }

    /// Whether the capability's validity window contains `now_secs`.
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
    }

    /// Encode the capability blob (no frame header).
    pub fn encode(&self) -> Bytes {
        let scope = self.scope.as_bytes();
        debug_assert!(scope.len() <= u8::MAX as usize, "scope too long");
        let mut buf = BytesMut::with_capacity(CAP_V2_FIXED_LEN + scope.len() + CAP_SIG_LEN);
        buf.put_slice(&self.ticket_id);
        buf.put_slice(&self.veil_pk);
        buf.put_u8(self.role);
        buf.put_u64_le(self.not_before);
        buf.put_u64_le(self.not_after);
        buf.put_u8(self.suite_id);
        buf.put_u8(scope.len() as u8);
        buf.put_slice(scope);
        buf.put_slice(&self.sig);
        buf.freeze()
    }

    /// Decode a capability blob. Returns `None` on any malformation.
    pub fn decode(data: &mut impl Buf) -> Option<Self> {
        if data.remaining() < CAP_V2_FIXED_LEN {
            return None;
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        data.copy_to_slice(&mut ticket_id);
        let mut veil_pk = [0u8; VEIL_PK_LEN];
        data.copy_to_slice(&mut veil_pk);
        let role = data.get_u8();
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
            ticket_id,
            veil_pk,
            role,
            not_before,
            not_after,
            suite_id,
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

/// AUTH v3 record — a key-bound capability plus a client-side Ed25519 signature
/// over the TLS exporter. Replaces the HMAC authcode (which requires the relay
/// to be handed a shared secret) with a signature the relay can verify but
/// never reuse: the relay only ever sees `veil_pk` (public) and the signature,
/// never `veil_sk`.
#[derive(Debug, Clone)]
pub struct AuthRecordV3 {
    /// The presented key-bound capability.
    pub capability: CapabilityV2,
    /// `Ed25519(veil_sk, AUTH_V3_SIG_DOMAIN || exporter || ticket_id || not_after)`.
    pub client_sig: [u8; CLIENT_SIG_LEN],
}

impl AuthRecordV3 {
    fn signing_message(capability: &CapabilityV2, exporter: &[u8]) -> Vec<u8> {
        let mut m =
            Vec::with_capacity(AUTH_V3_SIG_DOMAIN.len() + exporter.len() + TICKET_ID_LEN + 8);
        m.extend_from_slice(AUTH_V3_SIG_DOMAIN);
        m.extend_from_slice(exporter);
        m.extend_from_slice(&capability.ticket_id);
        m.extend_from_slice(&capability.not_after.to_le_bytes());
        m
    }

    /// Build an AUTH v3 record from a capability and the holder's `veil_sk`.
    ///
    /// `exporter` must be exactly 32 bytes (the TLS exporter for this session).
    pub fn from_capability(
        capability: &CapabilityV2,
        veil_sk: &SigningKey,
        exporter: &[u8],
    ) -> Self {
        assert_eq!(exporter.len(), 32, "exporter must be 32 bytes");
        let msg = Self::signing_message(capability, exporter);
        let client_sig = veil_sk.sign(&msg).to_bytes();
        Self {
            capability: capability.clone(),
            client_sig,
        }
    }

    /// Full validation: issuer signature valid, role matches what this listener
    /// accepts, within the validity window at `now_secs`, and the client
    /// signature matches the exporter under the capability's `veil_pk`.
    ///
    /// `expected_role` lets the relay enforce role separation: its client-facing
    /// listener passes `ROLE_USER`, its upstream-facing (chaining) listener
    /// passes `ROLE_RELAY` — a capability issued for one role is rejected on the
    /// other's listener even though the signature itself is otherwise valid.
    pub fn verify(
        &self,
        issuer_pubkey: &[u8; 32],
        expected_role: u8,
        exporter: &[u8],
        now_secs: u64,
    ) -> bool {
        if !self.capability.verify_signature(issuer_pubkey) {
            return false;
        }
        if self.capability.role != expected_role {
            return false;
        }
        if !self.capability.is_valid_at(now_secs) {
            return false;
        }
        let vk = match VerifyingKey::from_bytes(&self.capability.veil_pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let msg = Self::signing_message(&self.capability, exporter);
        vk.verify_strict(&msg, &Signature::from_bytes(&self.client_sig))
            .is_ok()
    }

    /// Encode the AUTH v3 *payload*: `capability_v2_blob || client_sig[64]`.
    /// Wrap this in `Frame::auth_v3(...)` for the wire.
    pub fn encode_payload(&self) -> Bytes {
        let cap = self.capability.encode();
        let mut buf = BytesMut::with_capacity(cap.len() + CLIENT_SIG_LEN);
        buf.put_slice(&cap);
        buf.put_slice(&self.client_sig);
        buf.freeze()
    }

    /// Decode an AUTH v3 payload (`capability_v2_blob || client_sig[64]`), i.e.
    /// the `payload` of a `Frame` whose type is `FRAME_TYPE_AUTH_V3`.
    pub fn decode_payload(payload: &[u8]) -> Option<Self> {
        let mut buf = payload;
        let capability = CapabilityV2::decode(&mut buf)?;
        if buf.remaining() != CLIENT_SIG_LEN {
            return None;
        }
        let mut client_sig = [0u8; CLIENT_SIG_LEN];
        buf.copy_to_slice(&mut client_sig);
        Some(Self {
            capability,
            client_sig,
        })
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    fn issuer_keypair() -> ([u8; 32], [u8; 32]) {
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        (seed, sk.verifying_key().to_bytes())
    }

    fn holder_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn make_cap(issuer_seed: &[u8; 32], veil_pk: [u8; 32], role: u8) -> CapabilityV2 {
        CapabilityV2::sign(
            [0xABu8; TICKET_ID_LEN],
            veil_pk,
            role,
            1_000_000,
            1_000_000 + 7 * 24 * 3600,
            0x01,
            "ru-relay".into(),
            issuer_seed,
        )
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
        let (_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_USER);
        assert!(cap.verify_signature(&pk));
    }

    #[test]
    fn tampered_role_breaks_signature() {
        let (seed, pk) = issuer_keypair();
        let (_sk, veil_pk) = holder_keypair();
        let mut cap = make_cap(&seed, veil_pk, ROLE_USER);
        cap.role = ROLE_RELAY; // attempt to repurpose a user cap as a relay cap
        assert!(!cap.verify_signature(&pk));
    }

    #[test]
    fn capability_v2_encode_decode_roundtrip() {
        let (seed, _) = issuer_keypair();
        let (_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_RELAY);
        let blob = cap.encode();
        let decoded = CapabilityV2::decode_slice(&blob).expect("decode");
        assert_eq!(decoded.veil_pk, cap.veil_pk);
        assert_eq!(decoded.role, ROLE_RELAY);
        assert_eq!(decoded.scope, "ru-relay");
        assert_eq!(decoded.sig, cap.sig);
    }

    #[test]
    fn auth_v3_verify_success_for_matching_role() {
        let (seed, issuer_pk) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_USER);
        let rec = AuthRecordV3::from_capability(&cap, &veil_sk, &exporter());
        assert!(rec.verify(&issuer_pk, ROLE_USER, &exporter(), NOW));
    }

    #[test]
    fn auth_v3_rejects_role_mismatch() {
        // A valid relay capability must not authenticate on a user-facing listener.
        let (seed, issuer_pk) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_RELAY);
        let rec = AuthRecordV3::from_capability(&cap, &veil_sk, &exporter());
        assert!(!rec.verify(&issuer_pk, ROLE_USER, &exporter(), NOW));
        assert!(rec.verify(&issuer_pk, ROLE_RELAY, &exporter(), NOW));
    }

    #[test]
    fn auth_v3_rejects_wrong_exporter() {
        let (seed, issuer_pk) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_USER);
        let rec = AuthRecordV3::from_capability(&cap, &veil_sk, &exporter());
        let mut other = exporter();
        other[0] ^= 0x01;
        assert!(!rec.verify(&issuer_pk, ROLE_USER, &other, NOW));
    }

    #[test]
    fn auth_v3_rejects_expired() {
        let (seed, issuer_pk) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_USER);
        let rec = AuthRecordV3::from_capability(&cap, &veil_sk, &exporter());
        let after_expiry = cap.not_after + 1;
        assert!(!rec.verify(&issuer_pk, ROLE_USER, &exporter(), after_expiry));
    }

    #[test]
    fn auth_v3_rejects_forged_capability() {
        let (_seed, issuer_pk) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let forged = CapabilityV2 {
            ticket_id: [0xABu8; TICKET_ID_LEN],
            veil_pk,
            role: ROLE_USER,
            not_before: 1_000_000,
            not_after: 1_000_000 + 7 * 24 * 3600,
            suite_id: 0x01,
            scope: "ru-relay".into(),
            sig: [0u8; CAP_SIG_LEN],
        };
        let rec = AuthRecordV3::from_capability(&forged, &veil_sk, &exporter());
        assert!(!rec.verify(&issuer_pk, ROLE_USER, &exporter(), NOW));
    }

    #[test]
    fn auth_v3_rejects_signature_from_wrong_holder_key() {
        // Capability binds holder A's veil_pk, but holder B signs the AUTH record.
        let (seed, issuer_pk) = issuer_keypair();
        let (_sk_a, veil_pk_a) = holder_keypair();
        let sk_b = SigningKey::from_bytes(&[4u8; 32]);
        let cap = make_cap(&seed, veil_pk_a, ROLE_USER);
        let rec = AuthRecordV3::from_capability(&cap, &sk_b, &exporter());
        assert!(!rec.verify(&issuer_pk, ROLE_USER, &exporter(), NOW));
    }

    #[test]
    fn auth_v3_payload_roundtrip() {
        let (seed, _) = issuer_keypair();
        let (veil_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_RELAY);
        let rec = AuthRecordV3::from_capability(&cap, &veil_sk, &exporter());
        let payload = rec.encode_payload();
        let decoded = AuthRecordV3::decode_payload(&payload).expect("decode");
        assert_eq!(decoded.client_sig, rec.client_sig);
        assert_eq!(decoded.capability.role, ROLE_RELAY);
        assert_eq!(decoded.capability.sig, cap.sig);
    }

    #[test]
    fn auth_v3_decode_payload_rejects_garbage() {
        assert!(AuthRecordV3::decode_payload(&[0u8; 10]).is_none());
        let (seed, _) = issuer_keypair();
        let (_sk, veil_pk) = holder_keypair();
        let cap = make_cap(&seed, veil_pk, ROLE_USER);
        assert!(AuthRecordV3::decode_payload(&cap.encode()).is_none());
    }

    #[test]
    fn v1_and_v2_domains_do_not_cross_validate() {
        // A B2 (bearer) capability signed under CAP_DOMAIN must not verify as a
        // CapabilityV2 under the same issuer key, even with matching field values.
        let (seed, issuer_pk) = issuer_keypair();
        let bearer_cap = Capability::sign(
            Ticket {
                ticket_id: [0xABu8; TICKET_ID_LEN],
                auth_key: AuthKey::new([0x11; AUTH_KEY_LEN]),
                not_before: 1_000_000,
                not_after: 1_000_000 + 7 * 24 * 3600,
                suite_id: 0x01,
            },
            "ru-relay".into(),
            &seed,
        );
        // Reinterpret the bearer cap's signature on a v2 message with the same
        // ticket_id/not_before/not_after/suite/scope — must not validate.
        let mut forged_v2 = CapabilityV2 {
            ticket_id: bearer_cap.ticket.ticket_id,
            veil_pk: [0u8; VEIL_PK_LEN],
            role: ROLE_USER,
            not_before: bearer_cap.ticket.not_before,
            not_after: bearer_cap.ticket.not_after,
            suite_id: bearer_cap.ticket.suite_id,
            scope: bearer_cap.scope.clone(),
            sig: bearer_cap.sig,
        };
        assert!(!forged_v2.verify_signature(&issuer_pk));
        forged_v2.sig = [0u8; CAP_SIG_LEN];
        assert!(!forged_v2.verify_signature(&issuer_pk));
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
        let other_pk = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
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
        assert_eq!(
            decoded.ticket.auth_key.as_bytes(),
            cap.ticket.auth_key.as_bytes()
        );
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

    /// Cross-repo interop anchor for **B1** (`CapabilityV2`). Same role as the B2
    /// vector above, pinned against the backend's re-implementation. Fixed inputs:
    /// seed=[7;32], ticket_id=[1;16], veil_pk=[2;32], role=1 (ROLE_RELAY), nb=0,
    /// na=100, suite=1, scope="ru".
    const GOLDEN_BLOB_V2_HEX: &str = "010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010000000000000000640000000000000001027275548ee6e76270611644a8c7ac26407d6c9aed69e375472ee445384f0936661d7cdf3c08b88e448aa1d349f8e6f544fb26662bdbdc99ca2c412fdc232cfee49f06";

    #[test]
    fn capability_v2_blob_matches_golden_vector() {
        let cap = CapabilityV2::sign(
            [1u8; TICKET_ID_LEN],
            [2u8; VEIL_PK_LEN],
            ROLE_RELAY,
            0,
            100,
            1,
            "ru".into(),
            &[7u8; 32],
        );
        assert_eq!(hex::encode(cap.encode()), GOLDEN_BLOB_V2_HEX);
    }
}
