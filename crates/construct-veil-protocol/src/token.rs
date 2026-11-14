//! AUTH v4 — a one-time blind-signed access token, so a relay cannot link two
//! connections of one device.
//!
//! # Why
//!
//! AUTH v3 presents the same `ticket_id` and `veil_pk` on every connection, so a
//! relay links all connections of an install across IPs (see `ticket` module docs,
//! "What a relay can link"). AUTH v4 presents nothing that repeats between two
//! connections of one device except what every device of the pool shares: the
//! epoch-key certificate. Rule and mechanism: construct-docs
//! `decisions/veil-relay-sees-no-stable-device-id.md` §1, §5; todo 311.
//!
//! # Mechanism
//!
//! Privacy Pass token type 0x0002 (RFC 9578 §6) built on RSA blind signatures
//! (RFC 9474, variant RSABSSA-SHA384-PSS-Randomized, RSA-2048):
//!
//! 1. The issuer keeps one RSA key per pool and epoch ([`EpochKey`]) and signs its
//!    public half with its Ed25519 issuer key ([`EpochKeyCert`]). A relay already
//!    pins that Ed25519 key (`--issuer-pubkey`), so a new epoch key reaches every
//!    relay inside the AUTH record itself — no new channel, no relay config.
//! 2. For each token the client makes a fresh Ed25519 keypair (`eph_sk`, `eph_pk`),
//!    blinds `token message = "veil-token-v1" ‖ key_id ‖ eph_pk` and has the issuer
//!    sign the blinded value ([`TokenRequest`]). The issuer sees only blinded values.
//! 3. On a connection the client presents certificate, token and an Ed25519
//!    signature by `eph_sk` over the TLS exporter ([`AuthRecordV4`]). The relay
//!    checks the certificate against the issuer key, the token against the epoch
//!    key, and the exporter signature against `eph_pk`.
//!
//! The relay keeps no state: a captured record is useless elsewhere without
//! `eph_sk` (the exporter differs per TLS session), so no spent-token set is
//! needed. Spending a token once is the client's rule, for its own privacy; a
//! client that runs out reuses its last token — linkable as v3 is, never locked out.
//!
//! # Wire format
//!
//! ```text
//! cert message   = "veil-epoch-key-v1" || not_before[8 LE] || not_after[8 LE]
//!                  || scope_len[u8] || scope || modulus[256]
//! cert blob      = not_before[8 LE] || not_after[8 LE] || scope_len[u8] || scope
//!                  || modulus[256] || issuer_sig[64]        // Ed25519(issuer, cert message)
//! key_id         = SHA-256("veil-token-key-v1" || modulus[256])
//! token message  = "veil-token-v1" || key_id[32] || eph_pk[32]
//! token          = eph_pk[32] || msg_randomizer[32] || token_sig[256]
//!                  // token_sig = RSABSSA-SHA384-PSS-Randomized over (msg_randomizer, token message)
//! client_sig     = Ed25519(eph_sk, "veil-auth-v4" || exporter[32])
//! AUTH v4 payload = cert blob || token || client_sig[64]    // frame type FRAME_TYPE_AUTH_V4
//! ```
//!
//! The public exponent is fixed at 65537 and the modulus at exactly 2048 bits: one
//! key size, so the key encoding itself splits no anonymity set. `key_id` names the
//! exact epoch key in the signed token, as `token_key_id` does in RFC 9578 §6, so a
//! token minted under one key never verifies under another pool's or epoch's key.
//!
//! # What this does not close
//!
//! - A relay that colludes with the issuer in real time links by timing.
//! - A reconnect right after a network change pairs old and new IP by timing.
//! - An issuer that hands one person a key of their own: the client accepts only
//!   keys published in the signed config blob (client side, not this module).
//! - Not post-quantum (RFC 9474 §7.7): a quantum adversary could forge tokens
//!   (relay access), but not link them — the blinding is statistical.

use blind_rsa_signatures::reexports::crypto_bigint::BoxedUint;
use blind_rsa_signatures::reexports::rsa::RsaPublicKey;
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSRandomized, MessageRandomizer,
    PublicKeySha384PSSRandomized, SecretKeySha384PSSRandomized, Signature as RsaSignature,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::capability::{CAP_SIG_LEN, CapabilityError, MAX_SCOPE_LEN, scope_matches};

/// Bits of an epoch key's RSA modulus. The only size accepted.
pub const TOKEN_KEY_BITS: usize = 2048;

/// Bytes of an epoch key's RSA modulus, of a blinded message and of every RSA signature.
pub const TOKEN_KEY_LEN: usize = TOKEN_KEY_BITS / 8;

/// Public exponent of every epoch key.
const TOKEN_KEY_EXPONENT: u32 = 65537;

/// Bytes of a token's message randomizer (RFC 9474 §4.1, PrepareRandomize).
pub const MSG_RANDOMIZER_LEN: usize = 32;

/// Bytes of the one-time Ed25519 public key inside a token.
pub const EPH_PK_LEN: usize = 32;

/// Bytes of an epoch key's identifier.
pub const KEY_ID_LEN: usize = 32;

/// Bytes of an encoded token: `eph_pk || msg_randomizer || token_sig`.
pub const TOKEN_LEN: usize = EPH_PK_LEN + MSG_RANDOMIZER_LEN + TOKEN_KEY_LEN;

/// Domain of the issuer's Ed25519 signature over an epoch key.
pub const EPOCH_KEY_CERT_DOMAIN: &[u8] = b"veil-epoch-key-v1";

/// Domain of an epoch key's identifier.
pub const TOKEN_KEY_ID_DOMAIN: &[u8] = b"veil-token-key-v1";

/// Domain of the message an epoch key blind-signs.
pub const TOKEN_MSG_DOMAIN: &[u8] = b"veil-token-v1";

/// Domain of the AUTH v4 client signature over the TLS exporter. Distinct from
/// `AUTH_V3_SIG_DOMAIN` (`veil-auth-v1`).
pub const AUTH_V4_SIG_DOMAIN: &[u8] = b"veil-auth-v4";

/// Fixed part of a certificate blob: both window ends and the scope length byte.
const CERT_FIXED_LEN: usize = 8 + 8 + 1;

/// Why an AUTH v4 record was refused. Names the check, never the presented values:
/// the relay may log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthV4Reject {
    /// `now` lies outside the certificate's validity window.
    #[error("epoch key outside its window")]
    Expired,
    /// The certificate's scope is not accepted by this relay.
    #[error("epoch key scope not accepted here")]
    Scope,
    /// The certificate is not signed by the pinned issuer.
    #[error("epoch key certificate not signed by the issuer")]
    CertSignature,
    /// The modulus is not a usable 2048-bit RSA modulus.
    #[error("epoch key unusable")]
    Key,
    /// The token is not signed by the certificate's epoch key.
    #[error("token not signed by the epoch key")]
    TokenSignature,
    /// The exporter signature does not verify under the token's one-time key.
    #[error("exporter signature invalid")]
    ClientSignature,
}

/// Why a token could not be issued or finalized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// See [`CapabilityError`].
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    /// The certificate is not signed by the issuer the client trusts.
    #[error("epoch key certificate not signed by the issuer")]
    CertSignature,
    /// The RSA key is not a 2048-bit key with exponent 65537.
    #[error("epoch key must be RSA-{TOKEN_KEY_BITS} with e = 65537")]
    Key,
    /// The blind-RSA operation failed (malformed blinded message or signature, or a
    /// finalized signature that does not verify).
    #[error("blind RSA: {0}")]
    BlindRsa(String),
}

fn blind_rsa_err(e: blind_rsa_signatures::Error) -> TokenError {
    TokenError::BlindRsa(e.to_string())
}

/// `key_id` of the epoch key whose modulus is `modulus`.
pub fn token_key_id(modulus: &[u8; TOKEN_KEY_LEN]) -> [u8; KEY_ID_LEN] {
    let mut h = Sha256::new();
    h.update(TOKEN_KEY_ID_DOMAIN);
    h.update(modulus);
    h.finalize().into()
}

fn token_message(key_id: &[u8; KEY_ID_LEN], eph_pk: &[u8; EPH_PK_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(TOKEN_MSG_DOMAIN.len() + KEY_ID_LEN + EPH_PK_LEN);
    m.extend_from_slice(TOKEN_MSG_DOMAIN);
    m.extend_from_slice(key_id);
    m.extend_from_slice(eph_pk);
    m
}

fn client_sig_message(exporter: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_V4_SIG_DOMAIN.len() + exporter.len());
    m.extend_from_slice(AUTH_V4_SIG_DOMAIN);
    m.extend_from_slice(exporter);
    m
}

/// The RSA public key for `modulus`, or `None` unless it is exactly 2048 bits (top
/// bit set), odd and larger than the exponent.
fn public_key_from_modulus(modulus: &[u8; TOKEN_KEY_LEN]) -> Option<PublicKeySha384PSSRandomized> {
    if modulus[0] & 0x80 == 0 {
        return None;
    }
    let n = BoxedUint::from_be_slice(modulus, TOKEN_KEY_BITS as u32).ok()?;
    let e = BoxedUint::from(TOKEN_KEY_EXPONENT);
    // The top bit (checked above) gives the minimum; this gives the maximum, and odd n > e.
    let pk = RsaPublicKey::new_with_max_size(n, e, TOKEN_KEY_BITS).ok()?;
    Some(PublicKeySha384PSSRandomized::new(pk))
}

/// The issuer's Ed25519 certificate of one epoch key: its RSA modulus, the window it
/// is valid in, and the relay scope it is accepted on. Shared by every device of
/// the pool, so presenting it links nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeyCert {
    /// Unix seconds — the key is not accepted before this.
    pub not_before: u64,
    /// Unix seconds — the key is not accepted after this.
    pub not_after: u64,
    /// Relay scope the key is accepted on (empty = any), as [`scope_matches`].
    pub scope: String,
    /// The RSA modulus, big-endian, exactly [`TOKEN_KEY_BITS`] bits.
    pub modulus: [u8; TOKEN_KEY_LEN],
    /// Ed25519 signature by the issuer over the certificate message.
    pub sig: [u8; CAP_SIG_LEN],
}

impl EpochKeyCert {
    fn signing_message(
        not_before: u64,
        not_after: u64,
        scope: &str,
        modulus: &[u8; TOKEN_KEY_LEN],
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(
            EPOCH_KEY_CERT_DOMAIN.len() + CERT_FIXED_LEN + scope.len() + TOKEN_KEY_LEN,
        );
        m.extend_from_slice(EPOCH_KEY_CERT_DOMAIN);
        m.extend_from_slice(&not_before.to_le_bytes());
        m.extend_from_slice(&not_after.to_le_bytes());
        // The scope is followed by the modulus, so its length is signed too.
        m.push(scope.len() as u8);
        m.extend_from_slice(scope.as_bytes());
        m.extend_from_slice(modulus);
        m
    }

    /// Sign a certificate for `modulus` with the issuer's Ed25519 seed.
    pub fn sign(
        not_before: u64,
        not_after: u64,
        scope: String,
        modulus: [u8; TOKEN_KEY_LEN],
        issuer_seed: &[u8; 32],
    ) -> Result<Self, TokenError> {
        if scope.len() > MAX_SCOPE_LEN {
            return Err(CapabilityError::ScopeTooLong(scope.len()).into());
        }
        if public_key_from_modulus(&modulus).is_none() {
            return Err(TokenError::Key);
        }
        let msg = Self::signing_message(not_before, not_after, &scope, &modulus);
        let sig = SigningKey::from_bytes(issuer_seed).sign(&msg).to_bytes();
        Ok(Self {
            not_before,
            not_after,
            scope,
            modulus,
            sig,
        })
    }

    /// Whether the issuer whose Ed25519 public key is `issuer_pubkey` signed this.
    pub fn verify_signature(&self, issuer_pubkey: &[u8; 32]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(issuer_pubkey) else {
            return false;
        };
        if self.scope.len() > MAX_SCOPE_LEN {
            return false;
        }
        let msg =
            Self::signing_message(self.not_before, self.not_after, &self.scope, &self.modulus);
        vk.verify_strict(&msg, &Signature::from_bytes(&self.sig))
            .is_ok()
    }

    /// Whether the window contains `now_secs`.
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
    }

    /// This key's identifier, as signed inside every token.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        token_key_id(&self.modulus)
    }

    /// Encode the certificate blob.
    ///
    /// # Panics
    /// If `scope` was set longer than [`MAX_SCOPE_LEN`] after signing.
    pub fn encode(&self) -> Bytes {
        let scope = self.scope.as_bytes();
        assert!(
            scope.len() <= MAX_SCOPE_LEN,
            "epoch key scope is {} bytes; at most {MAX_SCOPE_LEN} fit the wire format",
            scope.len()
        );
        let mut buf = BytesMut::new();
        buf.put_u64_le(self.not_before);
        buf.put_u64_le(self.not_after);
        buf.put_u8(scope.len() as u8);
        buf.put_slice(scope);
        buf.put_slice(&self.modulus);
        buf.put_slice(&self.sig);
        buf.freeze()
    }

    /// Decode a certificate blob from the front of `data`. `None` on any malformation.
    pub fn decode(data: &mut impl Buf) -> Option<Self> {
        if data.remaining() < CERT_FIXED_LEN {
            return None;
        }
        let not_before = data.get_u64_le();
        let not_after = data.get_u64_le();
        let scope_len = data.get_u8() as usize;
        if data.remaining() < scope_len + TOKEN_KEY_LEN + CAP_SIG_LEN {
            return None;
        }
        let mut scope = vec![0u8; scope_len];
        data.copy_to_slice(&mut scope);
        let scope = String::from_utf8(scope).ok()?;
        let mut modulus = [0u8; TOKEN_KEY_LEN];
        data.copy_to_slice(&mut modulus);
        let mut sig = [0u8; CAP_SIG_LEN];
        data.copy_to_slice(&mut sig);
        Some(Self {
            not_before,
            not_after,
            scope,
            modulus,
            sig,
        })
    }
}

/// One epoch key with its secret half — the issuer's side. One per pool and epoch,
/// used for nothing but these tokens (RFC 9474 §6.2).
pub struct EpochKey {
    sk: SecretKeySha384PSSRandomized,
    cert: EpochKeyCert,
}

impl EpochKey {
    /// Generate a fresh RSA-2048 epoch key and certify it with the issuer's seed.
    /// Slow (prime generation, around a second): done once per pool and epoch.
    pub fn generate(
        not_before: u64,
        not_after: u64,
        scope: String,
        issuer_seed: &[u8; 32],
    ) -> Result<Self, TokenError> {
        let kp = KeyPairSha384PSSRandomized::generate(&mut DefaultRng, TOKEN_KEY_BITS)
            .map_err(blind_rsa_err)?;
        Self::from_secret_key(kp.sk, not_before, not_after, scope, issuer_seed)
    }

    /// Load an epoch key the issuer stored as PKCS#8 DER ([`Self::secret_key_der`])
    /// and certify it.
    pub fn from_pkcs8_der(
        der: &[u8],
        not_before: u64,
        not_after: u64,
        scope: String,
        issuer_seed: &[u8; 32],
    ) -> Result<Self, TokenError> {
        let sk = SecretKeySha384PSSRandomized::from_der(der).map_err(blind_rsa_err)?;
        Self::from_secret_key(sk, not_before, not_after, scope, issuer_seed)
    }

    fn from_secret_key(
        sk: SecretKeySha384PSSRandomized,
        not_before: u64,
        not_after: u64,
        scope: String,
        issuer_seed: &[u8; 32],
    ) -> Result<Self, TokenError> {
        let pk = sk.public_key().map_err(|_| TokenError::Key)?;
        let modulus: [u8; TOKEN_KEY_LEN] = pk
            .components()
            .n()
            .try_into()
            .map_err(|_| TokenError::Key)?;
        // The relay rebuilds the key from the modulus alone, with e = 65537: a key it
        // would rebuild differently (another exponent) is refused here, not there.
        if public_key_from_modulus(&modulus).as_ref() != Some(&pk) {
            return Err(TokenError::Key);
        }
        let cert = EpochKeyCert::sign(not_before, not_after, scope, modulus, issuer_seed)?;
        Ok(Self { sk, cert })
    }

    /// The secret key as PKCS#8 DER, for the issuer's storage. Wiped on drop.
    pub fn secret_key_der(&self) -> Result<Zeroizing<Vec<u8>>, TokenError> {
        self.sk.to_der().map(Zeroizing::new).map_err(blind_rsa_err)
    }

    /// The certificate the client receives with its tokens and presents in AUTH v4.
    pub fn cert(&self) -> &EpochKeyCert {
        &self.cert
    }

    /// Sign one blinded message (RFC 9474 BlindSign; the crate checks its result
    /// before returning it, §7.1). The issuer learns nothing about the token.
    pub fn blind_sign(&self, blinded: &[u8]) -> Result<[u8; TOKEN_KEY_LEN], TokenError> {
        let sig = self.sk.blind_sign(blinded).map_err(blind_rsa_err)?;
        sig.0
            .try_into()
            .map_err(|_| TokenError::BlindRsa("blind signature length".into()))
    }
}

/// A client's request for one token, between blinding and finalizing. Holds the
/// one-time key and the blinding secret; both are wiped on drop.
pub struct TokenRequest {
    cert: EpochKeyCert,
    pk: PublicKeySha384PSSRandomized,
    eph_sk: SigningKey,
    blinding: BlindingResult,
}

impl Drop for TokenRequest {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl TokenRequest {
    /// Zero the blinding secret: with it, the issuer's view of this request could be matched
    /// to the token. `SigningKey` zeroizes itself on drop (ed25519-dalek `zeroize` feature).
    fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.blinding.secret.0.zeroize();
    }

    /// Start one token under `cert`, after checking that `issuer_pubkey` signed it.
    /// Returns the request and the blinded message to send to the issuer.
    pub fn new(
        cert: &EpochKeyCert,
        issuer_pubkey: &[u8; 32],
    ) -> Result<(Self, [u8; TOKEN_KEY_LEN]), TokenError> {
        if !cert.verify_signature(issuer_pubkey) {
            return Err(TokenError::CertSignature);
        }
        let pk = public_key_from_modulus(&cert.modulus).ok_or(TokenError::Key)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        blind_rsa_signatures::reexports::rand::fill(&mut seed[..]);
        let eph_sk = SigningKey::from_bytes(&seed);
        let msg = token_message(&cert.key_id(), &eph_sk.verifying_key().to_bytes());
        let blinding = pk.blind(&mut DefaultRng, &msg).map_err(blind_rsa_err)?;
        let blinded: [u8; TOKEN_KEY_LEN] = blinding
            .blind_message
            .0
            .clone()
            .try_into()
            .map_err(|_| TokenError::BlindRsa("blinded message length".into()))?;
        Ok((
            Self {
                cert: cert.clone(),
                pk,
                eph_sk,
                blinding,
            },
            blinded,
        ))
    }

    /// Unblind the issuer's answer into a token. Fails unless the result verifies
    /// under the epoch key (the crate checks it).
    pub fn finalize(self, blind_sig: &[u8]) -> Result<AccessToken, TokenError> {
        let msg = token_message(&self.cert.key_id(), &self.eph_sk.verifying_key().to_bytes());
        let sig = self
            .pk
            .finalize(&BlindSignature(blind_sig.to_vec()), &self.blinding, &msg)
            .map_err(blind_rsa_err)?;
        let token_sig: [u8; TOKEN_KEY_LEN] = sig
            .0
            .try_into()
            .map_err(|_| TokenError::BlindRsa("signature length".into()))?;
        let msg_randomizer = self
            .blinding
            .msg_randomizer
            .as_ref()
            .ok_or_else(|| TokenError::BlindRsa("no message randomizer".into()))?
            .0;
        Ok(AccessToken {
            cert: self.cert.clone(),
            eph_sk: self.eph_sk.clone(),
            msg_randomizer,
            token_sig,
        })
    }
}

/// A finalized token the client holds until it spends it on one connection.
#[derive(Clone)]
pub struct AccessToken {
    /// The epoch key's certificate.
    pub cert: EpochKeyCert,
    eph_sk: SigningKey,
    msg_randomizer: [u8; MSG_RANDOMIZER_LEN],
    token_sig: [u8; TOKEN_KEY_LEN],
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the one-time key nor the token itself: either links a connection.
        f.debug_struct("AccessToken")
            .field("not_after", &self.cert.not_after)
            .finish_non_exhaustive()
    }
}

/// AUTH v4 record — what a relay receives on one connection.
#[derive(Debug, Clone)]
pub struct AuthRecordV4 {
    /// The epoch key's certificate (shared by the pool).
    pub cert: EpochKeyCert,
    /// The token's one-time Ed25519 public key.
    pub eph_pk: [u8; EPH_PK_LEN],
    /// RFC 9474 message randomizer of the token.
    pub msg_randomizer: [u8; MSG_RANDOMIZER_LEN],
    /// The epoch key's signature over the token message.
    pub token_sig: [u8; TOKEN_KEY_LEN],
    /// `Ed25519(eph_sk, AUTH_V4_SIG_DOMAIN || exporter)`.
    pub client_sig: [u8; CAP_SIG_LEN],
}

impl AuthRecordV4 {
    /// Spend `token` on the TLS session whose exporter is `exporter`.
    pub fn from_token(token: &AccessToken, exporter: &[u8; 32]) -> Self {
        let client_sig = token.eph_sk.sign(&client_sig_message(exporter)).to_bytes();
        Self {
            cert: token.cert.clone(),
            eph_pk: token.eph_sk.verifying_key().to_bytes(),
            msg_randomizer: token.msg_randomizer,
            token_sig: token.token_sig,
            client_sig,
        }
    }

    /// Full validation, offline: window and scope of the certificate, the issuer's
    /// signature on it, the epoch key's signature on the token, and the one-time
    /// key's signature on this session's exporter. The free checks run first.
    pub fn verify(
        &self,
        issuer_pubkey: &[u8; 32],
        relay_scope: &str,
        exporter: &[u8; 32],
        now_secs: u64,
    ) -> Result<(), AuthV4Reject> {
        let cert = &self.cert;
        if !cert.is_valid_at(now_secs) {
            return Err(AuthV4Reject::Expired);
        }
        if !scope_matches(&cert.scope, relay_scope) {
            return Err(AuthV4Reject::Scope);
        }
        if !cert.verify_signature(issuer_pubkey) {
            return Err(AuthV4Reject::CertSignature);
        }
        let pk = public_key_from_modulus(&cert.modulus).ok_or(AuthV4Reject::Key)?;
        let msg = token_message(&cert.key_id(), &self.eph_pk);
        pk.verify(
            &RsaSignature(self.token_sig.to_vec()),
            Some(MessageRandomizer(self.msg_randomizer)),
            &msg,
        )
        .map_err(|_| AuthV4Reject::TokenSignature)?;
        let vk =
            VerifyingKey::from_bytes(&self.eph_pk).map_err(|_| AuthV4Reject::ClientSignature)?;
        vk.verify_strict(
            &client_sig_message(exporter),
            &Signature::from_bytes(&self.client_sig),
        )
        .map_err(|_| AuthV4Reject::ClientSignature)
    }

    /// Encode the AUTH v4 *payload*; wrap it in `Frame::auth_v4` for the wire.
    pub fn encode_payload(&self) -> Bytes {
        let cert = self.cert.encode();
        let mut buf = BytesMut::with_capacity(cert.len() + TOKEN_LEN + CAP_SIG_LEN);
        buf.put_slice(&cert);
        buf.put_slice(&self.eph_pk);
        buf.put_slice(&self.msg_randomizer);
        buf.put_slice(&self.token_sig);
        buf.put_slice(&self.client_sig);
        buf.freeze()
    }

    /// Decode an AUTH v4 payload. `None` on any malformation, trailing bytes included.
    pub fn decode_payload(payload: &[u8]) -> Option<Self> {
        let mut buf = payload;
        let cert = EpochKeyCert::decode(&mut buf)?;
        if buf.remaining() != TOKEN_LEN + CAP_SIG_LEN {
            return None;
        }
        let mut eph_pk = [0u8; EPH_PK_LEN];
        buf.copy_to_slice(&mut eph_pk);
        let mut msg_randomizer = [0u8; MSG_RANDOMIZER_LEN];
        buf.copy_to_slice(&mut msg_randomizer);
        let mut token_sig = [0u8; TOKEN_KEY_LEN];
        buf.copy_to_slice(&mut token_sig);
        let mut client_sig = [0u8; CAP_SIG_LEN];
        buf.copy_to_slice(&mut client_sig);
        Some(Self {
            cert,
            eph_pk,
            msg_randomizer,
            token_sig,
            client_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only RSA-2048 keys (openssl genpkey, PKCS#8 DER): generating one per test would
    // cost seconds in a debug build.
    const KEY_A: &[u8] = include_bytes!("../tests/fixtures/token_key_a.p8.der");
    const KEY_B: &[u8] = include_bytes!("../tests/fixtures/token_key_b.p8.der");
    const ISSUER: [u8; 32] = [9u8; 32];
    const OTHER_ISSUER: [u8; 32] = [10u8; 32];
    const NOT_BEFORE: u64 = 1_000;
    const NOT_AFTER: u64 = 2_000;
    const NOW: u64 = 1_500;
    const EXPORTER: [u8; 32] = [0x42; 32];

    fn issuer_pk() -> [u8; 32] {
        crate::issuer_public_key(&ISSUER)
    }

    fn epoch_key(der: &[u8], scope: &str) -> EpochKey {
        EpochKey::from_pkcs8_der(der, NOT_BEFORE, NOT_AFTER, scope.into(), &ISSUER).unwrap()
    }

    /// One full issuance: blind on the client, sign on the issuer, finalize on the client.
    fn issue(key: &EpochKey) -> AccessToken {
        let (req, blinded) = TokenRequest::new(key.cert(), &issuer_pk()).unwrap();
        let blind_sig = key.blind_sign(&blinded).unwrap();
        req.finalize(&blind_sig).unwrap()
    }

    fn record(key: &EpochKey) -> AuthRecordV4 {
        AuthRecordV4::from_token(&issue(key), &EXPORTER)
    }

    fn verify(rec: &AuthRecordV4) -> Result<(), AuthV4Reject> {
        rec.verify(&issuer_pk(), "", &EXPORTER, NOW)
    }

    #[test]
    fn an_issued_token_spent_on_a_session_verifies_after_the_wire() {
        let rec = record(&epoch_key(KEY_A, ""));
        let wire = AuthRecordV4::decode_payload(&rec.encode_payload()).unwrap();
        assert_eq!(verify(&wire), Ok(()));
    }

    #[test]
    fn the_window_is_inclusive_at_both_ends_and_closed_outside() {
        let rec = record(&epoch_key(KEY_A, ""));
        let at = |now| rec.verify(&issuer_pk(), "", &EXPORTER, now);
        assert_eq!(at(NOT_BEFORE), Ok(()));
        assert_eq!(at(NOT_AFTER), Ok(()));
        assert_eq!(at(NOT_BEFORE - 1), Err(AuthV4Reject::Expired));
        assert_eq!(at(NOT_AFTER + 1), Err(AuthV4Reject::Expired));
    }

    #[test]
    fn the_scope_must_match_the_relay_unless_either_is_empty() {
        let scoped = record(&epoch_key(KEY_A, "pool-a"));
        let on = |rec: &AuthRecordV4, relay| rec.verify(&issuer_pk(), relay, &EXPORTER, NOW);
        assert_eq!(on(&scoped, "pool-a"), Ok(()));
        assert_eq!(on(&scoped, ""), Ok(()));
        assert_eq!(on(&scoped, "pool-b"), Err(AuthV4Reject::Scope));
        assert_eq!(on(&record(&epoch_key(KEY_A, "")), "pool-b"), Ok(()));
    }

    #[test]
    fn a_certificate_from_another_issuer_is_refused() {
        let rec = record(&epoch_key(KEY_A, ""));
        let other = crate::issuer_public_key(&OTHER_ISSUER);
        assert_eq!(
            rec.verify(&other, "", &EXPORTER, NOW),
            Err(AuthV4Reject::CertSignature)
        );
    }

    #[test]
    fn a_widened_window_or_changed_scope_breaks_the_certificate() {
        let mut rec = record(&epoch_key(KEY_A, "pool-a"));
        rec.cert.not_after = NOT_AFTER + 1;
        assert_eq!(verify(&rec), Err(AuthV4Reject::CertSignature));
        let mut rec = record(&epoch_key(KEY_A, "pool-a"));
        rec.cert.not_before = NOT_BEFORE - 1;
        assert_eq!(verify(&rec), Err(AuthV4Reject::CertSignature));
        let mut rec = record(&epoch_key(KEY_A, "pool-a"));
        rec.cert.scope = String::new();
        assert_eq!(verify(&rec), Err(AuthV4Reject::CertSignature));
    }

    #[test]
    fn a_token_of_one_epoch_key_does_not_verify_under_another() {
        let token_a = record(&epoch_key(KEY_A, ""));
        let mut rec = token_a.clone();
        rec.cert = epoch_key(KEY_B, "").cert().clone();
        assert_eq!(verify(&rec), Err(AuthV4Reject::TokenSignature));
    }

    #[test]
    fn every_token_field_is_under_the_epoch_key_signature() {
        let rec = record(&epoch_key(KEY_A, ""));
        let mut r = rec.clone();
        r.eph_pk = SigningKey::from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(verify(&r), Err(AuthV4Reject::TokenSignature));
        let mut r = rec.clone();
        r.msg_randomizer[0] ^= 1;
        assert_eq!(verify(&r), Err(AuthV4Reject::TokenSignature));
        let mut r = rec.clone();
        r.token_sig[TOKEN_KEY_LEN - 1] ^= 1;
        assert_eq!(verify(&r), Err(AuthV4Reject::TokenSignature));
    }

    #[test]
    fn the_token_signs_its_key_id_and_its_domain() {
        // A signature by the right key over the token message of another key id, or over the
        // bare (key id, eph_pk) without the domain, is not a token.
        let key = epoch_key(KEY_A, "");
        let eph = SigningKey::from_bytes(&[6u8; 32]);
        let eph_pk = eph.verifying_key().to_bytes();
        let sign_raw = |msg: &[u8]| {
            let pk = public_key_from_modulus(&key.cert().modulus).unwrap();
            let blinding = pk.blind(&mut DefaultRng, msg).unwrap();
            let bs = key.blind_sign(&blinding.blind_message.0).unwrap();
            let sig = pk
                .finalize(&BlindSignature(bs.to_vec()), &blinding, msg)
                .unwrap();
            (
                sig.0.try_into().unwrap(),
                blinding.msg_randomizer.unwrap().0,
            )
        };
        let client_sig = eph.sign(&client_sig_message(&EXPORTER)).to_bytes();
        let rec_for = |msg: &[u8]| {
            let (token_sig, msg_randomizer) = sign_raw(msg);
            AuthRecordV4 {
                cert: key.cert().clone(),
                eph_pk,
                msg_randomizer,
                token_sig,
                client_sig,
            }
        };
        assert_eq!(
            verify(&rec_for(&token_message(&key.cert().key_id(), &eph_pk))),
            Ok(())
        );
        let other_id = token_key_id(&epoch_key(KEY_B, "").cert().modulus);
        assert_eq!(
            verify(&rec_for(&token_message(&other_id, &eph_pk))),
            Err(AuthV4Reject::TokenSignature)
        );
        let mut bare = key.cert().key_id().to_vec();
        bare.extend_from_slice(&eph_pk);
        assert_eq!(verify(&rec_for(&bare)), Err(AuthV4Reject::TokenSignature));
    }

    #[test]
    fn the_record_is_bound_to_this_sessions_exporter() {
        let rec = record(&epoch_key(KEY_A, ""));
        assert_eq!(
            rec.verify(&issuer_pk(), "", &[0x43; 32], NOW),
            Err(AuthV4Reject::ClientSignature)
        );
        let mut r = rec.clone();
        r.client_sig[0] ^= 1;
        assert_eq!(verify(&r), Err(AuthV4Reject::ClientSignature));
    }

    #[test]
    fn the_client_signature_carries_the_v4_domain() {
        // The same one-time key signing the bare exporter (or under the v3 domain) is refused.
        let token = issue(&epoch_key(KEY_A, ""));
        let mut rec = AuthRecordV4::from_token(&token, &EXPORTER);
        rec.client_sig = token.eph_sk.sign(&EXPORTER).to_bytes();
        assert_eq!(verify(&rec), Err(AuthV4Reject::ClientSignature));
        let mut v3 = crate::AUTH_V3_SIG_DOMAIN.to_vec();
        v3.extend_from_slice(&EXPORTER);
        rec.client_sig = token.eph_sk.sign(&v3).to_bytes();
        assert_eq!(verify(&rec), Err(AuthV4Reject::ClientSignature));
    }

    #[test]
    fn the_client_refuses_a_certificate_its_issuer_did_not_sign() {
        let key = epoch_key(KEY_A, "");
        let other = crate::issuer_public_key(&OTHER_ISSUER);
        assert!(matches!(
            TokenRequest::new(key.cert(), &other),
            Err(TokenError::CertSignature)
        ));
    }

    #[test]
    fn finalize_refuses_a_blind_signature_that_does_not_unblind_to_a_token() {
        // The client's own check (RFC 9474 Finalize verifies): a corrupted answer, or one
        // computed with another key, never becomes a token the client would spend.
        let key = epoch_key(KEY_A, "");
        let (req, blinded) = TokenRequest::new(key.cert(), &issuer_pk()).unwrap();
        let mut sig = key.blind_sign(&blinded).unwrap();
        sig[TOKEN_KEY_LEN / 2] ^= 1;
        assert!(matches!(req.finalize(&sig), Err(TokenError::BlindRsa(_))));

        // Fixture A's modulus is larger than B's, so A signs any value blinded under B.
        let key_b = epoch_key(KEY_B, "");
        assert!(key.cert().modulus > key_b.cert().modulus, "fixture order");
        let (req, blinded) = TokenRequest::new(key_b.cert(), &issuer_pk()).unwrap();
        let by_a = key.blind_sign(&blinded).unwrap();
        assert!(matches!(req.finalize(&by_a), Err(TokenError::BlindRsa(_))));
    }

    #[test]
    fn two_tokens_never_repeat_a_one_time_value() {
        let key = epoch_key(KEY_A, "");
        let (a, b) = (record(&key), record(&key));
        assert_ne!(a.eph_pk, b.eph_pk);
        assert_ne!(a.msg_randomizer, b.msg_randomizer);
        assert_ne!(a.token_sig, b.token_sig);
        assert_eq!(a.cert, b.cert, "the certificate is the pool's, shared");
    }

    #[test]
    fn only_a_2048_bit_odd_modulus_is_a_key() {
        let good = epoch_key(KEY_A, "").cert().modulus;
        assert!(public_key_from_modulus(&good).is_some());
        let mut short = good;
        short[0] &= 0x7f; // 2047 bits
        assert!(public_key_from_modulus(&short).is_none());
        let mut even = good;
        even[TOKEN_KEY_LEN - 1] &= 0xfe;
        assert!(public_key_from_modulus(&even).is_none());
        assert_eq!(
            EpochKeyCert::sign(NOT_BEFORE, NOT_AFTER, String::new(), short, &ISSUER),
            Err(TokenError::Key)
        );
        // A relay refuses a certificate the issuer signed over a bad modulus by hand.
        let mut rec = record(&epoch_key(KEY_A, ""));
        rec.cert.modulus = even;
        let msg = EpochKeyCert::signing_message(NOT_BEFORE, NOT_AFTER, "", &even);
        rec.cert.sig = SigningKey::from_bytes(&ISSUER).sign(&msg).to_bytes();
        assert_eq!(verify(&rec), Err(AuthV4Reject::Key));
    }

    #[test]
    fn a_scope_longer_than_its_length_byte_is_not_certified() {
        let modulus = epoch_key(KEY_A, "").cert().modulus;
        let long = "x".repeat(MAX_SCOPE_LEN + 1);
        assert!(matches!(
            EpochKeyCert::sign(NOT_BEFORE, NOT_AFTER, long, modulus, &ISSUER),
            Err(TokenError::Capability(CapabilityError::ScopeTooLong(256)))
        ));
        let longest = EpochKeyCert::sign(
            NOT_BEFORE,
            NOT_AFTER,
            "x".repeat(MAX_SCOPE_LEN),
            modulus,
            &ISSUER,
        )
        .unwrap();
        assert!(longest.verify_signature(&issuer_pk()));
        // A scope grown past the length byte in memory, with the issuer's signature over the
        // wrapped length, still does not verify: the length byte would not name it.
        let wrapped = "x".repeat(MAX_SCOPE_LEN + 1);
        let msg = EpochKeyCert::signing_message(NOT_BEFORE, NOT_AFTER, &wrapped, &modulus);
        let forged = EpochKeyCert {
            scope: wrapped,
            sig: SigningKey::from_bytes(&ISSUER).sign(&msg).to_bytes(),
            ..longest
        };
        assert!(!forged.verify_signature(&issuer_pk()));
    }

    #[test]
    fn the_epoch_key_survives_the_issuers_storage() {
        let key = epoch_key(KEY_A, "");
        let der = key.secret_key_der().unwrap();
        let again =
            EpochKey::from_pkcs8_der(&der, NOT_BEFORE, NOT_AFTER, String::new(), &ISSUER).unwrap();
        assert_eq!(again.cert(), key.cert());
        // A token issued by the reloaded key verifies under the original certificate.
        let mut rec = record(&again);
        rec.cert = key.cert().clone();
        assert_eq!(verify(&rec), Ok(()));
    }

    #[test]
    fn decode_refuses_truncated_and_trailing_bytes() {
        let rec = record(&epoch_key(KEY_A, "pool"));
        let payload = rec.encode_payload();
        assert!(AuthRecordV4::decode_payload(&payload).is_some());
        // Every prefix, cuts inside the certificate's modulus and signature included: refused,
        // never a panic.
        for cut in 0..payload.len() {
            assert!(
                AuthRecordV4::decode_payload(&payload[..cut]).is_none(),
                "cut at {cut}"
            );
        }
        // A certificate blob alone, exactly its own length, decodes to itself.
        let blob = rec.cert.encode();
        let mut exact = &blob[..];
        assert_eq!(EpochKeyCert::decode(&mut exact), Some(rec.cert.clone()));
        assert!(exact.is_empty());
        assert_eq!(EpochKeyCert::decode(&mut &blob[..blob.len() - 1]), None);
        let mut long = payload.to_vec();
        long.push(0);
        assert!(AuthRecordV4::decode_payload(&long).is_none());
        // A scope that is not UTF-8.
        let mut bad = payload.to_vec();
        bad[CERT_FIXED_LEN] = 0xff;
        assert!(AuthRecordV4::decode_payload(&bad).is_none());
    }

    /// The layout, byte for byte, as the module docs give it — any reordering, width or
    /// domain change shows here, not first on a relay.
    #[test]
    fn the_wire_layout_is_the_documented_one() {
        let rec = AuthRecordV4 {
            cert: EpochKeyCert {
                not_before: 0x0102_0304_0506_0708,
                not_after: 0x1112_1314_1516_1718,
                scope: "ab".into(),
                modulus: [0xcc; TOKEN_KEY_LEN],
                sig: [0xdd; CAP_SIG_LEN],
            },
            eph_pk: [0xe1; EPH_PK_LEN],
            msg_randomizer: [0xe2; MSG_RANDOMIZER_LEN],
            token_sig: [0xe3; TOKEN_KEY_LEN],
            client_sig: [0xe4; CAP_SIG_LEN],
        };
        let mut want = vec![
            8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 2,
        ];
        want.extend_from_slice(b"ab");
        want.extend_from_slice(&[0xcc; TOKEN_KEY_LEN]);
        want.extend_from_slice(&[0xdd; CAP_SIG_LEN]);
        want.extend_from_slice(&[0xe1; EPH_PK_LEN]);
        want.extend_from_slice(&[0xe2; MSG_RANDOMIZER_LEN]);
        want.extend_from_slice(&[0xe3; TOKEN_KEY_LEN]);
        want.extend_from_slice(&[0xe4; CAP_SIG_LEN]);
        assert_eq!(rec.encode_payload().as_ref(), want.as_slice());
        assert_eq!(want.len(), 2 + 721, "721 bytes with an empty scope");

        let mut cert_msg = b"veil-epoch-key-v1".to_vec();
        cert_msg.extend_from_slice(&want[..17 + 2 + TOKEN_KEY_LEN]);
        assert_eq!(
            EpochKeyCert::signing_message(
                rec.cert.not_before,
                rec.cert.not_after,
                "ab",
                &rec.cert.modulus
            ),
            cert_msg
        );
        let mut id = Sha256::new();
        id.update(b"veil-token-key-v1");
        id.update([0xcc; TOKEN_KEY_LEN]);
        let id: [u8; 32] = id.finalize().into();
        assert_eq!(token_key_id(&[0xcc; TOKEN_KEY_LEN]), id);
        assert_eq!(
            rec.cert.key_id(),
            id,
            "a certificate's key id is its modulus's"
        );
        let mut tok = b"veil-token-v1".to_vec();
        tok.extend_from_slice(&id);
        tok.extend_from_slice(&[0xe1; EPH_PK_LEN]);
        assert_eq!(token_message(&id, &[0xe1; EPH_PK_LEN]), tok);
        let mut cs = b"veil-auth-v4".to_vec();
        cs.extend_from_slice(&EXPORTER);
        assert_eq!(client_sig_message(&EXPORTER), cs);
    }

    /// The rsa pre-release pin (Cargo.toml) is temporary: blind-rsa-signatures 0.18.0 does not
    /// build against rsa 0.10.0. This fails after the end date while the pin is still there —
    /// look for a blind-rsa-signatures release on rsa >= 0.10.0, drop the pin and the audit
    /// note, or move the date with a reason.
    #[test]
    fn the_rsa_pre_release_pin_has_an_end_date() {
        const END: u64 = 1_801_008_000; // 2027-01-27 00:00 UTC
        let pinned = include_str!("../Cargo.toml").contains("\"=0.10.0-rc.18\"");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            !(pinned && now > END),
            "rsa is still pinned to 0.10.0-rc.18 past its end date"
        );
    }

    #[test]
    fn a_token_prints_neither_its_key_nor_its_signature() {
        let token = issue(&epoch_key(KEY_A, ""));
        let shown = format!("{token:?}");
        let hex = |b: &[u8]| {
            b.iter()
                .map(|x| format!("{x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        assert!(!shown.contains(&hex(&token.eph_sk.to_bytes()[..4])));
        assert!(!shown.contains(&hex(&token.token_sig[..4])));
        assert!(
            !shown.contains("eph_sk") && !shown.contains("token_sig"),
            "{shown}"
        );
        assert!(
            shown.starts_with("AccessToken") && shown.contains("not_after"),
            "{shown}"
        );
    }

    #[test]
    fn a_request_wipes_its_blinding_secret() {
        let key = epoch_key(KEY_A, "");
        let (mut req, _) = TokenRequest::new(key.cert(), &issuer_pk()).unwrap();
        assert!(req.blinding.secret.0.iter().any(|&b| b != 0));
        req.wipe();
        assert!(req.blinding.secret.0.iter().all(|&b| b == 0));
    }
}
