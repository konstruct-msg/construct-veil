//! Auth record — session-bound authenticator sent in the first encrypted application record.
//!
//! # Protocol
//!
//! ```text
//! exp      = TLS-Exporter("construct veil-front auth v1", "", 32)   // RFC 8446 §7.5
//! authcode = HMAC-SHA256(auth_key, exp || ticket_id || not_after)
//! auth_rec = frame(0x00, ticket_id[16] || authcode[32])            // 48-byte payload
//! ```
//!
//! # Why this shape
//! - Handshake stays clean — no `veil-front` bits in TLS handshake
//! - Secret never on the wire — `auth_key` is only used as HMAC key
//! - **Replay-proof by construction** — `exp` differs every TLS session, so
//!   a captured `auth_rec` is useless on any new connection (stateless!)
//! - Ticket is fungible — `ticket_id` does not identify the client

use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::ticket::{Ticket, TICKET_ID_LEN};
use crate::varint::{decode_varint, encode_varint};
use crate::FRAME_TYPE_AUTH;

/// Length of the HMAC-SHA256 authcode in bytes.
pub const AUTHCODE_LEN: usize = 32;

/// Total payload length of an AUTH frame: ticket_id (16) + authcode (32).
pub const AUTH_PAYLOAD_LEN: usize = TICKET_ID_LEN + AUTHCODE_LEN;

/// An auth record parsed from the first application data of a TLS connection.
#[derive(Debug, Clone)]
pub struct AuthRecord {
    /// The ticket identifier (opaque server-side index).
    pub ticket_id: [u8; TICKET_ID_LEN],
    /// The HMAC authenticator. Must be compared with `ConstantTimeEq`.
    pub authcode: [u8; AUTHCODE_LEN],
}

impl AuthRecord {
    /// Build an auth record from a ticket and TLS exporter output.
    ///
    /// `exporter` must be exactly 32 bytes (the output of
    /// `Connection::export_keying_material(EXPORTER_LABEL, &[], 32)`).
    pub fn from_ticket(ticket: &Ticket, exporter: &[u8]) -> Self {
        assert_eq!(exporter.len(), 32, "exporter must be 32 bytes");

        let mut mac = Hmac::<Sha256>::new_from_slice(ticket.auth_key.as_bytes())
            .expect("HMAC-SHA256 accepts any key length");

        mac.update(exporter);
        mac.update(&ticket.ticket_id);
        mac.update(&ticket.not_after.to_le_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        let mut authcode = [0u8; AUTHCODE_LEN];
        authcode.copy_from_slice(&code_bytes);

        Self {
            ticket_id: ticket.ticket_id,
            authcode,
        }
    }

    /// Verify this auth record against the given ticket and exporter.
    ///
    /// Uses **constant-time comparison** — never `==` on the authcode bytes.
    /// Returns `true` if the authcode matches.
    pub fn verify(&self, ticket: &Ticket, exporter: &[u8]) -> bool {
        if self.ticket_id != ticket.ticket_id {
            return false;
        }

        let expected = Self::from_ticket(ticket, exporter);
        self.authcode.ct_eq(&expected.authcode).into()
    }

    /// Encode this auth record as a wire-format frame.
    ///
    /// Returns: `FRAME_TYPE_AUTH || varint(payload_len) || ticket_id || authcode`
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + 2 + AUTH_PAYLOAD_LEN);
        buf.put_u8(FRAME_TYPE_AUTH);
        encode_varint(AUTH_PAYLOAD_LEN as u64, &mut buf);
        buf.put_slice(&self.ticket_id);
        buf.put_slice(&self.authcode);
        buf.freeze()
    }

    /// Decode an auth record from a wire-format frame.
    ///
    /// Expects: `FRAME_TYPE_AUTH || varint(payload_len) || ticket_id[16] || authcode[32]`
    ///
    /// Returns `None` if the frame type is wrong, the payload is malformed,
    /// or there are not enough bytes.
    pub fn decode(data: &mut impl Buf) -> Option<Self> {
        // Check frame type.
        if !data.has_remaining() {
            return None;
        }
        let frame_type = data.get_u8();
        if frame_type != FRAME_TYPE_AUTH {
            return None;
        }

        // Decode payload length.
        let (payload_len, _) = decode_varint(data)?;
        if payload_len != AUTH_PAYLOAD_LEN as u64 {
            return None;
        }

        // Check we have enough bytes.
        if data.remaining() < AUTH_PAYLOAD_LEN {
            return None;
        }

        let mut ticket_id = [0u8; TICKET_ID_LEN];
        data.copy_to_slice(&mut ticket_id);

        let mut authcode = [0u8; AUTHCODE_LEN];
        data.copy_to_slice(&mut authcode);

        Some(Self {
            ticket_id,
            authcode,
        })
    }

    /// Decode an auth record from a byte slice.
    pub fn decode_slice(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        Self::decode(&mut buf)
    }
}

/// Verify an authcode against an expected value using constant-time comparison.
///
/// This is the **only** way authcode bytes should ever be compared.
/// Never use `==` on cryptographic byte arrays.
#[inline]
pub fn constant_time_verify(actual: &[u8; AUTHCODE_LEN], expected: &[u8; AUTHCODE_LEN]) -> bool {
    actual.ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::AuthKey;
    use crate::AUTH_KEY_LEN;
    use tokio_util::codec::{Decoder, Encoder};

    /// Create a test ticket with known values.
    fn make_test_ticket() -> Ticket {
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id[0] = 0xDE;
        ticket_id[1] = 0xAD;

        let mut auth_key = [0u8; AUTH_KEY_LEN];
        auth_key[0] = 0xBE;
        auth_key[1] = 0xEF;

        Ticket {
            ticket_id,
            auth_key: AuthKey::new(auth_key),
            not_before: 1_000_000,
            not_after: 1_000_000 + 6 * 3600,
            suite_id: 0x01,
        }
    }

    /// Create a fake 32-byte TLS exporter (deterministic for testing).
    fn make_test_exporter() -> [u8; 32] {
        let mut exp = [0u8; 32];
        exp[0] = 0xCA;
        exp[1] = 0xFE;
        exp
    }

    #[test]
    fn auth_record_from_ticket() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let auth = AuthRecord::from_ticket(&ticket, &exporter);

        // Deterministic: same inputs produce same output.
        let auth2 = AuthRecord::from_ticket(&ticket, &exporter);
        assert_eq!(auth.ticket_id, auth2.ticket_id);
        assert_eq!(auth.authcode, auth2.authcode);
    }

    #[test]
    fn auth_record_verify_success() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let auth = AuthRecord::from_ticket(&ticket, &exporter);

        assert!(auth.verify(&ticket, &exporter));
    }

    #[test]
    fn auth_record_verify_wrong_exporter() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let auth = AuthRecord::from_ticket(&ticket, &exporter);

        // Different exporter → different authcode → verification fails.
        let mut exporter2 = exporter;
        exporter2[0] ^= 0x01;

        assert!(!auth.verify(&ticket, &exporter2));
    }

    #[test]
    fn auth_record_replay_proof() {
        // Same ticket, two different "TLS sessions" (different exporters).
        let ticket = make_test_ticket();
        let exporter1 = make_test_exporter();
        let mut exporter2 = make_test_exporter();
        exporter2[31] = 0xFF; // different session

        let auth1 = AuthRecord::from_ticket(&ticket, &exporter1);
        let auth2 = AuthRecord::from_ticket(&ticket, &exporter2);

        // Authcodes must differ (replay protection).
        assert_ne!(auth1.authcode, auth2.authcode);

        // auth1 must NOT verify with exporter2 (and vice versa).
        assert!(!auth1.verify(&ticket, &exporter2));
        assert!(!auth2.verify(&ticket, &exporter1));
    }

    #[test]
    fn auth_record_bit_flip_fails() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let mut auth = AuthRecord::from_ticket(&ticket, &exporter);

        // Flip one bit in the authcode.
        auth.authcode[0] ^= 0x01;

        assert!(!auth.verify(&ticket, &exporter));
    }

    #[test]
    fn auth_record_encode_decode_roundtrip() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let auth = AuthRecord::from_ticket(&ticket, &exporter);

        let encoded = auth.encode();
        let mut buf = encoded.clone();
        let decoded = AuthRecord::decode(&mut buf).expect("decode failed");

        assert_eq!(decoded.ticket_id, auth.ticket_id);
        assert_eq!(decoded.authcode, auth.authcode);
    }

    #[test]
    fn auth_record_decode_wrong_type() {
        // DATA frame should not decode as AUTH.
        let mut buf = BytesMut::new();
        buf.put_u8(crate::FRAME_TYPE_DATA);
        encode_varint(AUTH_PAYLOAD_LEN as u64, &mut buf);
        buf.put_bytes(0, AUTH_PAYLOAD_LEN);

        let mut slice = buf.freeze();
        assert!(AuthRecord::decode(&mut slice).is_none());
    }

    #[test]
    fn auth_record_decode_truncated() {
        let ticket = make_test_ticket();
        let exporter = make_test_exporter();
        let auth = AuthRecord::from_ticket(&ticket, &exporter);

        let encoded = auth.encode();
        // Truncate to half the bytes.
        let truncated = &encoded[..encoded.len() / 2];

        assert!(AuthRecord::decode_slice(truncated).is_none());
    }

    #[test]
    fn frame_encode_decode_roundtrip() {
        // Use the framing module's Frame + codec.
        use crate::framing::{Frame, VeilFrontCodec};
        let payload = Bytes::from(&b"hello veil-front"[..]);
        let frame = Frame::data(payload.clone());

        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("frame expected");
        assert!(decoded.is_data());
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_payload_too_large() {
        use crate::framing::VeilFrontCodec;
        let mut codec = VeilFrontCodec::with_max_payload(50);
        let mut buf = BytesMut::new();
        buf.put_u8(crate::FRAME_TYPE_DATA);
        // Encode a payload length of 200 (above the 50 limit).
        encode_varint(200, &mut buf);
        buf.put_bytes(0, 200);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn constant_time_verify_correct() {
        let a = [0x42u8; AUTHCODE_LEN];
        let b = [0x42u8; AUTHCODE_LEN];
        assert!(constant_time_verify(&a, &b));
    }

    #[test]
    fn constant_time_verify_different() {
        let a = [0x42u8; AUTHCODE_LEN];
        let mut b = [0x42u8; AUTHCODE_LEN];
        b[0] = 0x43;
        assert!(!constant_time_verify(&a, &b));
    }

    #[test]
    fn chaff_frame_roundtrip() {
        use crate::framing::{Frame, VeilFrontCodec};
        let chaff_payload = Bytes::from(vec![0u8; 128]);
        let frame = Frame::chaff(chaff_payload.clone());

        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("decode failed");
        assert!(decoded.is_chaff());
        assert_eq!(decoded.payload, chaff_payload);
    }
}
