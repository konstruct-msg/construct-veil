//! Regression tests for the 2026-10-22 audit, block 212 (protocol crate). Each
//! names the mutation that turns it red.

use bytes::BytesMut;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

use crate::*;

const SEED: [u8; 32] = [7u8; 32];
const EXPORTER: [u8; 32] = [0xCA; 32];
const NOW: u64 = 1_000_000 + 3600;

fn ticket(suite_id: u8) -> Ticket {
    Ticket {
        ticket_id: [0xAB; TICKET_ID_LEN],
        auth_key: AuthKey::new([0x42; AUTH_KEY_LEN]),
        not_before: 1_000_000,
        not_after: 1_000_000 + 86_400,
        suite_id,
    }
}

fn holder() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn cap_v2(scope: &str, suite_id: u8) -> CapabilityV2 {
    CapabilityV2::sign(
        [0xAB; TICKET_ID_LEN],
        holder().verifying_key().to_bytes(),
        ROLE_USER,
        1_000_000,
        1_000_000 + 86_400,
        suite_id,
        scope.into(),
        &SEED,
    )
    .unwrap()
}

// ── AuthKey ──────────────────────────────────────────────────────────────────

/// The key bytes are wiped when an `AuthKey` is dropped. Mutation: remove the
/// `Drop` impl (back to the bare `ZeroizeOnDrop` marker) — the bytes survive.
#[test]
#[allow(unsafe_code)]
fn auth_key_is_wiped_on_drop() {
    let mut slot = std::mem::ManuallyDrop::new(AuthKey::new([0x5A; AUTH_KEY_LEN]));
    // SAFETY: the value is dropped exactly once, in place; ManuallyDrop keeps
    // its storage alive, and `[u8; 32]` has no invalid bit patterns, so reading
    // the bytes back afterwards is sound.
    let bytes = unsafe {
        std::ptr::drop_in_place(&mut *slot);
        std::ptr::read(slot.as_bytes())
    };
    assert_eq!(bytes, [0u8; AUTH_KEY_LEN]);
}

// ── varint ───────────────────────────────────────────────────────────────────

/// Mutation: drop the overlong check — `80 00` decodes as 0.
#[test]
fn overlong_varints_are_malformed() {
    for bytes in [&[0x80u8, 0x00][..], &[0xFF, 0x00], &[0x81, 0x80, 0x00]] {
        assert_eq!(
            decode_varint_checked(&mut &bytes[..]),
            Varint::Malformed,
            "{bytes:02x?}"
        );
    }
}

/// Mutation: drop the 10th-byte check — `FF×9 7F` decodes to a truncated value.
#[test]
fn varints_past_u64_are_malformed() {
    let mut over = vec![0xFF; 9];
    over.push(0x7F);
    assert_eq!(decode_varint_checked(&mut &over[..]), Varint::Malformed);
    let mut eleven = vec![0xFF; 10];
    eleven.push(0x00);
    assert_eq!(decode_varint_checked(&mut &eleven[..]), Varint::Malformed);

    let mut max = Vec::new();
    encode_varint(u64::MAX, &mut max);
    assert_eq!(max.len(), VARINT_MAX_BYTES);
    assert_eq!(
        decode_varint_checked(&mut &max[..]),
        Varint::Value(u64::MAX, 10)
    );
}

#[test]
fn a_truncated_varint_is_incomplete_not_malformed() {
    assert_eq!(
        decode_varint_checked(&mut &[0x80u8][..]),
        Varint::Incomplete
    );
    assert_eq!(decode_varint_checked(&mut &[][..]), Varint::Incomplete);
}

proptest! {
    /// Every value round-trips, and the decoder accepts exactly the encoder's bytes.
    #[test]
    fn varint_round_trips(v in any::<u64>()) {
        let mut buf = Vec::new();
        let n = encode_varint(v, &mut buf);
        prop_assert_eq!(decode_varint_checked(&mut &buf[..]), Varint::Value(v, n));
        // Every strict prefix is merely incomplete.
        for cut in 0..buf.len() {
            prop_assert_eq!(decode_varint_checked(&mut &buf[..cut]), Varint::Incomplete);
        }
    }
}

// ── frame decoder ────────────────────────────────────────────────────────────

/// A header whose length varint can never complete is an error, not "wait for
/// more". Mutation: map `Varint::Malformed` to `Ok(None)` (the old behaviour) —
/// the decoder keeps asking for bytes forever.
#[test]
fn a_malformed_length_is_an_error_not_a_wait() {
    let mut codec = VeilFrontCodec::default();
    let mut src = BytesMut::from(&[WIRE_VER, FRAME_TYPE_DATA][..]);
    src.extend_from_slice(&[0xFF; 32]);
    assert!(codec.decode(&mut src).is_err());

    // Overlong pad_len after a valid payload_len.
    let mut src = BytesMut::from(&[WIRE_VER, FRAME_TYPE_DATA, 0x01, 0x80, 0x00][..]);
    assert!(codec.decode(&mut src).is_err());
}

#[test]
fn an_oversized_length_is_an_error() {
    let mut codec = VeilFrontCodec::default();
    let mut src = BytesMut::from(&[WIRE_VER, FRAME_TYPE_DATA][..]);
    let mut len = Vec::new();
    encode_varint(u64::MAX, &mut len);
    src.extend_from_slice(&len);
    src.extend_from_slice(&[0x00]);
    assert!(codec.decode(&mut src).is_err());
}

fn encode_all(frames: &[Frame]) -> BytesMut {
    let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    let mut buf = BytesMut::new();
    for f in frames {
        codec.encode(f.clone(), &mut buf).unwrap();
    }
    buf
}

fn decode_all(chunks: &[&[u8]]) -> Result<Vec<Frame>, std::io::Error> {
    let mut codec = VeilFrontCodec::default();
    let mut src = BytesMut::new();
    let mut out = Vec::new();
    for chunk in chunks {
        src.extend_from_slice(chunk);
        while let Some(f) = codec.decode(&mut src)? {
            out.push(f);
        }
    }
    Ok(out)
}

proptest! {
    /// Arbitrary bytes never panic the decoder.
    #[test]
    fn the_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_all(&[&bytes]);
    }

    /// However the wire is split into reads, the same frames come out.
    #[test]
    fn frames_survive_any_split(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 1..5),
        cut in any::<prop::sample::Index>(),
    ) {
        let frames: Vec<Frame> = payloads.into_iter().map(Frame::data_vec).collect();
        let wire = encode_all(&frames);
        let at = cut.index(wire.len() + 1);
        let (a, b) = wire.split_at(at);
        let decoded = decode_all(&[a, b]).unwrap();
        prop_assert_eq!(decoded, frames);
    }
}

// ── capabilities ─────────────────────────────────────────────────────────────

/// Mutation: drop `check_scope_len` from `sign` — a 256-byte scope is signed and
/// encodes with a wrapped length byte.
#[test]
fn a_scope_longer_than_the_length_byte_is_refused() {
    let long = "s".repeat(MAX_SCOPE_LEN + 1);
    assert_eq!(
        Capability::sign(ticket(SUITE_CLASSIC_V1), long.clone(), &SEED).unwrap_err(),
        CapabilityError::ScopeTooLong(MAX_SCOPE_LEN + 1)
    );
    assert!(
        CapabilityV2::sign(
            [0; TICKET_ID_LEN],
            [0; VEIL_PK_LEN],
            ROLE_USER,
            0,
            1,
            SUITE_CLASSIC_V1,
            long,
            &SEED
        )
        .is_err()
    );
    // The longest scope that fits still round-trips.
    let max = "s".repeat(MAX_SCOPE_LEN);
    let cap = Capability::sign(ticket(SUITE_CLASSIC_V1), max.clone(), &SEED).unwrap();
    assert_eq!(Capability::decode_slice(&cap.encode()).unwrap().scope, max);
}

/// The panic must not depend on the build profile. Mutation: back to
/// `debug_assert!` — red only under `cargo test --release` (verified); in a debug
/// run `debug_assert!` panics too, so CI's debug tests cannot tell them apart.
#[test]
#[should_panic(expected = "fit the wire format")]
fn encoding_a_scope_grown_after_signing_panics() {
    let mut cap = Capability::sign(ticket(SUITE_CLASSIC_V1), String::new(), &SEED).unwrap();
    cap.scope = "s".repeat(MAX_SCOPE_LEN + 1);
    let _ = cap.encode();
}

/// Scope is enforced by `verify` itself. Mutation: remove `scope_matches` from
/// `AuthRecordV2::verify` / `AuthRecordV3::verify`.
#[test]
fn verify_enforces_the_scope() {
    let pk = issuer_public_key(&SEED);

    let v2 = AuthRecordV2::from_capability(
        &Capability::sign(ticket(SUITE_CLASSIC_V1), "ru-a".into(), &SEED).unwrap(),
        &EXPORTER,
    );
    assert!(v2.verify(&pk, "ru-a", &EXPORTER, NOW));
    assert!(
        v2.verify(&pk, "", &EXPORTER, NOW),
        "an empty relay scope is a wildcard"
    );
    assert!(!v2.verify(&pk, "ru-b", &EXPORTER, NOW));

    let v3 = AuthRecordV3::from_capability(&cap_v2("ru-a", SUITE_CLASSIC_V1), &holder(), &EXPORTER);
    assert!(v3.verify(&pk, "ru-a", ROLE_USER, &EXPORTER, NOW));
    assert!(!v3.verify(&pk, "ru-b", ROLE_USER, &EXPORTER, NOW));

    // An empty capability scope is a wildcard on any relay.
    let any = AuthRecordV3::from_capability(&cap_v2("", SUITE_CLASSIC_V1), &holder(), &EXPORTER);
    assert!(any.verify(&pk, "ru-b", ROLE_USER, &EXPORTER, NOW));
}

/// The suite id is signed and now checked. Mutation: remove the
/// `SUITE_CLASSIC_V1` comparison from either `verify`.
#[test]
fn verify_rejects_an_unknown_suite() {
    let pk = issuer_public_key(&SEED);
    let v2 = AuthRecordV2::from_capability(
        &Capability::sign(ticket(0x7F), String::new(), &SEED).unwrap(),
        &EXPORTER,
    );
    assert!(!v2.verify(&pk, "", &EXPORTER, NOW));
    let v3 = AuthRecordV3::from_capability(&cap_v2("", 0x7F), &holder(), &EXPORTER);
    assert!(!v3.verify(&pk, "", ROLE_USER, &EXPORTER, NOW));
}
