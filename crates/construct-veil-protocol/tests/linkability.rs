//! What a relay sees in AUTH: does anything repeat across two connections of one device?
//!
//! The rule (construct-docs decisions/veil-relay-sees-no-stable-device-id.md §1): no hop sees a
//! value that is the same in two connections of one device, except values shared by many devices.
//! The relay terminates TLS, so it reads the whole AUTH frame. A run of 8 bytes or more common to
//! two connections' frames is a label it can link them by.
//!
//! AUTH v3 breaks the rule by design — `veil_pk` (one per install) and `ticket_id` (one per
//! capability) ride in every frame — and `auth_v3_links_two_connections_of_one_device` pins that,
//! so the stand shows exactly what is linkable. AUTH v4 (todo 311) adds the test that nothing is;
//! the v3 test goes when v3 does.

use bytes::BytesMut;
use construct_veil_protocol::{AuthRecordV3, CapabilityV2, Frame, ROLE_USER, VeilFrontCodec};
use ed25519_dalek::SigningKey;
use tokio_util::codec::Encoder;

/// The shortest common run that counts as a label. Shorter runs occur by chance between any two
/// random strings of this size; 8 bytes do not (2^-64 per position pair).
const LABEL: usize = 8;

/// The longest run of bytes common to `a` and `b` (classic DP, O(len(a)·len(b))), with where it
/// starts in `a`.
fn longest_common_run(a: &[u8], b: &[u8]) -> (usize, usize) {
    let mut prev = vec![0usize; b.len() + 1];
    let (mut best, mut at) = (0, 0);
    for (i, &x) in a.iter().enumerate() {
        let mut cur = vec![0usize; b.len() + 1];
        for (j, &y) in b.iter().enumerate() {
            if x == y {
                cur[j + 1] = prev[j] + 1;
                if cur[j + 1] > best {
                    best = cur[j + 1];
                    at = i + 1 - best;
                }
            }
        }
        prev = cur;
    }
    (best, at)
}

/// Every run of at least [`LABEL`] bytes of `needle` that also occurs in `hay`.
fn contains_run_of(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() >= LABEL
        && hay
            .windows(LABEL)
            .any(|w| needle.windows(LABEL).any(|n| n == w))
}

/// The bytes a relay reads after its TLS: the encoded AUTH v3 frame of `device` over `exporter`.
fn auth_v3_wire(device: &SigningKey, ticket_id: [u8; 16], exporter: [u8; 32]) -> Vec<u8> {
    let cap = CapabilityV2::sign(
        ticket_id,
        device.verifying_key().to_bytes(),
        ROLE_USER,
        0,
        u64::MAX,
        1,
        String::new(),
        &[7u8; 32],
    )
    .unwrap();
    let rec = AuthRecordV3::from_capability(&cap, device, &exporter);
    let mut buf = BytesMut::new();
    VeilFrontCodec::default()
        .encode(Frame::auth_v3(rec.encode_payload()), &mut buf)
        .unwrap();
    buf.to_vec()
}

/// The detector finds a planted label and nothing in two independent random strings.
#[test]
fn the_detector_finds_a_planted_label_and_no_chance_one() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let (mut a, mut b) = (vec![0u8; 400], vec![0u8; 400]);
    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);
    assert!(
        longest_common_run(&a, &b).0 < LABEL,
        "independent random strings"
    );
    b[100..100 + LABEL].copy_from_slice(&a[300..300 + LABEL]);
    assert_eq!(longest_common_run(&a, &b), (LABEL, 300));
}

/// Two connections of one install under AUTH v3: the relay reads `veil_pk` and `ticket_id` in
/// both. This is the defect todo 311 removes; the test fails the day v3 stops carrying them —
/// replace it then with the v4 test that nothing is common.
#[test]
fn auth_v3_links_two_connections_of_one_device() {
    let device = SigningKey::from_bytes(&[3u8; 32]);
    let ticket_id = [0x5au8; 16];
    let first = auth_v3_wire(&device, ticket_id, [0x01; 32]);
    let second = auth_v3_wire(&device, ticket_id, [0x02; 32]);

    let (run, _) = longest_common_run(&first, &second);
    assert!(
        run >= LABEL,
        "nothing common — has v3 changed? ({run} bytes)"
    );
    assert!(
        contains_run_of(&second, &device.verifying_key().to_bytes()),
        "veil_pk is in both"
    );
    assert!(contains_run_of(&second, &ticket_id), "ticket_id is in both");
    assert!(contains_run_of(&first, &device.verifying_key().to_bytes()));
    assert!(contains_run_of(&first, &ticket_id));

    // Two devices on the same capability window share nothing device-specific: only what every
    // AUTH v3 frame carries (frame header, the issuer's fixed fields) may repeat, and that is
    // shorter than the per-device values above.
    let other = SigningKey::from_bytes(&[4u8; 32]);
    let theirs = auth_v3_wire(&other, [0xa5u8; 16], [0x02; 32]);
    assert!(!contains_run_of(
        &theirs,
        &device.verifying_key().to_bytes()
    ));
    assert!(!contains_run_of(&theirs, &ticket_id));
}
