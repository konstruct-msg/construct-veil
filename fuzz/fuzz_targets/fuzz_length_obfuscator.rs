//! Fuzz target: SipHash OFB length obfuscator round-trip.
//!
//! Verifies that mask → unmask always recovers the original length,
//! regardless of key/IV material. Also tests that the OFB state machine
//! stays in sync across many operations.

#![no_main]

use arbitrary::Arbitrary;
use construct_ice::framing::length_dist::LengthObfuscator;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    siphash_key: [u8; 16],
    siphash_iv: [u8; 8],
    lengths: Vec<u16>,
}

fuzz_target!(|input: FuzzInput| {
    if input.lengths.len() > 1024 {
        return;
    }

    let mut encoder = LengthObfuscator::new(&input.siphash_key, &input.siphash_iv);
    let mut decoder = LengthObfuscator::new(&input.siphash_key, &input.siphash_iv);

    for &length in &input.lengths {
        let masked = encoder.mask_length(length);
        let recovered = decoder.unmask_length(&masked);
        assert_eq!(
            recovered, length,
            "Round-trip failed: mask({}) → unmask → {}",
            length, recovered
        );
    }
});
