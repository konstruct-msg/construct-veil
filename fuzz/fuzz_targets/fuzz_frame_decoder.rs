//! Fuzz target: obfs4 frame decoder state machine.
//!
//! Simulates receiving arbitrary bytes from a network stream and feeding
//! them into the FrameDecoder in chunks. Tests for panics, infinite loops,
//! and buffer overflows in the decode pipeline.
//!
//! The decoder normally receives authenticated ciphertext, but an adversary
//! (or DPI probe) can send anything. This target ensures no crashes occur
//! regardless of input.

#![no_main]

use arbitrary::Arbitrary;
use construct_ice::framing::decoder::{DecodedFrame, FrameDecoder};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Session key material (normally from ntor handshake KDF).
    key: [u8; 32],
    nonce_prefix: [u8; 16],
    siphash_key: [u8; 16],
    siphash_iv: [u8; 8],
    /// Raw "network" bytes to feed into the decoder.
    wire_data: Vec<u8>,
    /// Split points: feed wire_data in chunks at these positions.
    splits: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    if input.wire_data.len() > 16384 {
        return;
    }

    let mut decoder = FrameDecoder::new(
        &input.key,
        &input.nonce_prefix,
        &input.siphash_key,
        &input.siphash_iv,
    );

    // Compute split points as positions within wire_data.
    let mut positions: Vec<usize> = input
        .splits
        .iter()
        .map(|&s| (s as usize) % (input.wire_data.len().max(1)))
        .collect();
    positions.sort_unstable();
    positions.dedup();
    positions.push(input.wire_data.len());

    let mut prev = 0;
    for pos in positions {
        if pos <= prev {
            continue;
        }
        let chunk = &input.wire_data[prev..pos];
        decoder.feed(chunk);
        prev = pos;

        // Try decoding after each chunk (incremental parsing).
        // Limit iterations to prevent infinite decode loops.
        for _ in 0..64 {
            match decoder.decode_frame() {
                Ok(Some(DecodedFrame::Payload(_))) => {}
                Ok(Some(DecodedFrame::PrngSeed(_))) => {}
                Ok(None) => break,   // need more data
                Err(_) => return,    // protocol error — fine
            }
        }
    }
});
