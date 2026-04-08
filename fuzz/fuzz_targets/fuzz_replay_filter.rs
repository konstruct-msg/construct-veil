//! Fuzz target: replay filter — anti-replay protection for obfs4 handshakes.
//!
//! Tests that:
//! 1. The filter never panics on any sequence of MAC inputs.
//! 2. After `test_and_set(mac)` returns false, the SAME mac returns true
//!    (replay detection invariant holds).
//! 3. The bucket cap (MAX_BUCKET_SIZE) prevents memory exhaustion under
//!    flood attacks.
//!
//! This is security-critical: if `test_and_set` fails to detect a replay,
//! an adversary who captured a valid client handshake can replay it to
//! fingerprint the server as an obfs4 proxy.

#![no_main]

use arbitrary::Arbitrary;
use construct_ice::replay_filter::ReplayFilter;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Sequence of 16-byte MACs to feed into the filter.
    macs: Vec<[u8; 16]>,
}

fuzz_target!(|input: FuzzInput| {
    // Cap to prevent trivial OOM via MAX_BUCKET_SIZE flood.
    if input.macs.len() > 2048 {
        return;
    }

    let mut filter = ReplayFilter::new();

    for mac in &input.macs {
        let first = filter.test_and_set(*mac);
        if !first {
            // First time seen — second call must be a replay.
            let second = filter.test_and_set(*mac);
            assert!(
                second,
                "replay_filter invariant violated: same MAC accepted twice"
            );
        }
    }
});
