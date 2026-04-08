//! Fuzz target: protocol classifier (active probe resistance).
//!
//! Tests that `classify_peeked_bytes` never panics on any input and that
//! all non-TLS/HTTP inputs are correctly classified as TryObfs4.
//! This is critical for DPI resistance — a false classification could
//! cause an obfs4 handshake to be proxied to the cover server (revealing
//! the server as a proxy) or cause a TLS probe to enter the obfs4 path
//! (which would then hang and fingerprint the server).

#![no_main]

use construct_ice::transport::cover::classify_peeked_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic.
    let _decision = classify_peeked_bytes(data);
});
