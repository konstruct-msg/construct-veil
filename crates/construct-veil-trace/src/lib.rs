//! What a capture of our traffic looks like to someone who cannot decrypt it.
//!
//! Every padding claim this project makes is a claim about shape: record sizes, their order, the
//! gaps between them. None of it has ever been measured — `mode0_front.rs` says "~33% overhead"
//! and "zero added latency (confirmed by on-device benchmark)", which is a latency measurement
//! answering a shape question. The external review (construct-docs
//! `decisions/veil-external-transport-review-2026-09` §2.8, §3.3) is blunt about the gap and about
//! the wrong way to close it: a Kolmogorov–Smirnov test that fails to reject is not evidence of
//! indistinguishability, and per-packet resampling of one connection is not a sample of size N.
//!
//! So this rig reports what an adversary would actually get, not a p-value:
//!
//! * the observable stream — TLS record lengths, directions and arrival times, recovered without
//!   any key, because the record header is cleartext;
//! * summaries per capture, so a human can look at a distribution before believing a number;
//! * the separation between two sets of captures, as the accuracy of the simplest classifiers an
//!   adversary would reach for. A number near 0.5 means those classifiers failed — which is a
//!   floor on nothing, only evidence that the cheap attack is not free.
//!
//! The unit of evidence is a connection, never a packet: packets inside one connection are not
//! independent draws, and treating them as such is how a rig talks itself into a result.

pub mod capture;
pub mod flow;
pub mod records;
pub mod stats;
