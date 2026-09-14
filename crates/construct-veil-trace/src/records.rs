//! TLS records out of a plaintext byte stream — the layer an on-path observer actually sees.
//!
//! The record header is not encrypted: one byte of content type, two of legacy version, two of
//! length. That is enough to recover, without any key, the sequence of record sizes and the moment
//! each one completed — the exact inputs every shape claim in this project is about.
//!
//! Under TLS 1.3 the content type on the wire is always `application_data` (23) once the handshake
//! is past, because the real type is inside the encrypted body. So the type tells us where the
//! handshake ends and nothing after that; the length and the clock carry the information.

use serde::{Deserialize, Serialize};

/// TLS content types as they appear on the wire.
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// The largest a TLS record may claim to be (RFC 8446 §5.1: 2^14 plus AEAD expansion).
const MAX_RECORD_LEN: usize = (1 << 14) + 256;

/// Which way a record travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Client to server.
    Up,
    /// Server to client.
    Down,
}

/// One record as an observer would tally it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Capture time of the packet that completed the record, in seconds.
    pub t: f64,
    pub dir: Direction,
    /// Bytes on the wire, header included — that is what costs and what is counted.
    pub len: usize,
    /// Wire content type. Always 23 after the handshake under TLS 1.3.
    pub ct: u8,
}

impl Record {
    /// Whether this record carries application data rather than handshake bookkeeping.
    pub fn is_application(&self) -> bool {
        self.ct == CT_APPLICATION_DATA
    }
}

/// Walks one direction's byte stream, emitting records as they complete.
#[derive(Debug, Default)]
pub struct RecordFramer {
    buf: Vec<u8>,
    desynced: bool,
}

impl RecordFramer {
    /// Feeds contiguous bytes that became available at `timestamp`.
    ///
    /// A record is reported at the timestamp of the segment that completed it, not the one that
    /// started it: a record split across two packets is only observable once its last byte lands.
    pub fn push(&mut self, bytes: &[u8], timestamp: f64, dir: Direction, out: &mut Vec<Record>) {
        if self.desynced {
            return;
        }
        self.buf.extend_from_slice(bytes);

        loop {
            if self.buf.len() < 5 {
                return;
            }
            let ct = self.buf[0];
            let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;

            // A header that cannot be a TLS record means the stream is not what we think it is —
            // a missed gap, a proxy, the wrong port. Stop rather than emit invented lengths.
            if !matches!(ct, CT_CHANGE_CIPHER_SPEC | CT_ALERT | CT_HANDSHAKE | CT_APPLICATION_DATA)
                || len > MAX_RECORD_LEN
            {
                self.desynced = true;
                return;
            }

            let total = 5 + len;
            if self.buf.len() < total {
                return; // record still in flight
            }
            out.push(Record { t: timestamp, dir, len: total, ct });
            self.buf.drain(..total);
        }
    }

    /// Whether framing gave up on this direction. A desynced direction must not be summarised.
    pub fn desynced(&self) -> bool {
        self.desynced
    }

    /// Bytes held for a record that never completed.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ct: u8, len: usize) -> Vec<u8> {
        let mut v = vec![ct, 0x03, 0x03];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.extend(std::iter::repeat_n(0xAA, len));
        v
    }

    #[test]
    fn back_to_back_records_are_counted_with_their_headers() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();
        let mut wire = record(CT_APPLICATION_DATA, 100);
        wire.extend(record(CT_APPLICATION_DATA, 40));

        f.push(&wire, 1.0, Direction::Up, &mut out);

        assert_eq!(out.iter().map(|r| r.len).collect::<Vec<_>>(), vec![105, 45]);
    }

    /// The point of timing a record by its last byte: an observer cannot see a record until it is
    /// complete, so a record spanning two packets is an event at the second one.
    #[test]
    fn a_record_split_across_packets_is_timed_by_its_completion() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();
        let wire = record(CT_APPLICATION_DATA, 100);

        f.push(&wire[..50], 1.0, Direction::Down, &mut out);
        assert!(out.is_empty(), "half a record is not an event");
        f.push(&wire[50..], 2.5, Direction::Down, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].t, 2.5);
        assert_eq!(out[0].len, 105);
    }

    /// Several records coalesced into one packet are still several records. This is the case the
    /// whole rig exists for: `max_fragment_size` is what stops the client doing this, and losing
    /// it is the open cost of moving to Apple's TLS stack.
    #[test]
    fn coalesced_records_in_one_packet_stay_separate() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();
        let mut wire = Vec::new();
        for len in [256, 256, 1024] {
            wire.extend(record(CT_APPLICATION_DATA, len));
        }

        f.push(&wire, 1.0, Direction::Up, &mut out);

        assert_eq!(out.iter().map(|r| r.len).collect::<Vec<_>>(), vec![261, 261, 1029]);
    }

    #[test]
    fn the_handshake_is_distinguishable_from_what_follows() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();
        let mut wire = record(CT_HANDSHAKE, 300);
        wire.extend(record(CT_APPLICATION_DATA, 64));

        f.push(&wire, 1.0, Direction::Up, &mut out);

        assert!(!out[0].is_application());
        assert!(out[1].is_application());
    }

    /// Garbage must stop the framer. Inventing lengths from a desynced stream would produce a
    /// distribution that looks like a finding.
    #[test]
    fn an_impossible_header_desyncs_instead_of_inventing_records() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();

        f.push(&[0x47, 0x45, 0x54, 0x20, 0x2f], 1.0, Direction::Up, &mut out);

        assert!(f.desynced(), "\"GET /\" is not a TLS record");
        assert!(out.is_empty());
    }

    #[test]
    fn an_oversized_length_desyncs() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();

        f.push(&[CT_APPLICATION_DATA, 3, 3, 0xFF, 0xFF], 1.0, Direction::Up, &mut out);

        assert!(f.desynced());
    }

    #[test]
    fn an_incomplete_trailing_record_is_reported_as_pending() {
        let mut f = RecordFramer::default();
        let mut out = Vec::new();
        let wire = record(CT_APPLICATION_DATA, 100);

        f.push(&wire[..30], 1.0, Direction::Up, &mut out);

        assert_eq!(out.len(), 0);
        assert_eq!(f.pending(), 30);
    }
}
