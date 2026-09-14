//! Putting one TCP direction back into the byte stream the TLS layer wrote.
//!
//! Deliberately small. A capture of our own connection on a quiet link is nearly always in order,
//! so the job is to be *honest* about the cases that are not, rather than to reimplement a stack:
//! a retransmit must not duplicate bytes, a reordered segment must not truncate the stream, and a
//! gap we cannot fill must be reported instead of silently concatenated — a hidden gap shifts every
//! following record boundary and turns the whole trace into plausible nonsense.

use std::collections::BTreeMap;

/// One direction of one TCP connection, identified the usual way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// A byte run handed to the TLS framer, with the capture time of the packet that completed it.
#[derive(Debug, Clone, PartialEq)]
pub struct Segment {
    pub timestamp: f64,
    pub bytes: Vec<u8>,
}

/// Why a direction stopped producing trustworthy bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gap {
    /// Bytes were lost from the capture (not from the network) and the stream cannot be continued.
    Missing { at: u32 },
}

/// Reassembles one direction.
#[derive(Debug, Default)]
pub struct Reassembler {
    next_seq: Option<u32>,
    held: BTreeMap<u32, Vec<u8>>,
    /// Bytes held out of order, so a pathological capture cannot grow this without bound.
    held_bytes: usize,
    gap: Option<Gap>,
}

impl Reassembler {
    /// Out-of-order bytes we are willing to hold before declaring the stream broken. A real
    /// reorder is a segment or two; anything beyond this is a capture we should not be trusting.
    pub const MAX_HELD_BYTES: usize = 1 << 20;

    /// Offers one TCP segment. Returns the bytes that are now contiguous, oldest first.
    ///
    /// The returned timestamp is the capture time of the packet that made those bytes available —
    /// the moment the data existed on the wire, which is what an observer keys on.
    pub fn push(&mut self, seq: u32, payload: &[u8], timestamp: f64) -> Option<Segment> {
        if self.gap.is_some() || payload.is_empty() {
            return None;
        }

        let next = *self.next_seq.get_or_insert(seq);

        // Wholly before what we have already emitted: a retransmit, drop it.
        if seq_lt(seq.wrapping_add(payload.len() as u32), next) || seq.wrapping_add(payload.len() as u32) == next {
            return None;
        }

        let mut out: Vec<u8> = Vec::new();
        if seq_lt(seq, next) {
            // Partial retransmit: keep only the part we have not seen.
            let already = next.wrapping_sub(seq) as usize;
            out.extend_from_slice(&payload[already.min(payload.len())..]);
        } else if seq == next {
            out.extend_from_slice(payload);
        } else {
            // Ahead of the stream — hold it and wait for the hole to be filled.
            self.held_bytes += payload.len();
            if self.held_bytes > Self::MAX_HELD_BYTES {
                self.gap = Some(Gap::Missing { at: next });
                return None;
            }
            self.held.entry(seq).or_insert_with(|| payload.to_vec());
            return None;
        }

        let mut cursor = next.wrapping_add(out.len() as u32);
        while let Some((&seq_held, _)) = self.held.range(..).next() {
            if seq_lt(cursor, seq_held) {
                break; // still a hole
            }
            let held = self.held.remove(&seq_held).expect("just inspected");
            self.held_bytes -= held.len();
            let skip = cursor.wrapping_sub(seq_held) as usize;
            if skip < held.len() {
                out.extend_from_slice(&held[skip..]);
                cursor = cursor.wrapping_add((held.len() - skip) as u32);
            }
        }

        self.next_seq = Some(cursor);
        if out.is_empty() {
            None
        } else {
            Some(Segment { timestamp, bytes: out })
        }
    }

    /// The gap that stopped this direction, if one did.
    pub fn gap(&self) -> Option<Gap> {
        self.gap
    }
}

/// Sequence-number comparison that survives the 32-bit wrap (RFC 1982).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_segments_pass_straight_through() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(100, b"abc", 1.0).unwrap().bytes, b"abc");
        assert_eq!(r.push(103, b"de", 2.0).unwrap().bytes, b"de");
    }

    /// A retransmit must not duplicate bytes: duplicated bytes become phantom TLS records, and a
    /// phantom record is exactly the kind of artefact that would look like padding.
    #[test]
    fn a_full_retransmit_is_dropped() {
        let mut r = Reassembler::default();
        r.push(100, b"abc", 1.0).unwrap();
        assert!(r.push(100, b"abc", 1.5).is_none());
        assert_eq!(r.push(103, b"d", 2.0).unwrap().bytes, b"d");
    }

    /// A partial retransmit overlaps the stream; only the new tail may be emitted.
    #[test]
    fn a_partial_retransmit_contributes_only_its_new_bytes() {
        let mut r = Reassembler::default();
        r.push(100, b"abc", 1.0).unwrap();
        assert_eq!(r.push(102, b"cde", 2.0).unwrap().bytes, b"de");
    }

    /// Reordering is the case where a naive parser silently truncates. The held segment must be
    /// released once its predecessor arrives, in stream order.
    #[test]
    fn a_reordered_segment_is_held_and_then_released_in_order() {
        let mut r = Reassembler::default();
        r.push(100, b"ab", 0.5).unwrap(); // establish the stream first — see the test below
        assert!(r.push(105, b"fg", 1.0).is_none(), "arrived early, nothing contiguous yet");
        let out = r.push(102, b"cde", 2.0).unwrap();
        assert_eq!(out.bytes, b"cdefg", "both runs, in stream order");
        assert_eq!(out.timestamp, 2.0, "timed by the packet that made them available");
    }

    /// Overlap between a held segment and the one that fills the hole must not duplicate.
    #[test]
    fn a_held_segment_overlapping_the_hole_is_trimmed() {
        let mut r = Reassembler::default();
        r.push(100, b"ab", 0.5).unwrap();
        r.push(104, b"efg", 1.0);
        assert_eq!(r.push(102, b"cde", 2.0).unwrap().bytes, b"cdefg");
    }

    /// An unfillable hole must stop the stream rather than concatenate across it — silently
    /// joining the two sides would shift every later record boundary.
    #[test]
    fn an_unfillable_hole_stops_the_direction() {
        let mut r = Reassembler::default();
        r.push(100, b"a", 1.0).unwrap();
        let huge = vec![0u8; Reassembler::MAX_HELD_BYTES + 1];
        assert!(r.push(1_000, &huge, 2.0).is_none());
        assert_eq!(r.gap(), Some(Gap::Missing { at: 101 }));
        assert!(r.push(101, b"b", 3.0).is_none(), "a broken direction stays broken");
    }

    /// Captures start mid-connection all the time, and the first segment of a direction is
    /// genuinely ambiguous: "the capture began here" and "this packet overtook its predecessor"
    /// look identical. The first segment seen is taken as the origin — the alternative is holding
    /// every capture's opening bytes forever waiting for a predecessor that was never recorded.
    #[test]
    fn a_capture_started_mid_stream_begins_at_the_first_segment() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(9_999, b"xy", 1.0).unwrap().bytes, b"xy");
    }

    #[test]
    fn sequence_comparison_survives_the_wrap() {
        assert!(seq_lt(u32::MAX, 0));
        assert!(!seq_lt(0, u32::MAX));
        // Two bytes at MAX-1 and MAX leave the stream expecting 0 — the wrap must be a
        // continuation, not a hole of four billion bytes.
        let mut r = Reassembler::default();
        r.push(u32::MAX - 1, b"ab", 1.0).unwrap();
        assert_eq!(r.push(0, b"cd", 2.0).unwrap().bytes, b"cd");
    }
}
