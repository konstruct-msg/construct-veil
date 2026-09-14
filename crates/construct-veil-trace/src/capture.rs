//! From link-layer frames to the connection-tagged record stream.
//!
//! Split out of the CLI so the path that matters — dissect, reassemble, frame, attribute to a
//! connection — is driven by tests rather than by a capture someone has to take by hand.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flow::{FlowKey, Reassembler};
use crate::records::{Direction, Record, RecordFramer};

/// One record, tagged with the connection it belongs to.
///
/// The connection has to survive into the trace file: it is the unit of evidence, and a trace that
/// only carried records would invite exactly the per-packet pooling the review warns about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracedRecord {
    pub conn: u32,
    #[serde(flatten)]
    pub record: Record,
}

/// Accumulates packets into a record stream.
#[derive(Debug)]
pub struct TraceBuilder {
    port: u16,
    streams: HashMap<FlowKey, (Reassembler, RecordFramer)>,
    connections: HashMap<(FlowKey, FlowKey), u32>,
    next_conn: u32,
}

impl TraceBuilder {
    /// `port` is the server port that identifies the connections of interest; it also fixes which
    /// direction is "up", so the two sides never depend on which packet was captured first.
    pub fn new(port: u16) -> Self {
        Self { port, streams: HashMap::new(), connections: HashMap::new(), next_conn: 0 }
    }

    /// Offers one link-layer frame. Returns the records it completed.
    pub fn push(&mut self, data: &[u8], timestamp: f64) -> Vec<TracedRecord> {
        let Some((key, seq, payload)) = dissect(data) else { return Vec::new() };
        if (key.dst_port != self.port && key.src_port != self.port) || payload.is_empty() {
            return Vec::new();
        }

        let dir = if key.dst_port == self.port { Direction::Up } else { Direction::Down };
        let reverse =
            FlowKey { src: key.dst, dst: key.src, src_port: key.dst_port, dst_port: key.src_port };
        // Key the connection on the (client, server) pair whichever way the packet went, so both
        // directions land on one id.
        let pair = if dir == Direction::Up { (key, reverse) } else { (reverse, key) };
        let next = &mut self.next_conn;
        let conn = *self.connections.entry(pair).or_insert_with(|| {
            let id = *next;
            *next += 1;
            id
        });

        let (reassembler, framer) = self.streams.entry(key).or_default();
        let Some(segment) = reassembler.push(seq, payload, timestamp) else { return Vec::new() };

        let mut records = Vec::new();
        framer.push(&segment.bytes, segment.timestamp, dir, &mut records);
        records.into_iter().map(|record| TracedRecord { conn, record }).collect()
    }

    /// Connections seen so far.
    pub fn connections(&self) -> u32 {
        self.next_conn
    }

    /// Directions whose byte stream broke — desynced framing, or a hole that could not be filled.
    ///
    /// Their records stop early, so the connections they belong to are short in a way that has
    /// nothing to do with the traffic. Discard them; do not summarise them.
    pub fn broken_directions(&self) -> usize {
        self.streams
            .values()
            .filter(|(reassembler, framer)| framer.desynced() || reassembler.gap().is_some())
            .count()
    }
}

/// Pulls (flow, sequence number, payload) out of one link-layer frame.
///
/// Loopback captures are not Ethernet — on macOS `lo0` frames carry a 4-byte null header — so both
/// framings are tried. Anything else is skipped rather than guessed at.
pub fn dissect(data: &[u8]) -> Option<(FlowKey, u32, &[u8])> {
    let sliced = etherparse::SlicedPacket::from_ethernet(data)
        .ok()
        .filter(|s| s.net.is_some())
        .or_else(|| etherparse::SlicedPacket::from_ip(data.get(4..)?).ok())?;

    let (src, dst) = match sliced.net.as_ref()? {
        etherparse::NetSlice::Ipv4(ip) => {
            let h = ip.header();
            (to16(&h.source()), to16(&h.destination()))
        }
        etherparse::NetSlice::Ipv6(ip) => {
            let h = ip.header();
            (h.source(), h.destination())
        }
    };

    let etherparse::TransportSlice::Tcp(tcp) = sliced.transport.as_ref()? else { return None };
    Some((
        FlowKey { src, dst, src_port: tcp.source_port(), dst_port: tcp.destination_port() },
        tcp.sequence_number(),
        tcp.payload(),
    ))
}

/// IPv4 addresses live in the same 16-byte slot as IPv6 so one flow key covers both.
fn to16(addr: &[u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[12..].copy_from_slice(addr);
    out
}
