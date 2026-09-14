//! End-to-end over synthetic frames: does a known shape survive dissect → reassemble → frame?
//!
//! The rig's whole value is that its output can be trusted when it contradicts an expectation. So
//! the cases here are ones where the answer is known before the code runs, including the two that
//! would quietly corrupt a real capture — a retransmit and a reorder.

use construct_veil_trace::capture::TraceBuilder;
use construct_veil_trace::records::{CT_APPLICATION_DATA, CT_HANDSHAKE, Direction};
use construct_veil_trace::stats::ConnectionFeatures;

const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [10, 0, 0, 2];
const PORT: u16 = 443;

/// One Ethernet + IPv4 + TCP frame carrying `payload`.
fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, seq, 65535);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).expect("in-memory write");
    out
}

/// A TLS record of `len` payload bytes; on the wire it costs `len + 5`.
fn record(ct: u8, len: usize) -> Vec<u8> {
    let mut v = vec![ct, 0x03, 0x03];
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend(std::iter::repeat_n(0xAB, len));
    v
}

fn up(seq: u32, payload: &[u8]) -> Vec<u8> {
    frame(CLIENT, SERVER, 40_000, PORT, seq, payload)
}

fn down(seq: u32, payload: &[u8]) -> Vec<u8> {
    frame(SERVER, CLIENT, PORT, 40_000, seq, payload)
}

#[test]
fn a_bucketed_session_comes_back_with_its_buckets_intact() {
    let mut builder = TraceBuilder::new(PORT);
    let mut out = Vec::new();

    // The client's shape under Mode 0: everything in two buckets.
    let mut seq = 1_000;
    for (i, len) in [256, 256, 1024, 256].into_iter().enumerate() {
        let wire = record(CT_APPLICATION_DATA, len);
        out.extend(builder.push(&up(seq, &wire), i as f64));
        seq += wire.len() as u32;
    }

    let sizes: Vec<usize> = out.iter().map(|t| t.record.len).collect();
    assert_eq!(sizes, vec![261, 261, 1029, 261]);
    assert!(out.iter().all(|t| t.record.dir == Direction::Up));
    assert!(out.iter().all(|t| t.conn == 0), "one connection");
}

/// Both directions of one connection must carry the same id — otherwise every feature computed
/// per connection is computed on half a conversation.
#[test]
fn the_two_directions_of_a_connection_share_one_id() {
    let mut builder = TraceBuilder::new(PORT);
    let mut out = Vec::new();

    out.extend(builder.push(&up(1_000, &record(CT_APPLICATION_DATA, 100)), 0.0));
    out.extend(builder.push(&down(5_000, &record(CT_APPLICATION_DATA, 900)), 0.1));

    assert_eq!(out.len(), 2);
    assert_eq!(out[0].conn, out[1].conn);
    assert_eq!(out[0].record.dir, Direction::Up);
    assert_eq!(out[1].record.dir, Direction::Down);
    assert_eq!(builder.connections(), 1);
}

/// Two clients behind one capture are two observations, not one big one.
#[test]
fn separate_connections_get_separate_ids() {
    let mut builder = TraceBuilder::new(PORT);
    let mut out = Vec::new();

    out.extend(builder.push(&frame(CLIENT, SERVER, 40_000, PORT, 1, &record(CT_APPLICATION_DATA, 10)), 0.0));
    out.extend(builder.push(&frame(CLIENT, SERVER, 40_001, PORT, 1, &record(CT_APPLICATION_DATA, 10)), 0.1));

    assert_eq!(builder.connections(), 2);
    assert_ne!(out[0].conn, out[1].conn);
}

/// A record split across two packets is one record, timed by the packet that completed it.
#[test]
fn a_record_spanning_two_packets_is_one_record() {
    let mut builder = TraceBuilder::new(PORT);
    let wire = record(CT_APPLICATION_DATA, 2_000);

    let first = builder.push(&up(1_000, &wire[..800]), 5.0);
    let second = builder.push(&up(1_800, &wire[800..]), 5.25);

    assert!(first.is_empty());
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].record.len, 2_005);
    assert_eq!(second[0].record.t, 5.25);
}

/// The case that silently inflates a trace: a retransmitted packet must not become extra records.
#[test]
fn a_retransmitted_packet_does_not_invent_records() {
    let mut builder = TraceBuilder::new(PORT);
    let wire = record(CT_APPLICATION_DATA, 256);

    let first = builder.push(&up(1_000, &wire), 1.0);
    let again = builder.push(&up(1_000, &wire), 1.4);

    assert_eq!(first.len(), 1);
    assert!(again.is_empty(), "the same bytes twice are still one record");
}

/// The case that silently truncates a trace: a reordered packet must be held, not dropped.
#[test]
fn a_reordered_packet_is_recovered_rather_than_lost() {
    let mut builder = TraceBuilder::new(PORT);
    let first = record(CT_APPLICATION_DATA, 100);
    let second = record(CT_APPLICATION_DATA, 200);

    builder.push(&up(1_000, &first), 1.0);
    let early = builder.push(&up(1_000 + (first.len() + second.len()) as u32, &record(CT_APPLICATION_DATA, 300)), 2.0);
    let filled = builder.push(&up(1_000 + first.len() as u32, &second), 3.0);

    assert!(early.is_empty(), "held, waiting for the hole to close");
    assert_eq!(
        filled.iter().map(|t| t.record.len).collect::<Vec<_>>(),
        vec![205, 305],
        "both records, in stream order, once the hole closed"
    );
}

/// Traffic to another port shares the capture and must not share the trace.
#[test]
fn traffic_on_another_port_is_ignored() {
    let mut builder = TraceBuilder::new(PORT);

    let out = builder.push(
        &frame(CLIENT, SERVER, 40_000, 8_080, 1, &record(CT_APPLICATION_DATA, 100)),
        0.0,
    );

    assert!(out.is_empty());
    assert_eq!(builder.connections(), 0);
}

/// The features a comparison runs on must come out of a real frame sequence, not just out of unit
/// tests on hand-built records — this is the seam where a shape claim is actually produced.
#[test]
fn a_fixed_cadence_survives_the_whole_pipeline_as_a_flat_gap_distribution() {
    let mut builder = TraceBuilder::new(PORT);
    let mut records = Vec::new();
    let mut seq = 1_000u32;

    // Handshake first, then twenty identical records exactly half a second apart.
    let hello = record(CT_HANDSHAKE, 512);
    records.extend(builder.push(&up(seq, &hello), 0.0).into_iter().map(|t| t.record));
    seq += hello.len() as u32;

    for i in 0..20 {
        let wire = record(CT_APPLICATION_DATA, 256);
        records.extend(
            builder.push(&up(seq, &wire), 1.0 + i as f64 * 0.5).into_iter().map(|t| t.record),
        );
        seq += wire.len() as u32;
    }

    let features = ConnectionFeatures::from_records(&records).unwrap();

    assert_eq!(features.records, 20, "the handshake record is not part of the session shape");
    assert_eq!(features.median_gap, 0.5);
    assert!(features.gap_iqr.abs() < 1e-9, "a metronome has no spread");
    assert_eq!(features.distinct_sizes, 1);
    assert_eq!(features.modal_size_share, 1.0);
}
