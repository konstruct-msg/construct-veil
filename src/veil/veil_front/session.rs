//! Sans-IO veil-front data-plane session.
//!
//! The framing + chaff/payload policy for one authenticated veil-front tunnel,
//! with **no I/O**: no sockets, no async runtime, no system clock. Local bytes and
//! an injected [`Instant`] go in; framed wire bytes and decoded payloads come out.
//! The tokio ferry (`run_ferry`) and the host-terminated TLS path drive it against
//! real sockets; unit tests drive it directly with a controlled clock — which is
//! the whole point: the busy-loop that once starved payload behind chaff (only
//! reproducible on-device) is now a three-line unit test.
//!
//! See the sans-IO decision record (construct-docs
//! `decisions/sans-io-core-platform-adapters.md`).

use std::io;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use construct_veil_protocol::{FRAME_TYPE_DATA, Frame, LENGTH_BUCKETS, VeilFrontCodec};
use tokio_util::codec::{Decoder, Encoder};

use super::WriteStrategy;

/// A veil-front session, split into an up half and a down half so a driver can run
/// the two directions concurrently — they share no mutable state — exactly as
/// [`tokio::io::split`] splits a duplex. Construct with [`VeilFrontSession::new`].
pub struct VeilFrontSession;

impl VeilFrontSession {
    /// Create the two sans-IO halves for one tunnel.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> (VeilFrontUp, VeilFrontDown) {
        (VeilFrontUp::new(), VeilFrontDown::new())
    }
}

/// Up direction: local plaintext (gRPC h2c) → `DATA`/`CHAFF` frames → relay.
///
/// Pure policy: queue local bytes, then emit one framed wire chunk at a time with
/// payload priority and idle (front-loaded) chaff — see [`WriteStrategy`]. No I/O.
pub struct VeilFrontUp {
    strategy: WriteStrategy,
    codec: VeilFrontCodec,
}

impl VeilFrontUp {
    fn new() -> Self {
        Self {
            strategy: WriteStrategy::new(),
            codec: VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS),
        }
    }

    /// Queue a chunk of local plaintext to be sent as a `DATA` frame.
    pub fn queue_local(&mut self, data: &[u8]) {
        self.strategy
            .payload_queue
            .push(Frame::data(Bytes::copy_from_slice(data)));
    }

    /// Produce the next framed wire chunk to write to the relay, as of `now`.
    ///
    /// Payload takes priority; chaff fills idle time (the front window is driven by
    /// `now`). One frame per call — the caller loops. `Ok(None)` means nothing is
    /// due right now (no payload queued and no chaff owed). `now` is injected, so
    /// pacing is deterministic under test; production passes `Instant::now()`.
    pub fn next_wire(&mut self, now: Instant) -> io::Result<Option<BytesMut>> {
        match self.strategy.next_frame(now) {
            Some(frame) => {
                let mut out = BytesMut::with_capacity(frame.payload.len() + 16);
                self.codec.encode(frame, &mut out)?;
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }

    /// Whether anything is queued (payload or pending chaff) right now.
    pub fn has_pending(&self) -> bool {
        self.strategy.has_pending()
    }

    /// How long until something is due without more local bytes: zero now, `None` never. A driver
    /// waits on the local read for that long — with no timer once the chaff is sent: an idle tunnel
    /// must not wake the device.
    pub fn next_due(&mut self, now: Instant) -> Option<Duration> {
        self.strategy.next_due(now)
    }

    /// Consume the up half, returning the [`WriteStrategy`] for overhead metrics.
    pub fn into_strategy(self) -> WriteStrategy {
        self.strategy
    }
}

/// Down direction: relay frames → local plaintext, dropping `CHAFF`.
///
/// Pure: feed relay bytes, pop decoded `DATA` payloads. No I/O.
pub struct VeilFrontDown {
    codec: VeilFrontCodec,
    buf: BytesMut,
}

impl VeilFrontDown {
    fn new() -> Self {
        Self {
            codec: VeilFrontCodec::default(),
            buf: BytesMut::with_capacity(4096),
        }
    }

    /// Feed raw bytes received from the relay into the decode buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next decoded `DATA` payload to write to the local stream, draining
    /// and dropping any `CHAFF` (and ignoring stray AUTH/unknown frames) along the
    /// way. `Ok(None)` means no complete `DATA` frame is buffered yet — feed more.
    pub fn next_payload(&mut self) -> io::Result<Option<Bytes>> {
        while let Some(frame) = self.codec.decode(&mut self.buf)? {
            if frame.frame_type == FRAME_TYPE_DATA {
                return Ok(Some(frame.payload));
            }
            // CHAFF (cover traffic) and any stray AUTH/unknown mid-stream frame:
            // discard and keep decoding.
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::{FRAME_TYPE_CHAFF, VeilFrontCodec};

    /// Encode one frame the way the relay/peer would, for feeding a `VeilFrontDown`.
    fn encode(frame: Frame) -> BytesMut {
        let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let mut out = BytesMut::new();
        codec.encode(frame, &mut out).expect("encode");
        out
    }

    /// The regression that once cost hours on-device, now deterministic: with a
    /// payload queued, the first wire frame is that DATA — never a chaff frame —
    /// even at the very start of the front window when chaff is available.
    #[test]
    fn up_payload_takes_priority_over_chaff() {
        let start = Instant::now();
        let (mut up, mut down) = VeilFrontSession::new();
        up.queue_local(b"hello");

        let wire = up
            .next_wire(start)
            .expect("encode ok")
            .expect("a frame is due");
        down.feed(&wire);

        assert_eq!(
            down.next_payload().expect("decode ok").as_deref(),
            Some(&b"hello"[..]),
            "queued payload must be the first frame, not chaff"
        );
    }

    /// An idle up half asks to be woken exactly when its next chaff is due, and not at all once it
    /// is sent; queued payload is due now. Mutation: ask for a tick after the chaff is done — this
    /// reddens.
    #[test]
    fn up_asks_to_be_woken_only_for_chaff_it_owes() {
        let (mut up, mut down) = VeilFrontSession::new();
        let mut now = Instant::now();
        let t0 = now;
        let mut frames = 0;
        while let Some(wait) = up.next_due(now) {
            now += wait;
            let wire = up.next_wire(now).unwrap().expect("due is due");
            down.feed(&wire);
            frames += 1;
        }
        assert!(frames <= 32);
        assert!(now - t0 <= Duration::from_secs(4), "chaff is front-loaded");
        assert_eq!(down.next_payload().unwrap(), None, "chaff is not payload");
        assert!(!up.has_pending());

        up.queue_local(b"payload");
        assert_eq!(up.next_due(now), Some(Duration::ZERO));
        assert!(up.next_wire(now).unwrap().is_some());
        assert_eq!(up.next_due(now), None);
    }

    /// The down half reassembles frames split across arbitrary feed boundaries and
    /// drops CHAFF, yielding only the DATA payloads in order.
    #[test]
    fn down_reassembles_across_feeds_and_drops_chaff() {
        let (_up, mut down) = VeilFrontSession::new();

        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode(Frame::data(Bytes::from(&b"alpha"[..]))));
        wire.extend_from_slice(&encode(Frame::new(
            FRAME_TYPE_CHAFF,
            Bytes::from(&b"\x00\x00\x00"[..]),
        )));
        wire.extend_from_slice(&encode(Frame::data(Bytes::from(&b"bravo"[..]))));

        // Feed one byte at a time — the hardest reassembly case.
        let mut got: Vec<Vec<u8>> = Vec::new();
        for b in wire.iter() {
            down.feed(&[*b]);
            while let Some(p) = down.next_payload().expect("decode ok") {
                got.push(p.to_vec());
            }
        }

        assert_eq!(got, vec![b"alpha".to_vec(), b"bravo".to_vec()]);
    }
}
