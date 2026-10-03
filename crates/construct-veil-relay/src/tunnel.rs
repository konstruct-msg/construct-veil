//! Tunnel forwarding — ferry h2c gRPC traffic through the authenticated tunnel.
//!
//! After auth validation, the relay is a **framed** ferry between the client's
//! h2c gRPC stream and the Construct backend (also h2c):
//!
//! - **client → backend:** decode veil-front frames; `DATA` payloads are written
//!   to the backend with their frame headers stripped; `CHAFF` frames are dropped.
//! - **backend → client:** raw backend bytes are wrapped in `DATA` frames, with
//!   **symmetric CHAFF injection** during idle periods (sketch §8: "A relay MAY
//!   also inject CHAFF toward the client symmetrically").
//!
//! **First-response alignment (§6.6):** after auth validation the relay immediately
//! emits a CHAFF frame before any backend data arrives. This ensures the tunnel
//! path's first emitted bytes share a length distribution with the site path's
//! first response (cover app content), satisfying constant-shape branching.
//!
//! This realises sketch §7 (Option B-lite, minimal framing) — the relay never
//! forwards frame headers to the backend, and the chaff channel is real on the
//! wire (CHAFF is silently discarded here, injected by the client's padding layer).

use bytes::{Bytes, BytesMut};
use construct_veil_protocol::{
    FRAME_TYPE_CHAFF, FRAME_TYPE_DATA, Frame, LENGTH_BUCKETS, VeilFrontCodec,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, info, warn};

/// Read buffer size for the backend → client direction.
const COPY_BUF: usize = 8192;

/// CHAFF length buckets (bytes) for symmetric relay-side injection.
/// Matches the Mode 0 bucket set from the client's WriteStrategy.
const CHAFF_BUCKETS: &[usize] = &[32, 64, 128, 256, 512];

/// How long after a tunnel opens the relay fills idle gaps toward the client with CHAFF:
/// the client's own Mode 0 window (`FRONT_WINDOW` in `mode0_front.rs`), so both directions
/// are front-loaded and then quiet. Sketch §8 makes this the mobile default; constant cover
/// traffic is Mode 2, "not a mobile default".
///
/// Until 2026-10-03 the relay sent a CHAFF frame every [`IDLE_CHAFF_TICK`] for the whole life
/// of the tunnel. An idle Android client on VEIL received ~44 MB an hour, ~35 packets a
/// second — a radio that never slept and a CPU that decrypted and discarded all of it.
pub(crate) const IDLE_CHAFF_WINDOW: Duration = Duration::from_secs(3);

/// Inside [`IDLE_CHAFF_WINDOW`], an idle gap this long gets a CHAFF frame.
pub(crate) const IDLE_CHAFF_TICK: Duration = Duration::from_millis(20);

/// Initial CHAFF payload sizes for first-response alignment (§6.6).
/// After auth validation, the relay sends one of these to match the cover
/// app's first-response length distribution.
const INITIAL_CHAFF_BUCKETS: &[usize] = &[128, 256];

/// Generate a random chaff payload from the given buckets.
fn random_chaff(rng: &mut impl Rng) -> Bytes {
    let len = CHAFF_BUCKETS[rng.gen_range(0..CHAFF_BUCKETS.len())];
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    Bytes::from(buf)
}

/// Generate a random initial chaff payload for first-response alignment.
fn initial_chaff(rng: &mut impl Rng) -> Bytes {
    let len = INITIAL_CHAFF_BUCKETS[rng.gen_range(0..INITIAL_CHAFF_BUCKETS.len())];
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    Bytes::from(buf)
}

/// Forward tunnel traffic between an authenticated client and the backend.
///
/// `backend` is an already-connected byte stream — either a plain `TcpStream`
/// (co-located h2c backend) or a TLS stream (remote backend reached over its
/// public TLS endpoint, ALPN h2). The relay is transport-agnostic here: DATA
/// payloads are the client's raw H2/gRPC bytes, written to the backend verbatim.
///
/// `leftover` contains any buffered bytes that arrived in the same read as the
/// AUTH frame (after it was consumed) — these are the start of the framed DATA
/// stream and are fed into the decoder before reading more from the socket.
/// Tag a tunnel-half error with its direction while preserving the `ErrorKind`,
/// so the aggregated `tunnel forwarding error` log says which leg failed. The two
/// legs terminate different TLS sessions — client→backend reads the relay's TLS
/// **server** session with the client, backend→client reads the relay's TLS
/// **client** session with the backend — but rustls surfaces the same text for
/// both (e.g. "cannot decrypt peer's message"), so without the tag a decrypt
/// failure is unattributable. Kind is preserved so the disconnect classification
/// below still fires.
fn tag_direction(e: std::io::Error, dir: &str) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{dir}: {e}"))
}

pub async fn forward_tunnel<S, B>(
    client_stream: S,
    leftover: BytesMut,
    backend: B,
    peer: SocketAddr,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_rd, mut client_wr) = io::split(client_stream);
    let (backend_rd, backend_wr) = io::split(backend);

    // ── Diagnostics: per-direction byte counters + a periodic progress log, so a
    // stall is localised to a direction (request not sent / no response / low
    // throughput) instead of guessed at. TEMPORARY — lower to debug or remove once
    // veil-front throughput is understood.
    let up_bytes = Arc::new(AtomicU64::new(0)); // client → backend (requests)
    let down_bytes = Arc::new(AtomicU64::new(0)); // backend → client (responses)
    let chaff_bytes = Arc::new(AtomicU64::new(0)); // relay-injected chaff toward client
    let start = Instant::now();
    let progress = {
        let (u, d, c) = (up_bytes.clone(), down_bytes.clone(), chaff_bytes.clone());
        tokio::spawn(async move {
            let (mut lu, mut ld, mut lc) = (0u64, 0u64, 0u64);
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let (cu, cd, cc) = (
                    u.load(Ordering::Relaxed),
                    d.load(Ordering::Relaxed),
                    c.load(Ordering::Relaxed),
                );
                // chaff_d>0 while down_d=0 → down loop alive, backend silent (D1).
                // chaff_d=0 while up still flows → down loop blocked on client write (D2).
                info!(
                    peer = %peer, up = cu, down = cd, chaff = cc,
                    up_d = cu - lu, down_d = cd - ld, chaff_d = cc - lc,
                    "tunnel progress (up=client→backend, down=backend→client)"
                );
                (lu, ld, lc) = (cu, cd, cc);
            }
        })
    };

    // ── First-response alignment (§6.6): emit an initial CHAFF frame
    // before any backend data. This ensures the tunnel path's first emitted
    // bytes share a length distribution with the site path's first response.
    let chaff_payload = initial_chaff(&mut rand::thread_rng());
    let mut init_frame = BytesMut::with_capacity(2 + 9 + chaff_payload.len());
    let mut codec_init = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    codec_init.encode(Frame::chaff(chaff_payload), &mut init_frame)?;
    client_wr.write_all(&init_frame).await?;
    client_wr.flush().await?;
    debug!("emitted initial CHAFF for first-response alignment");

    // client → backend: de-frame DATA, drop CHAFF. Clone the counters out before
    // the `async move` so the originals survive for the summary log below.
    let up_c = up_bytes.clone();
    let up = async move {
        deframe_client_to_backend(client_rd, leftover, backend_wr, up_c)
            .await
            .map_err(|e| tag_direction(e, "client→backend"))
    };
    // backend → client: wrap raw bytes in DATA frames.
    let down_c = down_bytes.clone();
    let chaff_c = chaff_bytes.clone();
    let down = async move {
        frame_backend_to_client(backend_rd, client_wr, down_c, chaff_c, IDLE_CHAFF_WINDOW)
            .await
            .map_err(|e| tag_direction(e, "backend→client"))
    };

    let result = tokio::try_join!(up, down);
    progress.abort();
    info!(
        peer = %peer,
        up = up_bytes.load(Ordering::Relaxed),
        down = down_bytes.load(Ordering::Relaxed),
        chaff = chaff_bytes.load(Ordering::Relaxed),
        dur_ms = start.elapsed().as_millis() as u64,
        "tunnel closed"
    );
    match result {
        Ok(_) => {
            debug!("tunnel forwarding completed normally");
            Ok(())
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe
            {
                debug!("tunnel closed (client disconnect)");
                Ok(())
            } else {
                warn!(error = %e, "tunnel forwarding error");
                Err(e)
            }
        }
    }
}

/// Decode veil-front frames from the client, writing DATA payloads to the
/// backend and silently dropping CHAFF frames.
async fn deframe_client_to_backend<R, W>(
    mut client_rd: R,
    leftover: BytesMut,
    mut backend_wr: W,
    bytes: Arc<AtomicU64>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut codec = VeilFrontCodec::default();
    let mut buf = leftover;

    loop {
        // Drain any complete frames already in the buffer.
        let mut wrote_payload = false;
        while let Some(frame) = codec.decode(&mut buf)? {
            match frame.frame_type {
                FRAME_TYPE_DATA => {
                    backend_wr.write_all(&frame.payload).await?;
                    bytes.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                    wrote_payload = true;
                }
                FRAME_TYPE_CHAFF => {
                    // cover traffic — discard.
                }
                other => {
                    // AUTH (already consumed) or unknown mid-stream frame.
                    // Drop it rather than corrupt the backend stream.
                    debug!(frame_type = other, "unexpected mid-tunnel frame, dropping");
                }
            }
        }

        // Flush before blocking on the next client read. The backend is a
        // `tokio_rustls` TLS stream (`--backend-tls`); `write_all` only buffers
        // plaintext, so without this flush a small client→backend request (a
        // unary gRPC call) can sit unsent in the TLS buffer until more bytes
        // arrive — the request never reaches the backend, no response comes
        // back, and the client RPC dies with clientSideTimeout. The opposite
        // direction (`frame_backend_to_client`) already flushes per DATA write,
        // which is why server→client stream data flowed while unary sends hung.
        if wrote_payload {
            backend_wr.flush().await?;
        }

        let n = client_rd.read_buf(&mut buf).await?;
        if n == 0 {
            backend_wr.shutdown().await?;
            return Ok(());
        }
    }
}

/// Wrap raw backend bytes in DATA frames toward the client, with symmetric
/// CHAFF injection during idle periods of the first `chaff_window` (sketch §8, Mode 0).
/// After it, an idle backend means an idle tunnel: the read waits with no timer.
async fn frame_backend_to_client<R, W>(
    mut backend_rd: R,
    mut client_wr: W,
    bytes: Arc<AtomicU64>,
    chaff_bytes: Arc<AtomicU64>,
    chaff_window: Duration,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    let mut rbuf = [0u8; COPY_BUF];
    let opened = Instant::now();

    loop {
        // Inside the window, read with a short timeout — if idle, inject CHAFF.
        let read_fut = backend_rd.read(&mut rbuf);
        let read = if opened.elapsed() < chaff_window {
            tokio::time::timeout(IDLE_CHAFF_TICK, read_fut).await.ok()
        } else {
            Some(read_fut.await)
        };
        let n = match read {
            Some(Ok(0)) => {
                // Backend closed.
                client_wr.shutdown().await?;
                return Ok(());
            }
            Some(Ok(n)) => {
                bytes.fetch_add(n as u64, Ordering::Relaxed);
                n
            }
            Some(Err(e)) => return Err(e),
            None => {
                // Backend idle — inject a CHAFF frame (symmetric padding).
                let chaff = random_chaff(&mut rand::thread_rng());
                let mut out = BytesMut::with_capacity(2 + 9 + chaff.len());
                codec.encode(Frame::chaff(chaff), &mut out)?;
                client_wr.write_all(&out).await?;
                chaff_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
                // Don't flush immediately — wait for backend data to batch.
                continue;
            }
        };

        let frame = Frame::data(Bytes::copy_from_slice(&rbuf[..n]));
        let mut out = BytesMut::with_capacity(2 + 9 + n);
        codec.encode(frame, &mut out)?;
        client_wr.write_all(&out).await?;
        client_wr.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// CHAFF fills idle gaps only inside the window; after it an idle backend sends
    /// nothing, and backend bytes still flow. Mutation: chaff for the life of the
    /// tunnel (ignore the window) — the count keeps growing; this reddens.
    #[tokio::test]
    async fn idle_chaff_stops_after_the_window() {
        let (mut backend_tx, backend_rd) = tokio::io::duplex(1 << 16);
        let (client_wr, mut client_rd) = tokio::io::duplex(1 << 22);
        let bytes = Arc::new(AtomicU64::new(0));
        let chaff = Arc::new(AtomicU64::new(0));
        let ferry = tokio::spawn(frame_backend_to_client(
            backend_rd,
            client_wr,
            bytes.clone(),
            chaff.clone(),
            Duration::from_millis(100),
        ));
        let drain = tokio::spawn(async move {
            let mut wire = Vec::new();
            client_rd.read_to_end(&mut wire).await.unwrap();
            wire
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        let after_window = chaff.load(Ordering::Relaxed);
        assert!(after_window > 0, "chaff fills the window");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            chaff.load(Ordering::Relaxed),
            after_window,
            "no chaff after the window"
        );

        backend_tx.write_all(b"hello").await.unwrap();
        drop(backend_tx);
        ferry.await.unwrap().unwrap();
        let wire = drain.await.unwrap();
        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::from(&wire[..]);
        let mut data = Vec::new();
        while let Some(frame) = codec.decode(&mut buf).unwrap() {
            if frame.frame_type == FRAME_TYPE_DATA {
                data.extend_from_slice(&frame.payload);
            }
        }
        assert_eq!(data, b"hello");
    }

    /// End-to-end: DATA frames are de-framed to the backend, CHAFF is dropped,
    /// and the backend's reply comes back wrapped in DATA frames.
    #[tokio::test]
    async fn deframes_data_drops_chaff_and_reframes_reply() {
        // Echo backend.
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                sock.write_all(&buf[..n]).await.unwrap();
            }
        });

        // Client stream is one end of an in-memory duplex.
        let (client_inner, client_test) = tokio::io::duplex(8192);
        let backend_conn = tokio::net::TcpStream::connect(backend_addr).await.unwrap();
        backend_conn.set_nodelay(true).unwrap();
        let tunnel = tokio::spawn(async move {
            let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
            forward_tunnel(client_inner, BytesMut::new(), backend_conn, peer).await
        });

        let (mut test_rd, mut test_wr) = tokio::io::split(client_test);

        // Send DATA("hello"), CHAFF(16 bytes), DATA("world").
        let mut codec = VeilFrontCodec::default();
        let mut out = BytesMut::new();
        codec
            .encode(Frame::data(Bytes::from_static(b"hello")), &mut out)
            .unwrap();
        codec
            .encode(Frame::chaff(Bytes::from(vec![0u8; 16])), &mut out)
            .unwrap();
        codec
            .encode(Frame::data(Bytes::from_static(b"world")), &mut out)
            .unwrap();
        test_wr.write_all(&out).await.unwrap();

        // Read back framed DATA until we reconstruct "helloworld" (CHAFF must be
        // absent: the backend never echoes it because the relay dropped it).
        let mut buf = BytesMut::with_capacity(1024);
        let mut got = Vec::new();
        while got.len() < 10 {
            let n = test_rd.read_buf(&mut buf).await.unwrap();
            assert!(n > 0, "stream closed before full reply");
            while let Some(frame) = codec.decode(&mut buf).unwrap() {
                match frame.frame_type {
                    FRAME_TYPE_DATA => got.extend_from_slice(&frame.payload),
                    FRAME_TYPE_CHAFF => { /* relay-side symmetric chaff — discard */ }
                    other => panic!("unexpected frame type in reply: 0x{other:02x}"),
                }
            }
        }
        assert_eq!(&got, b"helloworld");

        // Close the client side to end the tunnel.
        drop(test_wr);
        drop(test_rd);
        let _ = tunnel.await;
    }
}
