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
use rand::Rng;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

/// Read buffer size for the backend → client direction.
const COPY_BUF: usize = 8192;

/// CHAFF length buckets (bytes) for symmetric relay-side injection.
/// Matches the Mode 0 bucket set from the client's WriteStrategy.
const CHAFF_BUCKETS: &[usize] = &[32, 64, 128, 256, 512];

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
pub async fn forward_tunnel<S, B>(
    client_stream: S,
    leftover: BytesMut,
    backend: B,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_rd, mut client_wr) = io::split(client_stream);
    let (backend_rd, backend_wr) = io::split(backend);

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

    // client → backend: de-frame DATA, drop CHAFF.
    let up = deframe_client_to_backend(client_rd, leftover, backend_wr);
    // backend → client: wrap raw bytes in DATA frames.
    let down = frame_backend_to_client(backend_rd, client_wr);

    match tokio::try_join!(up, down) {
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
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut codec = VeilFrontCodec::default();
    let mut buf = leftover;

    loop {
        // Drain any complete frames already in the buffer.
        loop {
            match codec.decode(&mut buf)? {
                Some(frame) => match frame.frame_type {
                    FRAME_TYPE_DATA => backend_wr.write_all(&frame.payload).await?,
                    FRAME_TYPE_CHAFF => { /* cover traffic — discard */ }
                    other => {
                        // AUTH (already consumed) or unknown mid-stream frame.
                        // Drop it rather than corrupt the backend stream.
                        debug!(frame_type = other, "unexpected mid-tunnel frame, dropping");
                    }
                },
                None => break, // need more bytes
            }
        }

        let n = client_rd.read_buf(&mut buf).await?;
        if n == 0 {
            backend_wr.shutdown().await?;
            return Ok(());
        }
    }
}

/// Wrap raw backend bytes in DATA frames toward the client, with symmetric
/// CHAFF injection during idle periods (sketch §8).
async fn frame_backend_to_client<R, W>(
    mut backend_rd: R,
    mut client_wr: W,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    let mut rbuf = [0u8; COPY_BUF];

    loop {
        // Read from backend with a short timeout — if idle, inject CHAFF.
        let read_fut = backend_rd.read(&mut rbuf);
        let n = match tokio::time::timeout(std::time::Duration::from_millis(20), read_fut).await {
            Ok(Ok(0)) => {
                // Backend closed.
                client_wr.shutdown().await?;
                return Ok(());
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Backend idle — inject a CHAFF frame (symmetric padding).
                let chaff = random_chaff(&mut rand::thread_rng());
                let mut out = BytesMut::with_capacity(2 + 9 + chaff.len());
                codec.encode(Frame::chaff(chaff), &mut out)?;
                client_wr.write_all(&out).await?;
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
            forward_tunnel(client_inner, BytesMut::new(), backend_conn).await
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
