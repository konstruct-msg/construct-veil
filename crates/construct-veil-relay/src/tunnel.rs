//! Tunnel forwarding — ferry h2c gRPC traffic through the authenticated tunnel.
//!
//! After auth validation, the relay is a **framed** ferry between the client's
//! h2c gRPC stream and the Construct backend (also h2c):
//!
//! - **client → backend:** decode veil-front frames; `DATA` payloads are written
//!   to the backend with their frame headers stripped; `CHAFF` frames are dropped.
//! - **backend → client:** raw backend bytes are wrapped in `DATA` frames.
//!
//! This realises sketch §7 (Option B-lite, minimal framing) — the relay never
//! forwards frame headers to the backend, and the chaff channel is real on the
//! wire (CHAFF is silently discarded here, injected by the client's padding layer).

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use construct_veil_protocol::{FRAME_TYPE_CHAFF, FRAME_TYPE_DATA, Frame, VeilFrontCodec};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

/// Read buffer size for the backend → client direction.
const COPY_BUF: usize = 8192;

/// Forward tunnel traffic between an authenticated client and the backend.
///
/// `leftover` contains any buffered bytes that arrived in the same read as the
/// AUTH frame (after it was consumed) — these are the start of the framed DATA
/// stream and are fed into the decoder before reading more from the socket.
pub async fn forward_tunnel<S>(
    client_stream: S,
    leftover: BytesMut,
    backend_addr: SocketAddr,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let backend = tokio::net::TcpStream::connect(backend_addr).await?;
    backend.set_nodelay(true)?;

    let (client_rd, client_wr) = io::split(client_stream);
    let (backend_rd, backend_wr) = backend.into_split();

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

/// Wrap raw backend bytes in DATA frames toward the client.
async fn frame_backend_to_client<R, W>(
    mut backend_rd: R,
    mut client_wr: W,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut codec = VeilFrontCodec::default();
    let mut rbuf = [0u8; COPY_BUF];

    loop {
        let n = backend_rd.read(&mut rbuf).await?;
        if n == 0 {
            client_wr.shutdown().await?;
            return Ok(());
        }
        let frame = Frame::data(Bytes::copy_from_slice(&rbuf[..n]));
        let mut out = BytesMut::with_capacity(n + 4);
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
        let tunnel = tokio::spawn(async move {
            forward_tunnel(client_inner, BytesMut::new(), backend_addr).await
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
                assert_eq!(
                    frame.frame_type, FRAME_TYPE_DATA,
                    "reply must be DATA frames"
                );
                got.extend_from_slice(&frame.payload);
            }
        }
        assert_eq!(&got, b"helloworld");

        // Close the client side to end the tunnel.
        drop(test_wr);
        drop(test_rd);
        let _ = tunnel.await;
    }
}
