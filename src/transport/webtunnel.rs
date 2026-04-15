//! WebTunnel transport — WebSocket (RFC 6455) over TLS.
//!
//! Disguises traffic as standard `wss://` connections to bypass DPI.
//! Binary WebSocket frames transparently forward arbitrary TCP data.
//!
//! # Connection flow
//! ```text
//! [App] → local TCP → [WebTunnelStream] → TLS → WebSocket → relay:443
//! ```
//!
//! # DPI profile
//! Traffic appears as:
//! - Standard TLS ClientHello (with configurable SNI for CDN fronting)
//! - HTTP/1.1 `Upgrade: websocket` handshake
//! - Encrypted binary WebSocket frames
//!
//! Indistinguishable from browser-originated WebSocket connections by all
//! currently-deployed DPI systems (TSPU/ТСПУ, Iran DPI, GFW ML classifiers).
//!
//! # Domain fronting
//! Set `tls_sni` to a CDN domain (e.g. `storage.yandexcloud.net`) and
//! `host_header` to the relay domain. CDN routes by Host header; TLS
//! terminates at CDN edge with the fronting domain's cert (verified by SPKI pin).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::{Buf, BufMut, BytesMut};
use rand::random;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

// ── Frame helpers ─────────────────────────────────────────────────────────────

/// Encode `payload` as a masked binary WebSocket frame (RFC 6455 §5.2).
///
/// Clients MUST mask all sent frames (§5.3). Uses 4 cryptographically-random
/// masking key bytes so every frame has unique XOR key material.
fn encode_binary_frame(payload: &[u8], dst: &mut BytesMut) {
    let len = payload.len();
    // FIN=1, RSV1-3=0, opcode=2 (binary)
    dst.put_u8(0x82);
    // MASK=1, payload length
    if len <= 125 {
        dst.put_u8(0x80 | len as u8);
    } else if len <= 65535 {
        dst.put_u8(0xFE); // 0x80 | 126
        dst.put_u16(len as u16);
    } else {
        dst.put_u8(0xFF); // 0x80 | 127
        dst.put_u64(len as u64);
    }
    // Random 4-byte masking key
    let key: [u8; 4] = random::<[u8; 4]>();
    dst.put_slice(&key);
    // XOR-masked payload
    for (i, &b) in payload.iter().enumerate() {
        dst.put_u8(b ^ key[i & 3]);
    }
}

/// Encode a WebSocket close frame (opcode 0x8, no payload body).
fn encode_close_frame(dst: &mut BytesMut) {
    dst.put_u8(0x88); // FIN=1, opcode=8
    dst.put_u8(0x80); // MASK=1, len=0
    dst.put_u32(0); // masking key (zeroes — masked payload is empty)
}

/// Encode a WebSocket pong frame (opcode 0xA) with the given payload.
fn encode_pong_frame(payload: &[u8], dst: &mut BytesMut) {
    let len = payload.len().min(125); // Control frames must be ≤ 125 bytes
    dst.put_u8(0x8A); // FIN=1, opcode=0xA (pong)
    dst.put_u8(0x80 | len as u8); // MASK=1
    let key: [u8; 4] = random::<[u8; 4]>();
    dst.put_slice(&key);
    for (i, &b) in payload[..len].iter().enumerate() {
        dst.put_u8(b ^ key[i & 3]);
    }
}

/// Try to decode one WebSocket frame from `raw`.
///
/// On success: removes the frame from `raw`, appends decoded payload to
/// `payload_out`, and returns `Some(opcode)`.
/// Returns `None` when `raw` doesn't yet hold a complete frame.
/// Returns `Err` on a CLOSE frame or protocol violation.
fn try_decode_frame(
    raw: &mut BytesMut,
    payload_out: &mut BytesMut,
    pong_out: &mut BytesMut,
) -> io::Result<Option<u8>> {
    if raw.len() < 2 {
        return Ok(None);
    }

    let b0 = raw[0];
    let b1 = raw[1];
    let opcode = b0 & 0x0F;
    let masked = (b1 & 0x80) != 0;
    let len_byte = (b1 & 0x7F) as usize;

    let (header_end, payload_len) = match len_byte {
        0..=125 => (2usize, len_byte),
        126 => {
            if raw.len() < 4 { return Ok(None); }
            (4, u16::from_be_bytes([raw[2], raw[3]]) as usize)
        }
        _ /* 127 */ => {
            if raw.len() < 10 { return Ok(None); }
            let len = u64::from_be_bytes([
                raw[2], raw[3], raw[4], raw[5],
                raw[6], raw[7], raw[8], raw[9],
            ]) as usize;
            (10, len)
        }
    };

    let mask_len = if masked { 4 } else { 0 };
    let total_len = header_end + mask_len + payload_len;

    if raw.len() < total_len {
        return Ok(None); // Frame incomplete
    }

    let payload_start = header_end + mask_len;

    match opcode {
        // Continuation (0x0), text (0x1), binary (0x2) — data frames
        0x00 | 0x01 | 0x02 => {
            if masked {
                let key = [
                    raw[header_end],
                    raw[header_end + 1],
                    raw[header_end + 2],
                    raw[header_end + 3],
                ];
                for (i, &b) in raw[payload_start..payload_start + payload_len]
                    .iter()
                    .enumerate()
                {
                    payload_out.put_u8(b ^ key[i & 3]);
                }
            } else {
                payload_out.extend_from_slice(&raw[payload_start..payload_start + payload_len]);
            }
        }
        // CLOSE (0x8) — signal EOF
        0x08 => {
            raw.advance(total_len);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "webtunnel: close frame",
            ));
        }
        // PING (0x9) — queue a PONG response
        0x09 => {
            let ping_payload = &raw[payload_start..payload_start + payload_len];
            encode_pong_frame(ping_payload, pong_out);
        }
        // PONG (0xA) and anything else — ignore
        _ => {}
    }

    raw.advance(total_len);
    Ok(Some(opcode))
}

// ── WebTunnelStream ───────────────────────────────────────────────────────────

/// WebSocket client stream wrapping any `AsyncRead + AsyncWrite + Unpin` inner stream.
///
/// Handles WebSocket framing transparently; callers read/write raw bytes.
/// The underlying stream is typically a rustls TLS connection to the relay.
pub struct WebTunnelStream<S> {
    inner: S,
    /// Decoded WebSocket payload bytes ready for the caller.
    read_buf: BytesMut,
    /// Raw bytes from the inner stream not yet decoded into frames.
    raw_buf: BytesMut,
    /// Encoded WebSocket frames buffered for writing.
    write_buf: BytesMut,
    /// Received CLOSE frame → reads return EOF.
    closed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebTunnelStream<S> {
    /// Perform the HTTP/1.1 WebSocket upgrade handshake.
    ///
    /// # Parameters
    /// - `inner`       — TLS-connected stream to the relay.
    /// - `host_header` — HTTP `Host` header value (relay domain or CDN front domain).
    /// - `path`        — WebSocket resource path (e.g. `"/construct-ice"`).
    pub async fn connect(inner: S, host_header: &str, path: &str) -> io::Result<Self> {
        let mut stream = Self {
            inner,
            read_buf: BytesMut::with_capacity(65536),
            raw_buf: BytesMut::with_capacity(16384),
            write_buf: BytesMut::with_capacity(4096),
            closed: false,
        };

        // Random 16-byte Sec-WebSocket-Key (RFC 6455 §4.1 — must be unique per handshake)
        let key_bytes: [u8; 16] = random::<[u8; 16]>();
        let key = B64.encode(key_bytes);

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );

        stream.inner.write_all(request.as_bytes()).await?;
        stream.inner.flush().await?;

        // Read HTTP response headers (terminated by \r\n\r\n)
        let mut hdr_buf = vec![0u8; 4096];
        let mut total = 0usize;
        loop {
            if total >= hdr_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "webtunnel: HTTP response too large",
                ));
            }
            let n = stream.inner.read(&mut hdr_buf[total..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "webtunnel: connection closed during upgrade",
                ));
            }
            total += n;
            if hdr_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        // Verify 101 Switching Protocols
        let first_line_end = hdr_buf[..total]
            .iter()
            .position(|&b| b == b'\r')
            .unwrap_or(total.min(128));
        let status_line = &hdr_buf[..first_line_end];
        if !status_line.windows(3).any(|w| w == b"101") {
            let msg = std::str::from_utf8(status_line)
                .unwrap_or("(invalid)")
                .to_owned();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("webtunnel: expected 101, got: {msg}"),
            ));
        }

        // Any bytes after the HTTP header boundary are WebSocket data
        if let Some(pos) = hdr_buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
            let ws_start = pos + 4;
            if ws_start < total {
                stream.raw_buf.extend_from_slice(&hdr_buf[ws_start..total]);
            }
        }

        Ok(stream)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebTunnelStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        loop {
            // Fast path: drain already-decoded bytes
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // Decode as many complete frames as possible from raw_buf
            let mut pong_buf = BytesMut::new();
            loop {
                match try_decode_frame(&mut this.raw_buf, &mut this.read_buf, &mut pong_buf) {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        this.closed = true;
                        return Poll::Ready(Ok(())); // Clean close → EOF
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                    Ok(None) => break, // Incomplete frame — need more bytes
                    Ok(Some(_)) => {}  // Decoded a frame, keep looping
                }
            }

            // Queue any pong responses to be sent
            if !pong_buf.is_empty() {
                this.write_buf.extend_from_slice(&pong_buf);
            }

            if !this.read_buf.is_empty() {
                continue; // Got data, loop to drain
            }

            // Need more raw bytes from the inner stream
            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        this.closed = true;
                        return Poll::Ready(Ok(())); // EOF from inner
                    }
                    this.raw_buf.extend_from_slice(tmp_buf.filled());
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebTunnelStream<S> {
    /// Buffer `buf` as a WebSocket binary frame; always succeeds immediately.
    ///
    /// The frame is written to the inner stream on the next `poll_flush`.
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        encode_binary_frame(buf, &mut self.write_buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "webtunnel: write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Queue close frame (idempotent — only if nothing else is pending)
        if this.write_buf.is_empty() {
            encode_close_frame(&mut this.write_buf);
        }

        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => break, // Best-effort on shutdown
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
            }
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ── WebTunnelServerStream ─────────────────────────────────────────────────────

/// Server-side WebSocket transport (RFC 6455).
///
/// Accepts an incoming HTTP/1.1 WebSocket upgrade request, responds with
/// `101 Switching Protocols`, then wraps the stream for transparent framing:
/// - **Read**: incoming client frames are masked — automatically unmasked.
/// - **Write**: outgoing server frames are unmasked (per RFC 6455 §5.1).
///
/// # Usage (relay)
/// ```ignore
/// let ws = WebTunnelServerStream::accept(tls_stream, "/construct-ice").await?;
/// tokio::io::copy_bidirectional(&mut ws, &mut upstream).await?;
/// ```
#[cfg(feature = "server")]
pub struct WebTunnelServerStream<S> {
    inner: S,
    raw_buf: BytesMut,     // raw bytes from wire (undecoded frames)
    payload_buf: BytesMut, // decoded payload ready for caller
    pong_buf: BytesMut,    // queued pong frames to flush before writes
    write_buf: BytesMut,   // encoded frames pending flush
    closed: bool,
}

#[cfg(feature = "server")]
const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[cfg(feature = "server")]
impl<S: AsyncRead + AsyncWrite + Unpin> WebTunnelServerStream<S> {
    /// Perform the HTTP/1.1 WebSocket server handshake.
    ///
    /// Reads the upgrade request, validates `Upgrade: websocket`,
    /// computes `Sec-WebSocket-Accept` via SHA-1 (RFC 6455 §4.2.2),
    /// and writes the `101 Switching Protocols` response.
    pub async fn accept(mut inner: S, _path: &str) -> io::Result<Self> {
        use sha1::{Digest, Sha1};

        let mut hdr_buf = vec![0u8; 4096];
        let mut total = 0usize;
        loop {
            if total >= hdr_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "webtunnel-srv: request headers too large",
                ));
            }
            let n = inner.read(&mut hdr_buf[total..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "webtunnel-srv: client closed during handshake",
                ));
            }
            total += n;
            if hdr_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let headers = std::str::from_utf8(&hdr_buf[..total]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "webtunnel-srv: non-UTF8 headers",
            )
        })?;

        let headers_lc = headers.to_lowercase();
        if !headers_lc.contains("upgrade: websocket") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "webtunnel-srv: missing 'Upgrade: websocket'",
            ));
        }

        // Compute Sec-WebSocket-Accept from client's Sec-WebSocket-Key
        let accept_key = headers
            .lines()
            .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
            .and_then(|l| l.splitn(2, ':').nth(1))
            .map(|v| v.trim())
            .map(|key| {
                let mut h = Sha1::new();
                h.update(key.as_bytes());
                h.update(WS_MAGIC.as_bytes());
                B64.encode(h.finalize())
            })
            .unwrap_or_else(|| "dGhlIHNhbXBsZSBub25jZQ==".to_owned());

        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept_key}\r\n\
             \r\n"
        );
        inner.write_all(response.as_bytes()).await?;
        inner.flush().await?;

        // Bytes after header boundary belong to the WebSocket stream
        let mut raw_buf = BytesMut::with_capacity(65536);
        if let Some(pos) = hdr_buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
            let ws_start = pos + 4;
            if ws_start < total {
                raw_buf.extend_from_slice(&hdr_buf[ws_start..total]);
            }
        }

        Ok(Self {
            inner,
            raw_buf,
            payload_buf: BytesMut::with_capacity(65536),
            pong_buf: BytesMut::with_capacity(128),
            write_buf: BytesMut::with_capacity(4096),
            closed: false,
        })
    }
}

/// Encode `payload` as an **unmasked** binary WebSocket frame (server → client).
///
/// Servers MUST NOT mask frames (RFC 6455 §5.1).
#[cfg(feature = "server")]
fn encode_server_frame(payload: &[u8], dst: &mut BytesMut) {
    let len = payload.len();
    dst.put_u8(0x82); // FIN=1, binary
    if len <= 125 {
        dst.put_u8(len as u8);
    } else if len <= 65535 {
        dst.put_u8(126);
        dst.put_u16(len as u16);
    } else {
        dst.put_u8(127);
        dst.put_u64(len as u64);
    }
    dst.put_slice(payload);
}

#[cfg(feature = "server")]
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebTunnelServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.closed {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Decode all complete frames from raw_buf into payload_buf
            let mut pong = BytesMut::new();
            loop {
                match try_decode_frame(&mut this.raw_buf, &mut this.payload_buf, &mut pong) {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                    Ok(None) => break,
                    Ok(Some(_)) => {
                        this.pong_buf.extend_from_slice(&pong);
                        pong.clear();
                    }
                }
            }

            if !this.payload_buf.is_empty() {
                let n = buf.remaining().min(this.payload_buf.len());
                buf.put_slice(&this.payload_buf[..n]);
                this.payload_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // Read more raw bytes from inner
            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.raw_buf.extend_from_slice(tmp_buf.filled());
                }
            }
        }
    }
}

#[cfg(feature = "server")]
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebTunnelServerStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Pong frames take priority — prepend them before data
        if !self.pong_buf.is_empty() {
            let pong = std::mem::take(&mut self.pong_buf);
            self.write_buf.extend_from_slice(&pong);
        }
        encode_server_frame(buf, &mut self.write_buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "webtunnel-srv: write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf.is_empty() {
            // Unmasked close frame (server side)
            this.write_buf.put_u8(0x88);
            this.write_buf.put_u8(0x00);
        }
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => break,
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn encode_decode_roundtrip_small() {
        let payload = b"hello construct";
        let mut buf = BytesMut::new();
        encode_binary_frame(payload, &mut buf);

        // buf is a valid masked binary frame; verify structure
        assert_eq!(buf[0], 0x82); // FIN + binary opcode
        assert_eq!(buf[1], 0x80 | payload.len() as u8); // MASK + len
        let key = [buf[2], buf[3], buf[4], buf[5]];
        let decoded: Vec<u8> = buf[6..]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i & 3])
            .collect();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_decode_frame_126() {
        // 200-byte payload → uses 2-byte extended length
        let payload = vec![0xAB_u8; 200];
        let mut buf = BytesMut::new();
        encode_binary_frame(&payload, &mut buf);
        assert_eq!(buf[0], 0x82);
        assert_eq!(buf[1], 0xFE); // MASK + 126
        let ext_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(ext_len, 200);
    }

    #[test]
    fn decode_unmasked_frame() {
        // Simulate a server-sent unmasked binary frame with 5-byte payload
        let payload = b"world";
        let mut raw = BytesMut::new();
        raw.put_u8(0x82); // FIN + binary
        raw.put_u8(payload.len() as u8); // no mask, len=5
        raw.put_slice(payload);

        let mut decoded = BytesMut::new();
        let mut pong = BytesMut::new();
        let result = try_decode_frame(&mut raw, &mut decoded, &mut pong).unwrap();
        assert_eq!(result, Some(0x02));
        assert_eq!(&decoded[..], payload);
        assert!(raw.is_empty());
    }

    #[test]
    fn decode_partial_frame_returns_none() {
        let mut raw = BytesMut::new();
        raw.put_u8(0x82); // only 1 byte — incomplete header
        let mut decoded = BytesMut::new();
        let mut pong = BytesMut::new();
        let result = try_decode_frame(&mut raw, &mut decoded, &mut pong).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn decode_close_frame_returns_err() {
        let mut raw = BytesMut::new();
        raw.put_u8(0x88); // FIN + close
        raw.put_u8(0x00); // no mask, len=0
        let mut decoded = BytesMut::new();
        let mut pong = BytesMut::new();
        let err = try_decode_frame(&mut raw, &mut decoded, &mut pong).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn decode_ping_queues_pong() {
        let ping_payload = b"ping!";
        let mut raw = BytesMut::new();
        raw.put_u8(0x89); // FIN + ping
        raw.put_u8(ping_payload.len() as u8); // no mask
        raw.put_slice(ping_payload);

        let mut decoded = BytesMut::new();
        let mut pong = BytesMut::new();
        let result = try_decode_frame(&mut raw, &mut decoded, &mut pong).unwrap();
        assert_eq!(result, Some(0x09));
        assert!(decoded.is_empty());
        assert!(!pong.is_empty()); // pong frame was queued
        assert_eq!(pong[0], 0x8A); // pong opcode
    }
}
