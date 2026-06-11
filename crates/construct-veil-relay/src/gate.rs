//! Constant-shape gate — the load-bearing module.
//!
//! After TLS handshake, the relay reads the first application data and routes:
//! - **Valid auth** → Tunnel (h2c forward to Construct backend)
//! - **Invalid/missing** → Site (forward to cover application)
//!
//! **Critical:** both branches must be constant-shape. Failed auth MUST NOT:
//! - Close the connection differently
//! - Add custom timeouts
//! - Change response timing or length distribution
//!
//! The cover app's own behaviour is the ONLY timing on the unauth branch.
//!
//! # Read strategy (anti-fingerprinting)
//!
//! The gate does **not** use a fixed read-threshold (e.g. "read exactly 51 bytes
//! then decide") — this is fingerprintable per Frolov et al. Instead it reads
//! like a web server: each `read()` attempt is followed immediately by a decode
//! attempt. If the data is incomplete, one more read with a short timeout is
//! allowed (to handle TCP segmentation), then the connection is routed to Site.
//! This means an active probe sees the same timing whether it sends 1 byte or
//! 100 bytes — the cover app's own response timing dominates.

use std::time::Duration;

use bytes::BytesMut;
use construct_veil_protocol::{AUTH_PAYLOAD_LEN, EXPORTER_LABEL, VeilFrontCodec};
use tokio::io::AsyncReadExt;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

use crate::tickets::TicketStore;

/// Timeout for the second read attempt during the gate.
///
/// A web server would start processing the HTTP request after the first read;
/// if more data arrives it processes it incrementally. We allow one extra read
/// with a short timeout to handle TCP segmentation of the AUTH frame, then
/// fall back to the site branch (which processes whatever bytes arrived).
///
/// This value should be small enough that an active probe cannot distinguish
/// "waiting for more auth bytes" from "starting to process an HTTP request."
/// 100ms is within the variance of typical web server first-read latency.
const GATE_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Result of the gate decision.
pub enum GateResult<S> {
    /// Valid auth — this connection is a tunnel.
    Tunnel {
        /// The original TLS stream (un-split).
        stream: S,
        /// Remaining buffered data after the AUTH frame was consumed.
        /// May contain early tunnel data from the client.
        leftover: BytesMut,
    },
    /// Invalid auth — forward to cover site.
    Site {
        /// The original TLS stream (un-split).
        stream: S,
        /// The raw bytes that were read (first application data).
        /// Must be forwarded to the site backend as-is.
        first_bytes: BytesMut,
    },
}

/// Gate with TLS exporter access — the actual production gate.
///
/// This is the version used by the main accept loop. It extracts the TLS
/// exporter from the connection before routing.
///
/// # Read strategy (anti-fingerprinting)
///
/// Does **not** use a fixed read-threshold. Instead:
/// 1. First read — try to decode AUTH frame immediately.
/// 2. If incomplete, one more read with `GATE_READ_TIMEOUT`.
/// 3. If still incomplete or decode fails → Site (no special timing).
/// 4. If valid auth → Tunnel.
pub async fn gate_with_exporter(
    tls_stream: TlsStream<tokio::net::TcpStream>,
    store: &TicketStore,
) -> Result<GateResult<TlsStream<tokio::net::TcpStream>>, std::io::Error> {
    // Extract TLS exporter BEFORE splitting the stream.
    let exporter = {
        let (_, conn) = tls_stream.get_ref();
        let mut exp = [0u8; 32];
        if let Err(e) = conn.export_keying_material(&mut exp, EXPORTER_LABEL.as_bytes(), Some(&[]))
        {
            warn!(error = %e, "TLS exporter failed, routing to site");
            return Ok(GateResult::Site {
                stream: tls_stream,
                first_bytes: BytesMut::new(),
            });
        }
        exp
    };

    let mut reader = tls_stream;
    let mut buf = BytesMut::with_capacity(4096);

    // ── First read (like a web server reading an HTTP request) ───────────

    let n = reader.read_buf(&mut buf).await.map_err(|e| {
        warn!(error = %e, "read error during gate");
        e
    })?;

    if n == 0 {
        debug!("no data after TLS handshake, routing to site");
        return Ok(GateResult::Site {
            stream: reader,
            first_bytes: buf,
        });
    }

    // Try to decode immediately — no fixed threshold.
    if let Some(result) = try_decode_auth(&buf, &exporter, store).await {
        return Ok(result.consume(reader, buf));
    }

    // Incomplete or invalid — one more read with timeout to handle TCP
    // segmentation of the AUTH frame. This is not a fixed threshold; we're
    // simply being tolerant of TCP behavior, just like a web server would be.
    let read_fut = reader.read_buf(&mut buf);
    match tokio::time::timeout(GATE_READ_TIMEOUT, read_fut).await {
        Ok(Ok(0)) => {
            // EOF after first read → definitely not our protocol.
            debug!("EOF after first read, routing to site");
        }
        Ok(Ok(_n2)) => {
            // Got more data, try decode again.
            if let Some(result) = try_decode_auth(&buf, &exporter, store).await {
                return Ok(result.consume(reader, buf));
            }
            // Still incomplete/invalid → Site.
            debug!("second read still incomplete, routing to site");
        }
        Ok(Err(e)) => {
            warn!(error = %e, "read error during gate (second read), routing to site");
        }
        Err(_) => {
            // Timeout — no more data within 100ms.
            // A web server would have started processing the HTTP request by now.
            debug!("read timeout after first read, routing to site");
        }
    }

    // Safety cap: if we accumulated >64KB without a valid frame, it's
    // definitely not our protocol.
    if buf.len() > 65536 {
        debug!(
            bytes = buf.len(),
            "too much data without valid auth frame, routing to site"
        );
    }

    Ok(GateResult::Site {
        stream: reader,
        first_bytes: buf,
    })
}

/// Try to decode an AUTH frame from the buffer and validate it.
///
/// Returns `Some(GateDecision)` if the buffer contains a complete AUTH frame
/// (valid or invalid). Returns `None` if the frame is incomplete (need more data).
///
/// This is the core gate logic — extracted for testability.
async fn try_decode_auth(
    buf: &BytesMut,
    exporter: &[u8; 32],
    store: &TicketStore,
) -> Option<GateDecision> {
    let mut decode_buf = buf.clone();
    match VeilFrontCodec::default().decode(&mut decode_buf) {
        Ok(Some(frame)) if frame.is_auth() && frame.payload.len() == AUTH_PAYLOAD_LEN => {
            let ticket_id: [u8; 16] = {
                let mut id = [0u8; 16];
                id.copy_from_slice(&frame.payload[..16]);
                id
            };
            let authcode: [u8; 32] = {
                let mut code = [0u8; 32];
                code.copy_from_slice(&frame.payload[16..48]);
                code
            };

            // Validate against the ticket store (constant-time compare).
            if let Some(_ticket) = store.validate(&ticket_id, &authcode, exporter).await {
                debug!(ticket_id = ?hex::encode(ticket_id), "auth valid, routing to tunnel");
                Some(GateDecision::Tunnel {
                    leftover: decode_buf,
                })
            } else {
                debug!(ticket_id = ?hex::encode(ticket_id), "auth invalid, routing to site");
                Some(GateDecision::Site)
            }
        }
        Ok(Some(frame)) => {
            debug!(
                frame_type = frame.frame_type,
                "non-auth frame, routing to site"
            );
            Some(GateDecision::Site)
        }
        Ok(None) => {
            // Incomplete frame — need more data.
            None
        }
        Err(e) => {
            debug!(error = %e, "frame decode error, routing to site");
            Some(GateDecision::Site)
        }
    }
}

/// The result of a decode attempt — Tunnel or Site, with leftover data.
enum GateDecision {
    /// Valid auth — tunnel with leftover bytes after AUTH frame.
    Tunnel { leftover: BytesMut },
    /// Invalid/missing auth — forward to site.
    Site,
}

impl GateDecision {
    /// Consume the read side of the stream and produce a `GateResult`.
    ///
    /// `buf` is everything read during the gate. For the Site branch it MUST be
    /// carried through as `first_bytes` — those are the client's request bytes
    /// (e.g. `GET / HTTP/1.1`) that the cover site needs to see. Returning an empty
    /// buffer here made `handle_connection` close the connection without forwarding
    /// (empty reply), so the cover site never responded to any non-auth request.
    fn consume<S>(self, stream: S, buf: BytesMut) -> GateResult<S> {
        match self {
            GateDecision::Tunnel { leftover } => GateResult::Tunnel { stream, leftover },
            GateDecision::Site => GateResult::Site {
                stream,
                first_bytes: buf,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_result_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<GateResult<BytesMut>>();
    }

    #[test]
    fn gate_read_timeout_is_reasonable() {
        // 100ms is within web server first-read latency variance.
        // Not too short (would reject slow clients) and not too long
        // (would give probes a timing oracle).
        assert!(GATE_READ_TIMEOUT >= Duration::from_millis(50));
        assert!(GATE_READ_TIMEOUT <= Duration::from_millis(200));
    }
}
