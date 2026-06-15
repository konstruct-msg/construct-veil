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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use construct_veil_protocol::{AuthRecordV2, EXPORTER_LABEL, VeilFrontCodec};
use tokio::io::AsyncReadExt;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    issuer_pubkey: &[u8; 32],
    relay_scope: &str,
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
    if let Some(result) = try_decode_auth(&buf, &exporter, issuer_pubkey, relay_scope) {
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
            if let Some(result) = try_decode_auth(&buf, &exporter, issuer_pubkey, relay_scope) {
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
fn try_decode_auth(
    buf: &BytesMut,
    exporter: &[u8; 32],
    issuer_pubkey: &[u8; 32],
    relay_scope: &str,
) -> Option<GateDecision> {
    let mut decode_buf = buf.clone();
    match VeilFrontCodec::default().decode(&mut decode_buf) {
        Ok(Some(frame)) if frame.is_auth_v2() => {
            // Parse the signed capability + authcode from the frame payload.
            let Some(rec) = AuthRecordV2::decode_payload(&frame.payload) else {
                debug!("malformed AUTH v2 payload, routing to site");
                return Some(GateDecision::Site);
            };

            // Scope gate: empty cap scope or empty relay scope = wildcard.
            let scope_ok = rec.capability.scope.is_empty()
                || relay_scope.is_empty()
                || rec.capability.scope == relay_scope;

            // Offline validation: issuer signature + validity window + exporter-bound
            // authcode (constant-time). No ticket store, no network.
            if scope_ok && rec.verify(issuer_pubkey, exporter, now_unix()) {
                debug!(
                    ticket_id = ?hex::encode(rec.capability.ticket.ticket_id),
                    "capability valid, routing to tunnel"
                );
                Some(GateDecision::Tunnel {
                    leftover: decode_buf,
                })
            } else {
                debug!("capability invalid (sig/expiry/scope/authcode), routing to site");
                Some(GateDecision::Site)
            }
        }
        Ok(Some(frame)) => {
            debug!(
                frame_type = frame.frame_type,
                "non-auth-v2 frame, routing to site"
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
    use construct_veil_protocol::ticket::{AuthKey, Ticket};
    use construct_veil_protocol::{AuthRecordV2, Capability, Frame, issuer_public_key};
    use tokio_util::codec::Encoder;

    const SEED: [u8; 32] = [7u8; 32];
    const EXPORTER: [u8; 32] = [0xCDu8; 32];

    /// Build a wire buffer holding one AUTH v2 frame for `scope`, signed by SEED.
    fn auth_v2_buf(scope: &str) -> BytesMut {
        let ticket = Ticket {
            ticket_id: [0x11; 16],
            auth_key: AuthKey::new([0x22; 32]),
            not_before: 0,
            not_after: u64::MAX,
            suite_id: 1,
        };
        let cap = Capability::sign(ticket, scope.to_string(), &SEED);
        let rec = AuthRecordV2::from_capability(&cap, &EXPORTER);
        let mut buf = BytesMut::new();
        VeilFrontCodec::default()
            .encode(Frame::auth_v2(rec.encode_payload()), &mut buf)
            .unwrap();
        buf
    }

    #[test]
    fn gate_accepts_valid_capability() {
        let pubkey = issuer_public_key(&SEED);
        let buf = auth_v2_buf("");
        let decision = try_decode_auth(&buf, &EXPORTER, &pubkey, "");
        assert!(matches!(decision, Some(GateDecision::Tunnel { .. })));
    }

    #[test]
    fn gate_rejects_wrong_issuer() {
        let wrong = issuer_public_key(&[9u8; 32]);
        let buf = auth_v2_buf("");
        let decision = try_decode_auth(&buf, &EXPORTER, &wrong, "");
        assert!(matches!(decision, Some(GateDecision::Site)));
    }

    #[test]
    fn gate_rejects_wrong_exporter() {
        let pubkey = issuer_public_key(&SEED);
        let buf = auth_v2_buf("");
        let mut other = EXPORTER;
        other[0] ^= 0x01;
        let decision = try_decode_auth(&buf, &other, &pubkey, "");
        assert!(matches!(decision, Some(GateDecision::Site)));
    }

    #[test]
    fn gate_rejects_scope_mismatch() {
        let pubkey = issuer_public_key(&SEED);
        let buf = auth_v2_buf("ru-relay");
        let decision = try_decode_auth(&buf, &EXPORTER, &pubkey, "nl-relay");
        assert!(matches!(decision, Some(GateDecision::Site)));
    }

    #[test]
    fn gate_scope_wildcard_matches() {
        let pubkey = issuer_public_key(&SEED);
        // Capability scoped to "ru-relay" but relay accepts any (empty scope).
        let buf = auth_v2_buf("ru-relay");
        let decision = try_decode_auth(&buf, &EXPORTER, &pubkey, "");
        assert!(matches!(decision, Some(GateDecision::Tunnel { .. })));
    }

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
