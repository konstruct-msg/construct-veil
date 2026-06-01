//! VeilFrontObfuscator — adapts the veil-front protocol to the [`Obfuscator`] trait.
//!
//! Probe flow:
//! 1. TCP connect to relay
//! 2. TLS 1.3 handshake (uTLS browser profile + SPKI pin)
//! 3. Derive TLS exporter keying material
//! 4. Parse ticket from bundle, build AuthRecord
//! 5. Send AUTH frame as first application data
//! 6. Read first frame back — if DATA, tunnel is live; if not, probe failed

use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::sync::CancellationToken;

use crate::veil::fsm::MethodId;
use crate::veil::obfuscator::{Obfuscator, ObfuscatorError, ObfuscatorHandle, ProbeRequest};
use construct_veil_protocol::{
    AuthRecord, Frame, VeilFrontCodec,
    AUTH_PAYLOAD_LEN, EXPORTER_LABEL, EXPORTER_LEN, FRAME_TYPE_AUTH, FRAME_TYPE_CHAFF,
    FRAME_TYPE_DATA,
};
use construct_veil_protocol::ticket::{
    ticket_from_bytes, ticket_to_bytes, AuthKey, Ticket, AUTH_KEY_LEN, TICKET_ID_LEN,
    TICKET_WIRE_LEN,
};

/// VeilFront probe adapter.
pub struct VeilFrontObfuscator;

impl VeilFrontObfuscator {
    /// Create a new VeilFrontObfuscator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for VeilFrontObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Obfuscator for VeilFrontObfuscator {
    fn method_id(&self) -> MethodId {
        MethodId::VeilFront
    }

    async fn start(
        &self,
        req: &ProbeRequest,
        cancel: CancellationToken,
    ) -> Result<ObfuscatorHandle, ObfuscatorError> {
        let req = req.clone();
        let cancel_probe = cancel.clone();

        let first_byte = async move {
            tokio::select! {
                _ = cancel_probe.cancelled() => {
                    Err(ObfuscatorError::Cancelled)
                }
                result = probe_veil_front(&req) => result,
            }
        };

        let cancel_shutdown = cancel.clone();
        let shutdown = async move {
            cancel_shutdown.cancel();
        };

        Ok(ObfuscatorHandle::new(first_byte, shutdown))
    }
}

/// Execute the veil-front probe: TCP + TLS + auth record.
async fn probe_veil_front(req: &ProbeRequest) -> Result<(), ObfuscatorError> {
    let relay_addr = &req.relay_addr;

    // TCP connect with timeout.
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(relay_addr))
        .await
        .map_err(|_| ObfuscatorError::Timeout)?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                ObfuscatorError::ConnectionRefused
            } else {
                ObfuscatorError::Io(e)
            }
        })?;

    tcp.set_nodelay(true).map_err(|e| ObfuscatorError::Io(e))?;

    // TLS handshake with SPKI pinning.
    let tls_sni = &req.tls_sni;
    let spki_hex = &req.spki_hex;

    let tls_stream = dial_utls_tcp(tcp, tls_sni, spki_hex, relay_addr).await?;

    // Parse ticket from the bundle (PoC: bundle is base64-encoded 65-byte ticket).
    let ticket = parse_ticket(&req.veil_front_ticket_b64)?;

    // Derive TLS exporter keying material (32 bytes).
    let exporter = derive_exporter(&tls_stream)?;

    // Build auth record: HMAC(auth_key, exporter || ticket_id || not_after).
    let auth = AuthRecord::from_ticket(&ticket, &exporter);
    let auth_frame = Frame::auth({
        let mut buf = BytesMut::with_capacity(AUTH_PAYLOAD_LEN);
        buf.put_slice(&auth.ticket_id);
        buf.put_slice(&auth.authcode);
        buf.freeze()
    });

    // Send AUTH frame as first application data.
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let mut codec = VeilFrontCodec::default();
    let mut tx_buf = BytesMut::new();
    codec
        .encode(auth_frame, &mut tx_buf)
        .map_err(|e| ObfuscatorError::Io(e))?;
    tokio::io::AsyncWriteExt::write_all(&mut writer, &tx_buf)
        .await
        .map_err(|e| ObfuscatorError::Io(e))?;
    tokio::io::AsyncWriteExt::flush(&mut writer)
        .await
        .map_err(|e| ObfuscatorError::Io(e))?;

    // Read the first frame back from the relay.
    // If the relay recognised our auth, it will send DATA frames (tunnel).
    // If not, it will send site content — which won't parse as valid frames
    // or will come as unexpected data.
    let mut rx_buf = BytesMut::with_capacity(4096);
    let mut total_read = 0;
    loop {
        let n = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::io::AsyncReadExt::read_buf(&mut reader, &mut rx_buf),
        )
        .await
        .map_err(|_| ObfuscatorError::Timeout)?
        .map_err(|e| ObfuscatorError::Io(e))?;

        if n == 0 {
            // EOF — relay closed connection without sending tunnel data.
            return Err(ObfuscatorError::Handshake(
                "relay closed connection after auth".into(),
            ));
        }

        total_read += n;

        // Try to decode a frame.
        let mut decode_buf = rx_buf.clone();
        match codec.decode(&mut decode_buf) {
            Ok(Some(frame)) => {
                match frame.frame_type {
                    FRAME_TYPE_DATA => {
                        // Tunnel is live — relay forwarded backend data as DATA frame.
                        return Ok(());
                    }
                    FRAME_TYPE_CHAFF => {
                        // Relay sent chaff — this is suspicious but could be a relay-side
                        // padding mode. Continue reading.
                        rx_buf = decode_buf;
                        continue;
                    }
                    FRAME_TYPE_AUTH => {
                        // Relay sent AUTH back — protocol error.
                        return Err(ObfuscatorError::Handshake(
                            "relay echoed AUTH frame".into(),
                        ));
                    }
                    other => {
                        return Err(ObfuscatorError::Handshake(format!(
                            "unexpected frame type: 0x{:02x}",
                            other
                        )));
                    }
                }
            }
            Ok(None) => {
                // Need more data — continue reading.
                if total_read > 65536 {
                    // Received >64KB without a valid frame — likely site content.
                    return Err(ObfuscatorError::Handshake(
                        "received >64KB without valid frame (likely routed to site)".into(),
                    ));
                }
                rx_buf = decode_buf;
                continue;
            }
            Err(e) => {
                // Decoding error — the data is not valid veil-front frames.
                // This means the relay routed us to the site (auth failed).
                return Err(ObfuscatorError::Handshake(format!(
                    "frame decode error (routed to site): {e}"
                )));
            }
        }
    }
}

/// Dial TLS using uTLS with SPKI pinning.
async fn dial_utls_tcp(
    tcp: TcpStream,
    tls_sni: &str,
    spki_hex: &str,
    relay_addr: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ObfuscatorError> {
    let (connector, server_name) = crate::tls_pinned::build_connector(
        tls_sni,
        spki_hex,
        relay_addr,
        crate::TlsProfile::Chrome131,
        // veil-front uses HTTP/2 (h2c inner, h2 on wire).
        Some(vec![b"h2".to_vec()]),
    )
    .map_err(|e| ObfuscatorError::Tls(e.to_string()))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| {
            let err_str = e.to_string();
            if (err_str.contains("alert") && err_str.contains("40"))
                || err_str.contains("handshake_failure")
            {
                ObfuscatorError::FingerprintBlocked
            } else if err_str.contains("cert")
                || err_str.contains("verify")
                || err_str.contains("certificate")
            {
                ObfuscatorError::CertProblem(err_str)
            } else {
                ObfuscatorError::Tls(err_str)
            }
        })
}

/// Derive the TLS exporter keying material (32 bytes).
fn derive_exporter(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; EXPORTER_LEN], ObfuscatorError> {
    // Get the underlying rustls connection.
    let (_, conn) = tls_stream.get_ref();
    let mut exporter = [0u8; EXPORTER_LEN];

    conn.export_keying_material(&mut exporter, EXPORTER_LABEL.as_bytes(), Some(&[]))
        .map_err(|e| ObfuscatorError::Tls(format!("TLS exporter failed: {e}")))?;

    Ok(exporter)
}

/// Parse a veil-front ticket from the bundle string.
///
/// PoC format: the bundle IS a base64-encoded 65-byte ticket blob.
/// Production: the bundle will be a manifest descriptor containing the ticket.
fn parse_ticket(bundle_b64: &str) -> Result<Ticket, ObfuscatorError> {
    if bundle_b64.is_empty() {
        return Err(ObfuscatorError::Handshake(
            "no veil-front ticket in bundle".into(),
        ));
    }

    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bundle_b64)
        .map_err(|e| ObfuscatorError::Handshake(format!("ticket base64 decode: {e}")))?;

    ticket_from_bytes(&raw).ok_or_else(|| {
        ObfuscatorError::Handshake(format!(
            "invalid ticket: expected {TICKET_WIRE_LEN} bytes, got {}",
            raw.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_id_is_veil_front() {
        let obf = VeilFrontObfuscator::new();
        assert_eq!(obf.method_id(), MethodId::VeilFront);
    }

    #[test]
    fn parse_ticket_from_base64() {
        // Build a valid 65-byte ticket.
        let ticket = Ticket {
            ticket_id: [0xAB; TICKET_ID_LEN],
            auth_key: AuthKey::new([0xCD; AUTH_KEY_LEN]),
            not_before: 1_000_000,
            not_after: 1_000_000 + 6 * 3600,
            suite_id: 0x01,
        };

        let bytes = ticket_to_bytes(&ticket);
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);

        let parsed = parse_ticket(&b64).expect("parse should succeed");
        assert_eq!(parsed.ticket_id, ticket.ticket_id);
        assert_eq!(parsed.auth_key.0, ticket.auth_key.0);
        assert_eq!(parsed.not_before, ticket.not_before);
        assert_eq!(parsed.not_after, ticket.not_after);
        assert_eq!(parsed.suite_id, ticket.suite_id);
    }

    #[test]
    fn parse_ticket_empty_bundle() {
        let err = parse_ticket("").unwrap_err();
        assert!(matches!(err, ObfuscatorError::Handshake(_)));
    }

    #[test]
    fn parse_ticket_invalid_base64() {
        let err = parse_ticket("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, ObfuscatorError::Handshake(_)));
    }

    #[test]
    fn parse_ticket_wrong_length() {
        // 10 bytes, not 65.
        let bytes = [0u8; 10];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let err = parse_ticket(&b64).unwrap_err();
        assert!(matches!(err, ObfuscatorError::Handshake(_)));
    }
}
