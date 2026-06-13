//! VeilFrontObfuscator — adapts the veil-front protocol to the [`Obfuscator`] trait.
//!
//! Probe flow:
//! 1. TCP connect to relay
//! 2. TLS 1.3 handshake (uTLS browser profile + SPKI pin)
//! 3. Derive TLS exporter keying material
//! 4. Parse ticket from bundle, build AuthRecord, send AUTH frame
//! 5. Send the HTTP/2 client preface inside a DATA frame to drive the h2c backend
//! 6. Read a framed DATA response back — its arrival proves the tunnel is live
//!
//! After a probe wins the race, the coordinator runs [`run_veil_front_ferry`] on
//! a fresh local listener: it re-dials + re-auths and ferries the gRPC client's
//! h2c bytes as `DATA` frames (sketch §7), dropping any `CHAFF` from the relay.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::sync::CancellationToken;

use crate::veil::fsm::MethodId;
use crate::veil::obfuscator::{Obfuscator, ObfuscatorError, ObfuscatorHandle, ProbeRequest};
use crate::veil::veil_front::WriteStrategy;
use construct_veil_protocol::ticket::{TICKET_WIRE_LEN, Ticket, ticket_from_bytes};
use construct_veil_protocol::{
    AUTH_PAYLOAD_LEN, AuthRecord, EXPORTER_LABEL, EXPORTER_LEN, FRAME_TYPE_CHAFF, FRAME_TYPE_DATA,
    Frame, LENGTH_BUCKETS, VeilFrontCodec,
};

/// HTTP/2 client connection preface (RFC 7540 §3.5) + an empty SETTINGS frame.
/// Sent inside the first DATA frame so the h2c backend responds, giving the
/// probe a real end-to-end first byte without a full gRPC exchange.
const H2_PREFACE_AND_SETTINGS: &[u8] =
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

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

/// Dial the relay, complete TLS (uTLS + SPKI pin), and send the AUTH frame.
///
/// Returns the authenticated TLS stream with the AUTH frame already written and
/// flushed. The caller drives the tunnel (probe round-trip or data ferry).
async fn dial_and_authenticate(
    relay_addr: &str,
    tls_sni: &str,
    spki_hex: &str,
    ticket_b64: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ObfuscatorError> {
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
    tcp.set_nodelay(true).map_err(ObfuscatorError::Io)?;

    // TLS handshake with SPKI pinning.
    let mut tls_stream = dial_utls_tcp(tcp, tls_sni, spki_hex, relay_addr).await?;

    // Parse the base64-encoded 65-byte veil-front ticket blob.
    let ticket = parse_ticket(ticket_b64)?;

    // Derive TLS exporter keying material (32 bytes) and build the auth record:
    // HMAC(auth_key, exporter || ticket_id || not_after).
    let exporter = derive_exporter(&tls_stream)?;
    let auth = AuthRecord::from_ticket(&ticket, &exporter);

    // Send the AUTH frame as the first application record, encoded with the SAME
    // wire codec the relay's gate decodes with: `WIRE_VER || type || payload_len
    // || pad_len || payload`. Do NOT use `AuthRecord::encode()` — it emits a
    // legacy, codec-incompatible framing (no version byte, no pad_len), which the
    // relay rejects → routes the connection to the cover site.
    let mut auth_payload = BytesMut::with_capacity(AUTH_PAYLOAD_LEN);
    auth_payload.extend_from_slice(&auth.ticket_id);
    auth_payload.extend_from_slice(&auth.authcode);
    let mut auth_frame = BytesMut::new();
    VeilFrontCodec::default()
        .with_buckets(LENGTH_BUCKETS)
        .encode(Frame::auth(auth_payload.freeze()), &mut auth_frame)
        .map_err(ObfuscatorError::Io)?;
    tls_stream
        .write_all(&auth_frame)
        .await
        .map_err(ObfuscatorError::Io)?;
    tls_stream.flush().await.map_err(ObfuscatorError::Io)?;

    Ok(tls_stream)
}

/// Execute the veil-front probe: auth, then drive a real end-to-end round-trip.
///
/// The relay never signals its branch decision (sketch §10), so we cannot infer
/// success from a relay-emitted marker. Instead we send the HTTP/2 client preface
/// inside a DATA frame; a valid tunnel forwards it to the h2c backend, whose
/// SETTINGS reply comes back wrapped in a DATA frame. Receiving that DATA frame
/// proves the tunnel is live. If auth failed we were routed to the cover site,
/// whose bytes do not decode as a DATA frame → probe fails.
async fn probe_veil_front(req: &ProbeRequest) -> Result<(), ObfuscatorError> {
    let tls_stream = dial_and_authenticate(
        &req.relay_addr,
        &req.tls_sni,
        &req.spki_hex,
        &req.veil_front_ticket_b64,
    )
    .await?;

    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);

    // Drive the h2c backend: send the preface inside a DATA frame.
    let mut tx_buf = BytesMut::new();
    codec
        .encode(
            Frame::data(Bytes::from_static(H2_PREFACE_AND_SETTINGS)),
            &mut tx_buf,
        )
        .map_err(ObfuscatorError::Io)?;
    writer
        .write_all(&tx_buf)
        .await
        .map_err(ObfuscatorError::Io)?;
    writer.flush().await.map_err(ObfuscatorError::Io)?;

    // Read frames back; a DATA frame confirms the tunnel.
    let mut rx_buf = BytesMut::with_capacity(4096);
    let mut total_read = 0;
    loop {
        // 7s: the relay opens a fresh TLS-upstream to the backend on the first
        // tunnel frame; a cold relay→backend handshake can exceed a tight 3s window
        // and spuriously fail the probe (veil-front is the only method now).
        let n = tokio::time::timeout(Duration::from_secs(7), reader.read_buf(&mut rx_buf))
            .await
            .map_err(|_| ObfuscatorError::Timeout)?
            .map_err(ObfuscatorError::Io)?;

        if n == 0 {
            return Err(ObfuscatorError::Handshake(
                "relay closed connection after auth".into(),
            ));
        }
        total_read += n;

        match codec.decode(&mut rx_buf) {
            Ok(Some(frame)) => match frame.frame_type {
                FRAME_TYPE_DATA => return Ok(()),
                FRAME_TYPE_CHAFF => continue, // relay-side cover, keep reading
                other => {
                    return Err(ObfuscatorError::Handshake(format!(
                        "unexpected frame type after auth: 0x{other:02x} (routed to site?)"
                    )));
                }
            },
            Ok(None) => {
                if total_read > 65536 {
                    return Err(ObfuscatorError::Handshake(
                        "received >64KB without a DATA frame (likely routed to site)".into(),
                    ));
                }
                continue;
            }
            Err(e) => {
                return Err(ObfuscatorError::Handshake(format!(
                    "frame decode error (routed to site): {e}"
                )));
            }
        }
    }
}

/// Run the veil-front data ferry for one accepted local connection.
///
/// Re-dials the relay, re-authenticates, then bridges the local h2c gRPC stream
/// and the tunnel:
/// - **local → relay:** `WriteStrategy` — payload DATA frames with FRONT-style
///   chaff injection (payload priority, no HOL blocking, length bucketing).
/// - **relay → local:** de-frame DATA payloads, drop CHAFF.
///
/// The up-stream uses the `FrontChaffScheduler` from M6 (§8 of the plan):
/// chaff is injected at connection start then tapers off; payload always wins.
///
/// Returns the `WriteStrategy` with final metrics (overhead ratio etc).
pub async fn run_veil_front_ferry_with_metrics(
    local: TcpStream,
    relay_addr: &str,
    tls_sni: &str,
    spki_hex: &str,
    ticket_b64: &str,
) -> Result<WriteStrategy, ObfuscatorError> {
    let tls_stream = dial_and_authenticate(relay_addr, tls_sni, spki_hex, ticket_b64).await?;

    let (relay_rd, relay_wr) = tokio::io::split(tls_stream);
    let (local_rd, local_wr) = tokio::io::split(local);

    // Use a WriteStrategy for the up-stream: payload + chaff with priority.
    let strategy = WriteStrategy::new();

    // local h2c → payload queue + chaff scheduler → DATA/CHAFF frames → relay
    //
    // Length bucketing is handled by the codec (encoder pads payloads up to the
    // next `LENGTH_BUCKETS` boundary with zero bytes; decoder on the relay side
    // honours `pad_len` and discards them).
    let up = async move {
        let mut strategy = strategy;
        let mut local_rd = local_rd;
        let mut relay_wr = relay_wr;
        let mut up_codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let mut rbuf = [0u8; 8192];

        loop {
            // 1. Check if there's a frame ready to send (payload or chaff).
            if let Some(frame) = strategy.next_frame() {
                let frame_type = frame.frame_type;
                let mut out = BytesMut::with_capacity(frame.payload.len() + 16);
                up_codec
                    .encode(frame, &mut out)
                    .map_err(ObfuscatorError::Io)?;
                relay_wr
                    .write_all(&out)
                    .await
                    .map_err(ObfuscatorError::Io)?;
                relay_wr.flush().await.map_err(ObfuscatorError::Io)?;

                // If we just sent chaff, continue the loop to check for more.
                if frame_type == FRAME_TYPE_CHAFF {
                    continue;
                }
                // If we sent payload, try to read more from local.
            }

            // 2. Read from local (non-blocking-ish: use a short timeout to allow
            //    chaff injection when the local stream is idle).
            let read_fut = local_rd.read(&mut rbuf);
            let n = match tokio::time::timeout(Duration::from_millis(20), read_fut).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => n,     // n > 0 guaranteed by the arm above
                Ok(Err(e)) => return Err(ObfuscatorError::Io(e)),
                Err(_) => {
                    // Timeout — local is idle, let chaff scheduler inject.
                    continue;
                }
            };

            // Push payload into the strategy's queue.
            strategy
                .payload_queue
                .push(Frame::data(Bytes::copy_from_slice(&rbuf[..n])));
        }

        relay_wr.shutdown().await.map_err(ObfuscatorError::Io)?;
        Ok(strategy)
    };

    // relay DATA frames → local; drop CHAFF
    let down = async {
        let mut relay_rd = relay_rd;
        let mut local_wr = local_wr;
        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Drain any complete frames already in the buffer.
            loop {
                match codec.decode(&mut buf).map_err(ObfuscatorError::Io)? {
                    Some(frame) => match frame.frame_type {
                        FRAME_TYPE_DATA => {
                            local_wr
                                .write_all(&frame.payload)
                                .await
                                .map_err(ObfuscatorError::Io)?;
                        }
                        FRAME_TYPE_CHAFF => { /* cover traffic — discard */ }
                        _ => { /* AUTH/unknown mid-stream — ignore */ }
                    },
                    None => break,
                }
            }

            let n = relay_rd
                .read_buf(&mut buf)
                .await
                .map_err(ObfuscatorError::Io)?;
            if n == 0 {
                break;
            }
        }
        local_wr.shutdown().await.map_err(ObfuscatorError::Io)
    };

    let (r1, r2) = tokio::join!(up, down);
    let strategy = r1?;
    r2?;

    Ok(strategy)
}

/// Run the veil-front data ferry for one accepted local connection.
///
/// Convenience wrapper around [`run_veil_front_ferry_with_metrics`] that discards
/// the final metrics. Use the `_with_metrics` variant when you need overhead stats.
pub async fn run_veil_front_ferry(
    local: TcpStream,
    relay_addr: &str,
    tls_sni: &str,
    spki_hex: &str,
    ticket_b64: &str,
) -> Result<(), ObfuscatorError> {
    let _ =
        run_veil_front_ferry_with_metrics(local, relay_addr, tls_sni, spki_hex, ticket_b64).await?;
    Ok(())
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

    connector.connect(server_name, tcp).await.map_err(|e| {
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

/// Parse a base64-encoded veil-front ticket.
///
/// Wire format: 65 raw bytes (see `construct_veil_protocol::ticket`), base64-
/// encoded for transport over string-typed channels (FFI, manifest).
/// An empty input returns a handshake error, which the coordinator treats as
/// "veil-front not configured" — the probe fails and the FSM moves on.
fn parse_ticket(ticket_b64: &str) -> Result<Ticket, ObfuscatorError> {
    if ticket_b64.is_empty() {
        return Err(ObfuscatorError::Handshake(
            "veil-front ticket is empty (not configured)".into(),
        ));
    }

    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ticket_b64)
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
    use construct_veil_protocol::ticket::{AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN, ticket_to_bytes};

    /// Live latency breakdown against the production relay. Requires the matching
    /// debug ticket in the relay's tickets.json. Ignored by default; run with:
    ///   cargo test -p construct-veil --features utls,coordinator --lib \
    ///     veil::veil_front_adapter::tests::live_latency -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_latency() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Ticket is a probing-resistance secret — never hardcode it. Source order:
            //   1. VEIL_TEST_TICKET env (override)
            //   2. the gitignored, server-synced deploy/data/tickets/tickets.json (first entry)
            // tickets.json is a JSON array of base64 strings; base64 has no '"', so the
            // first quoted token is the first ticket (no serde_json dep needed).
            let ticket = std::env::var("VEIL_TEST_TICKET")
                .ok()
                .filter(|t| !t.is_empty())
                .or_else(|| {
                    std::fs::read_to_string("deploy/data/tickets/tickets.json")
                        .ok()
                        .and_then(|s| s.split('"').nth(1).map(str::to_string))
                        .filter(|t| !t.is_empty())
                })
                .unwrap_or_default();
            if ticket.is_empty() {
                eprintln!(
                    "skip: no ticket — set VEIL_TEST_TICKET or populate deploy/data/tickets/tickets.json"
                );
                return;
            }
            let req = ProbeRequest {
                relay_addr: std::env::var("VEIL_TEST_RELAY")
                    .unwrap_or_else(|_| "api.divany-kresla.uk:443".into()),
                bundle: String::new(),
                tls_sni: "api.divany-kresla.uk".into(),
                spki_hex: std::env::var("VEIL_TEST_SPKI")
                    .unwrap_or_else(|_| "b2361c0448a33a10e6521300aa4de8d8fe402791dd4fd5b0fe10fbb09457570c".into()),
                host_header: "api.divany-kresla.uk".into(),
                wt_base_path: "/api/stream".into(),
                veil_front_ticket_b64: ticket,
            };

            for i in 1..=3 {
                let t0 = std::time::Instant::now();
                let tls = dial_and_authenticate(
                    &req.relay_addr, &req.tls_sni, &req.spki_hex, &req.veil_front_ticket_b64,
                ).await.expect("dial+auth");
                let t_auth = t0.elapsed();

                let (mut reader, mut writer) = tokio::io::split(tls);
                let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
                let mut tx = BytesMut::new();
                codec.encode(Frame::data(Bytes::from_static(H2_PREFACE_AND_SETTINGS)), &mut tx).unwrap();
                let t1 = std::time::Instant::now();
                writer.write_all(&tx).await.unwrap();
                writer.flush().await.unwrap();

                let mut rx = BytesMut::with_capacity(4096);
                let mut first_data = None;
                loop {
                    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_buf(&mut rx))
                        .await.expect("rtt timeout").expect("read");
                    if n == 0 { break; }
                    match codec.decode(&mut rx) {
                        Ok(Some(f)) if f.frame_type == FRAME_TYPE_DATA => { first_data = Some(t1.elapsed()); break; }
                        Ok(Some(_)) => continue,
                        Ok(None) => continue,
                        Err(e) => panic!("decode: {e}"),
                    }
                }
                eprintln!("[{i}] dial+TLS+auth={:?}  preface→firstDATA={:?}", t_auth, first_data);
            }
        });
    }

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
    fn parse_ticket_empty_input() {
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
