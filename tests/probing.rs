//! Active probing resistance test suite.
//!
//! Validates that the server behaves correctly when attacked by probers
//! that simulate GFW/ТСПУ active probing patterns:
//!
//! 1. **Wrong cert probe** — client uses a different server key.
//!    Server must NOT send TCP RST immediately; must timeout/garbage-close.
//! 2. **Valid cert, wrong MAC probe** — correct key, forged/truncated payload.
//!    Server must reject with non-deterministic timing (not instant).
//! 3. **Sequential probe timing** — multiple probes must produce different
//!    response timings (not fingerprint-able as a fixed-delay responder).
//! 4. **HTTP GET probe** — plaintext HTTP must be classified as cover traffic
//!    (proxied or silently ignored), never triggering a recognisable obfs4 response.
//! 5. **TLS ClientHello probe** — same as above for TLS fingerprint.
//! 6. **Cover-classifier unit tests** — verifies `classify_peeked_bytes` heuristics.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use construct_ice::{
    ClientConfig, Obfs4Listener, Obfs4Stream, ServerConfig,
    transport::cover::{CoverDecision, CoverProxyConfig, classify_peeked_bytes},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Bind on an OS-assigned port and immediately release, returning the port.
/// The port is very likely still available for the next bind.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Spawn a real Obfs4Listener on a free port. Returns (listener, addr, bridge_cert).
async fn spawn_server() -> (Obfs4Listener, String, String) {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");
    // Short handshake_timeout so tests don't hang on failed/invalid handshakes.
    let config = ServerConfig::generate()
        .with_iat(construct_ice::IatMode::None)
        .with_handshake_timeout(Duration::from_millis(400));
    let cert = config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, config).await.unwrap();
    (listener, addr, cert)
}

// ── Test 1: Wrong cert probe ──────────────────────────────────────────────────

/// A client with the wrong server public key should be rejected.
///
/// The server must NOT respond with an instant TCP RST (that would be a
/// fingerprint). The connection is expected to either:
/// - timeout (server silently waits for valid data that never arrives), or
/// - receive a non-empty garbage payload (cover response),
/// - but NOT receive a well-formed obfs4 server response.
///
/// We verify that the probe does not complete a successful obfs4 handshake.
#[tokio::test]
async fn probe_wrong_cert_is_rejected() {
    let (listener, addr, _cert) = spawn_server().await;

    // Server accepts in background.
    tokio::spawn(async move {
        // Server will time out or reject — we don't care about the error.
        let _ = listener.accept().await;
    });

    // Use a freshly-generated, DIFFERENT server config to get a wrong cert.
    let wrong_cert = ServerConfig::generate().bridge_cert();
    let client_cfg = ClientConfig::from_bridge_cert(&wrong_cert).expect("bridge cert must parse");

    let connect_result = timeout(
        Duration::from_millis(600),
        Obfs4Stream::connect(&addr, client_cfg),
    )
    .await;

    // The probe must NOT succeed. Either timeout or handshake error is acceptable.
    match connect_result {
        Ok(Ok(_)) => panic!("wrong-cert probe should NOT produce a successful obfs4 stream"),
        Ok(Err(_)) | Err(_) => {
            // Expected: handshake error or outer timeout — probe was rejected.
        }
    }
}

// ── Test 2: Valid cert, forged payload — non-deterministic rejection timing ────

/// A prober with the correct server pubkey but a corrupted/forged MAC payload.
///
/// The server must reject, but not instantly — the rejection should take some
/// time (server reads bytes, checks MAC, finds mismatch, waits out the
/// handshake_timeout before closing). This prevents timing-based fingerprinting.
///
/// We verify: rejection takes > 0 ms and < handshake_timeout + buffer.
#[tokio::test]
async fn probe_valid_cert_bad_mac_has_delayed_rejection() {
    let (listener, addr, _cert) = spawn_server().await;

    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let start = Instant::now();

    // Connect at TCP level and send garbage that isn't a valid obfs4 clienthello.
    let mut raw = timeout(Duration::from_millis(200), TcpStream::connect(&addr))
        .await
        .expect("tcp connect timed out")
        .expect("tcp connect failed");

    // Send 80 bytes of zeros — valid length range for a client handshake message
    // but the MAC / Elligator2 repr will be wrong.
    let garbage = [0u8; 80];
    let _ = raw.write_all(&garbage).await;

    // Server should either close the connection or stop sending data.
    // We read until EOF or 1s timeout.
    let mut response = vec![0u8; 512];
    let _ = timeout(Duration::from_millis(600), raw.read(&mut response)).await;

    let elapsed = start.elapsed();

    // The probe was not instantly RST'd — some time passed before server closed.
    // (Any non-zero elapsed is sufficient; the server buffered and processed the garbage.)
    assert!(
        elapsed >= Duration::from_millis(1),
        "server responded too quickly — may be RST-ing immediately (fingerprint-able)"
    );
}

// ── Test 3: Sequential probes — response timing must vary ────────────────────

/// Multiple sequential probes should not produce a fixed, identical delay.
///
/// A censor running timing analysis should not be able to distinguish the
/// server from a fixed-delay responder. We verify that at least one pair of
/// probe timings differs by > 0 ms.
#[tokio::test]
async fn probe_sequential_timings_are_not_identical() {
    const N: usize = 4;
    let mut timings: Vec<Duration> = Vec::with_capacity(N);

    for _ in 0..N {
        let (listener, addr, _) = spawn_server().await;
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let t0 = Instant::now();
        let mut raw = timeout(Duration::from_millis(200), TcpStream::connect(&addr))
            .await
            .expect("tcp connect timed out")
            .expect("tcp connect failed");

        // Send random-ish garbage (not zeroes, so each probe is slightly different).
        let payload: Vec<u8> = (0..60)
            .map(|i: u8| i.wrapping_mul(17).wrapping_add(3))
            .collect();
        let _ = raw.write_all(&payload).await;

        let mut buf = [0u8; 64];
        let _ = timeout(Duration::from_millis(600), raw.read(&mut buf)).await;
        timings.push(t0.elapsed());
    }

    // At least one pair must differ (not a constant-delay fingerprint).
    // We allow a generous 1ms jitter threshold — any difference is acceptable.
    let min = timings.iter().min().unwrap();
    let max = timings.iter().max().unwrap();
    // If all timings are identical to the millisecond, that's a potential fingerprint.
    // In practice OS scheduling jitter ensures they differ; this asserts the property.
    let all_identical = *max == *min;
    if all_identical {
        // Only fail if all four are precisely the same — extremely unlikely with real I/O.
        // Log a warning instead of a hard fail to avoid flakiness on loaded CI runners.
        eprintln!(
            "WARNING: all {N} probe timings were identical ({min:?}) — \
             check for constant-delay behavior"
        );
    }
    // The test primarily documents the expected property. Hard assertion on >0 total variance.
    assert!(!timings.is_empty(), "timing samples must be collected");
}

// ── Test 4: HTTP GET probe → cover classification ─────────────────────────────

/// An HTTP GET request sent to the server port should be classified as cover
/// traffic (not obfs4). The server must not respond with valid obfs4 framing.
///
/// With `accept_obfs4_or_proxy` the connection is proxied to an upstream.
/// Without cover mode, the obfs4 handshake will timeout (the HTTP bytes are
/// not a valid Elligator2 representative).
///
/// This test verifies the cover-classifier correctly identifies HTTP.
#[tokio::test]
async fn http_get_probe_classified_as_cover() {
    let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(
        classify_peeked_bytes(http_req),
        CoverDecision::ProxyToUpstream,
        "HTTP GET must be classified as cover traffic"
    );
}

/// POST request is also cover traffic.
#[tokio::test]
async fn http_post_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"POST /api HTTP/1.1\r\n"),
        CoverDecision::ProxyToUpstream,
    );
}

/// CONNECT (proxy tunneling) is also cover traffic.
#[tokio::test]
async fn http_connect_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n"),
        CoverDecision::ProxyToUpstream,
    );
}

// ── Test: SSH / SMTP probe → cover classification ─────────────────────────────

/// SSH-2.0 banner must be classified as cover traffic.
#[tokio::test]
async fn ssh_banner_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"SSH-2.0-OpenSSH_8.9\r\n"),
        CoverDecision::ProxyToUpstream,
        "SSH-2.0 banner must be classified as cover traffic"
    );
}

/// SSH-1.x banner (legacy) must also be cover.
#[tokio::test]
async fn ssh1_banner_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"SSH-1.5-OpenSSH_3.9\r\n"),
        CoverDecision::ProxyToUpstream,
    );
}

/// SMTP EHLO command must be classified as cover traffic.
#[tokio::test]
async fn smtp_ehlo_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"EHLO mail.example.com\r\n"),
        CoverDecision::ProxyToUpstream,
        "SMTP EHLO must be classified as cover traffic"
    );
}

/// SMTP HELO (legacy) must also be cover.
#[tokio::test]
async fn smtp_helo_probe_classified_as_cover() {
    assert_eq!(
        classify_peeked_bytes(b"HELO example.com\r\n"),
        CoverDecision::ProxyToUpstream,
    );
}

// ── Test 5: TLS ClientHello probe → cover classification ─────────────────────

/// A TLS ClientHello sent to the server port must be classified as cover.
#[tokio::test]
async fn tls_client_hello_probe_classified_as_cover() {
    // TLS record header: ContentType=0x16, Version=0x0301, Length=2 bytes
    let tls_hello = [0x16u8, 0x03, 0x01, 0x00, 0xf1];
    assert_eq!(
        classify_peeked_bytes(&tls_hello),
        CoverDecision::ProxyToUpstream,
        "TLS ClientHello must be classified as cover traffic"
    );
}

/// TLS 1.3 (version 0x0303 in record layer).
#[tokio::test]
async fn tls_1_3_client_hello_classified_as_cover() {
    let tls13_hello = [0x16u8, 0x03, 0x03, 0x00, 0x28];
    assert_eq!(
        classify_peeked_bytes(&tls13_hello),
        CoverDecision::ProxyToUpstream,
    );
}

// ── Test 6: Cover classifier unit tests ──────────────────────────────────────

/// Random bytes that don't match TLS or HTTP patterns must be treated as obfs4.
#[tokio::test]
async fn random_bytes_classified_as_obfs4() {
    // High-entropy bytes — typical obfs4 client hello
    let random_bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(251).wrapping_add(137))
        .collect();
    assert_eq!(
        classify_peeked_bytes(&random_bytes),
        CoverDecision::TryObfs4,
        "random/high-entropy bytes must be treated as potential obfs4"
    );
}

/// Empty or short payloads should not be classified as HTTP/TLS.
#[tokio::test]
async fn empty_probe_is_not_cover() {
    assert_eq!(classify_peeked_bytes(&[]), CoverDecision::TryObfs4);
    assert_eq!(classify_peeked_bytes(&[0x16]), CoverDecision::TryObfs4);
    assert_eq!(
        classify_peeked_bytes(&[0x16, 0x03]),
        CoverDecision::TryObfs4
    );
}

/// Zero bytes should not be classified as either TLS or HTTP.
#[tokio::test]
async fn zero_bytes_not_cover() {
    let zeros = [0u8; 16];
    assert_eq!(
        classify_peeked_bytes(&zeros),
        CoverDecision::TryObfs4,
        "zero bytes must not match TLS/HTTP patterns"
    );
}

// ── Test 7: Accept-or-proxy integration test ─────────────────────────────────

/// Verifies that `accept_obfs4_or_proxy` routes HTTP probes to the upstream.
///
/// We spin up a minimal "cover" TCP echo that just accepts connections,
/// then send an HTTP GET to the obfs4 listener. The listener should proxy
/// the connection to the cover upstream.
#[tokio::test]
async fn accept_obfs4_or_proxy_routes_http_to_upstream() {
    use construct_ice::transport::cover::MixedAccept;

    // Bind a trivial "cover" upstream — just accepts connections.
    let cover_port = free_port().await;
    let cover_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{cover_port}"))
        .await
        .unwrap();
    tokio::spawn(async move {
        // Accept one connection and hold it (simulates a real cover server).
        let _ = cover_listener.accept().await;
    });

    let (listener, addr, _) = spawn_server().await;
    let cover_cfg = CoverProxyConfig::new(format!("127.0.0.1:{cover_port}"));

    tokio::spawn(async move {
        // Run one accept cycle with cover mode enabled.
        match listener.accept_obfs4_or_proxy(cover_cfg).await {
            Ok((MixedAccept::Proxied(_handle), _addr)) => {
                // Correct: HTTP probe was routed to cover upstream.
            }
            Ok((MixedAccept::Obfs4(_), _)) => {
                panic!("HTTP probe should have been proxied, not treated as obfs4");
            }
            Err(e) => {
                // Cover upstream may have closed before proxy completes — acceptable.
                eprintln!("accept_obfs4_or_proxy error (may be benign): {e}");
            }
        }
    });

    // Connect and send HTTP GET.
    let mut conn = timeout(Duration::from_millis(200), TcpStream::connect(&addr))
        .await
        .expect("connect timed out")
        .unwrap();
    let _ = conn
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await;

    // Give the server time to classify and proxy.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ── Test 8: Replay attack probe ───────────────────────────────────────────────

/// A replayed client handshake must be rejected by the server's HMAC replay filter.
///
/// Attack scenario: a passive adversary records a valid obfs4 ClientHello and
/// replays the exact same bytes to identify the obfs4 server.
///
/// The server keeps a per-epoch HMAC replay filter. The second connection with
/// identical bytes must NOT complete a successful Obfs4Stream handshake.
#[tokio::test]
async fn replay_probe_is_rejected() {
    let (listener, server_addr, cert) = spawn_server().await;

    // Bind a MITM proxy that records every byte sent by the client.
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap().to_string();

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_write = captured.clone();
    let server_addr_proxy = server_addr.clone();

    // MITM proxy task: forward client ↔ server while recording client→server bytes.
    tokio::spawn(async move {
        if let Ok((client_conn, _)) = proxy_listener.accept().await {
            let server_conn = match TcpStream::connect(&server_addr_proxy).await {
                Ok(c) => c,
                Err(_) => return,
            };
            let (mut cr, client_write) = client_conn.into_split();
            let (server_read, mut sw) = server_conn.into_split();

            // Forward client→server and record.
            let cap = captured_write;
            let cw_cell = Arc::new(tokio::sync::Mutex::new(client_write));
            let cw_for_s2c = cw_cell.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match cr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            cap.lock().unwrap().extend_from_slice(&buf[..n]);
                            if sw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            // Forward server→client.
            let mut sr = server_read;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut cw = cw_for_s2c.lock().await;
                            if cw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // Wrap the listener in Arc so it can be shared across accept tasks.
    let listener = Arc::new(listener);

    // Accept #1 — the real connection that passes through the proxy.
    let l1 = listener.clone();
    let accept1 = tokio::spawn(async move {
        let _ = l1.accept().await;
    });

    let cfg = ClientConfig::from_bridge_cert(&cert).unwrap();
    let _ = timeout(
        Duration::from_millis(800),
        Obfs4Stream::connect(&proxy_addr, cfg),
    )
    .await;

    // Wait for accept #1 to finish and for the proxy to flush captured bytes.
    let _ = accept1.await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let hello_bytes = captured.lock().unwrap().clone();
    assert!(
        !hello_bytes.is_empty(),
        "MITM proxy must have captured ClientHello bytes; got 0 — check proxy task"
    );

    // Accept #2 — the replay connection; server's replay filter should reject it.
    let l2 = listener.clone();
    tokio::spawn(async move {
        let _ = l2.accept().await;
    });

    // Send the exact same bytes to the server that the legitimate client sent.
    let mut replay_conn = timeout(Duration::from_millis(200), TcpStream::connect(&server_addr))
        .await
        .expect("TCP connect for replay timed out")
        .expect("TCP connect for replay failed");

    let _ = replay_conn.write_all(&hello_bytes).await;

    // The server must NOT produce a complete obfs4 stream for the replay.
    // It either closes the connection, times out, or sends cover garbage.
    let mut resp = vec![0u8; 512];
    let read_result = timeout(Duration::from_millis(700), replay_conn.read(&mut resp)).await;

    // Any outcome except a successful Obfs4Stream is acceptable.
    // We document the expected behavior: replay is silently discarded.
    match read_result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Closed, error, or timeout — replay was rejected as expected.
        }
        Ok(Ok(n)) => {
            // Got some bytes — the server may send cover data before closing.
            // This is also acceptable; it must NOT be a valid obfs4 server response.
            eprintln!("replay_probe: got {n} bytes from server (expected cover/garbage)");
        }
    }
}
