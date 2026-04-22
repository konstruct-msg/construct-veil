//! Prometheus metrics for construct-ice relay nodes.
//!
//! Feature-gated behind `metrics`. When disabled, all instrumentation
//! calls compile to no-ops with zero runtime cost.
//!
//! ## Exposed metrics
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `ice_connections_active` | Gauge | Currently open obfs4/WebTunnel connections |
//! | `ice_handshakes_total` | Counter | Completed handshakes (`result=ok\|fail`) |
//! | `ice_bytes_total` | Counter | Bytes relayed (`direction=in\|out`) |
//! | `ice_iat_mode` | Gauge | Configured IAT mode (0=None, 1=Enabled, 2=Paranoid) |
//!
//! ## HTTP endpoint
//!
//! Call [`serve_metrics`] to expose `/metrics` on a given address.
//! Typically bound to `0.0.0.0:9100` for Prometheus scraping.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, TextEncoder, opts, register_int_counter,
    register_int_counter_vec, register_int_gauge,
};
use std::net::SocketAddr;

// ============================================================================
// Metric definitions
// ============================================================================

/// Current number of open obfs4/WebTunnel connections.
pub static ICE_CONNECTIONS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "ice_connections_active",
        "Current number of active obfs4/WebTunnel relay connections"
    )
    .expect("Failed to register ICE_CONNECTIONS_ACTIVE")
});

/// Total completed handshakes (client → server direction only).
/// Label `result`: "ok" | "fail"
pub static ICE_HANDSHAKES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "ice_handshakes_total",
            "Total obfs4/WebTunnel handshakes completed"
        ),
        &["result"]
    )
    .expect("Failed to register ICE_HANDSHAKES_TOTAL")
});

/// Total bytes processed by the relay.
/// Label `direction`: "in" | "out" (relative to the relay node)
pub static ICE_BYTES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "ice_bytes_total",
            "Total bytes relayed by construct-ice (in = from client, out = to client)"
        ),
        &["direction"]
    )
    .expect("Failed to register ICE_BYTES_TOTAL")
});

/// Configured IAT (Inter-Arrival Time) jitter mode as an integer.
/// 0 = None (no jitter), 1 = Enabled (10 ms), 2 = Paranoid (random chunk + 10 ms).
pub static ICE_IAT_MODE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "ice_iat_mode",
        "Configured IAT mode: 0=None, 1=Enabled, 2=Paranoid"
    )
    .expect("Failed to register ICE_IAT_MODE")
});

/// Total replay-filter rejections (duplicate/replayed client handshakes).
pub static ICE_REPLAY_REJECTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "ice_replay_rejections_total",
        "Total client handshakes rejected by the replay filter"
    ))
    .expect("Failed to register ICE_REPLAY_REJECTIONS_TOTAL")
});

/// Incremented when the replay filter bucket overflows and an entry is evicted.
/// A sustained increase indicates a flood/DoS attempt on the handshake endpoint.
pub static ICE_REPLAY_EVICTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "ice_replay_evictions_total",
        "Total replay filter evictions (bucket overflow — possible DoS indicator)"
    ))
    .expect("Failed to register ICE_REPLAY_EVICTIONS_TOTAL")
});

// ============================================================================
// Helper functions called from transport layer
// ============================================================================

/// Record a successful server-side handshake.
#[inline]
pub fn record_handshake_ok() {
    ICE_HANDSHAKES_TOTAL.with_label_values(&["ok"]).inc();
    ICE_CONNECTIONS_ACTIVE.inc();
}

/// Record a failed server-side handshake.
#[inline]
pub fn record_handshake_fail() {
    ICE_HANDSHAKES_TOTAL.with_label_values(&["fail"]).inc();
}

/// Record a connection being closed (decrements active gauge).
#[inline]
pub fn record_connection_closed() {
    ICE_CONNECTIONS_ACTIVE.dec();
}

/// Record bytes received from a client.
#[inline]
pub fn record_bytes_in(n: usize) {
    ICE_BYTES_TOTAL.with_label_values(&["in"]).inc_by(n as u64);
}

/// Record bytes sent to a client.
#[inline]
pub fn record_bytes_out(n: usize) {
    ICE_BYTES_TOTAL.with_label_values(&["out"]).inc_by(n as u64);
}

/// Record a replay-filter rejection.
#[inline]
pub fn record_replay_rejection() {
    ICE_REPLAY_REJECTIONS_TOTAL.inc();
}

/// Set the active IAT mode (call once at startup).
#[inline]
pub fn set_iat_mode(mode: u8) {
    ICE_IAT_MODE.set(mode as i64);
}

// ============================================================================
// HTTP /metrics endpoint
// ============================================================================

/// Gather all registered Prometheus metrics and encode as text.
pub fn gather() -> String {
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    encoder
        .encode(&prometheus::gather(), &mut buf)
        .expect("Failed to encode metrics");
    String::from_utf8(buf).expect("Metrics UTF-8 error")
}

/// Serve `/metrics` on `addr` using a minimal Tokio HTTP loop.
///
/// This is intentionally dependency-free (no hyper, no axum) — it only
/// handles the exact path Prometheus scrapes:
/// ```
/// GET /metrics HTTP/1.1
/// ```
/// Any other request receives a `404 Not Found`.
pub async fn serve_metrics(addr: SocketAddr) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("construct-ice metrics endpoint listening on {addr}");

    loop {
        let (mut stream, _peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /metrics") {
                let payload = gather();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = stream.write_all(body.as_bytes()).await;
        });
    }
}
