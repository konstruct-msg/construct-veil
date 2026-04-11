//! Cover traffic helpers for active-probing resistance.
//!
//! Motivation: DPI probers often initiate "legitimate-looking" protocols
//! (most commonly TLS ClientHello or HTTP) to fingerprint servers.
//! If the obfs4 handshake waits for more random-looking bytes and times out,
//! that behavior can itself become a fingerprint.
//!
//! This module provides a simple, opt-in strategy:
//! - Peek at the first bytes of an incoming TCP connection.
//! - If they look like TLS or HTTP, proxy the TCP stream to an upstream
//!   "cover" server (e.g. a real website).
//!
//! This is conceptually similar to "fallback/proxy-to-real-site" approaches
//! used by some censorship-circumvention proxies.

use std::time::Duration;

use tokio::{io, net::TcpStream, time::timeout};

/// Result of [`crate::transport::Obfs4Listener::accept_obfs4_or_proxy`].
pub enum MixedAccept {
    /// A real obfs4 client connection.
    Obfs4(Box<super::Obfs4Stream<TcpStream>>),
    /// A cover-looking connection that is being proxied to the upstream.
    ///
    /// Await the handle to observe any proxying errors.
    Proxied(tokio::task::JoinHandle<io::Result<()>>),
}

/// Configuration for cover traffic proxying.
#[derive(Clone, Debug)]
pub struct CoverProxyConfig {
    /// Where to proxy likely-cover connections (e.g. `"93.184.216.34:443"` or `"example.com:443"`).
    pub upstream_addr: String,
    /// How long to wait for enough bytes to classify traffic (TLS/HTTP) via `TcpStream::peek`.
    pub peek_timeout: Duration,
    /// Timeout for establishing the upstream TCP connection.
    pub connect_timeout: Duration,
}

impl CoverProxyConfig {
    /// Create a cover config that proxies to `upstream_addr`.
    pub fn new(upstream_addr: impl Into<String>) -> Self {
        Self {
            upstream_addr: upstream_addr.into(),
            ..Self::default()
        }
    }
}

impl Default for CoverProxyConfig {
    fn default() -> Self {
        Self {
            upstream_addr: "127.0.0.1:443".to_string(),
            peek_timeout: Duration::from_millis(150),
            connect_timeout: Duration::from_secs(3),
        }
    }
}

/// Decision returned by [`classify_peeked_bytes`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CoverDecision {
    /// Looks like a "normal" protocol (TLS/HTTP) — proxy it to the cover upstream.
    ProxyToUpstream,
    /// Doesn't look like TLS/HTTP (or not enough bytes) — proceed with obfs4 handshake.
    TryObfs4,
}

/// Peek a few bytes from the TCP stream (with a short timeout) and classify them.
pub async fn decide_cover(stream: &TcpStream, cfg: &CoverProxyConfig) -> io::Result<CoverDecision> {
    let mut buf = [0u8; 8];
    let peeked = timeout(cfg.peek_timeout, stream.peek(&mut buf)).await;
    let n = match peeked {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e),
        Err(_) => 0,
    };
    Ok(classify_peeked_bytes(&buf[..n]))
}

/// Heuristic classifier for active-probing traffic.
pub fn classify_peeked_bytes(peeked: &[u8]) -> CoverDecision {
    if looks_like_tls_client_hello(peeked)
        || looks_like_http_request(peeked)
        || looks_like_ssh_banner(peeked)
        || looks_like_smtp_command(peeked)
    {
        CoverDecision::ProxyToUpstream
    } else {
        CoverDecision::TryObfs4
    }
}

/// Returns true if the bytes look like a TLS record header for a ClientHello.
///
/// TLS record header: `ContentType(0x16) || Version(0x03 0x01/0x03/0x04) || Length(2)`
fn looks_like_tls_client_hello(b: &[u8]) -> bool {
    if b.len() < 3 {
        return false;
    }
    b[0] == 0x16 && b[1] == 0x03 && (0x00..=0x04).contains(&b[2])
}

/// Returns true if the bytes look like a plaintext HTTP request line prefix.
fn looks_like_http_request(b: &[u8]) -> bool {
    // Enough to match common methods + a space.
    // False positives on obfs4 are astronomically unlikely.
    const METHODS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|m| b.starts_with(m))
}

/// Returns true if the bytes look like an SSH banner (`SSH-2.0-` or `SSH-1.`).
fn looks_like_ssh_banner(b: &[u8]) -> bool {
    b.starts_with(b"SSH-2.0-") || b.starts_with(b"SSH-1.")
}

/// Returns true if the bytes look like a plaintext SMTP command.
fn looks_like_smtp_command(b: &[u8]) -> bool {
    const COMMANDS: [&[u8]; 5] = [b"EHLO ", b"HELO ", b"MAIL ", b"RCPT ", b"QUIT\r"];
    COMMANDS.iter().any(|c| b.starts_with(c))
}

/// Proxy `client` to `cfg.upstream_addr` until EOF in either direction.
pub async fn proxy_to_upstream(mut client: TcpStream, cfg: CoverProxyConfig) -> io::Result<()> {
    let upstream = timeout(cfg.connect_timeout, TcpStream::connect(cfg.upstream_addr)).await??;
    let mut upstream = upstream;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tls() {
        let b = [0x16, 0x03, 0x01, 0x00, 0x2e];
        assert_eq!(classify_peeked_bytes(&b), CoverDecision::ProxyToUpstream);
    }

    #[test]
    fn classify_http_methods() {
        assert_eq!(
            classify_peeked_bytes(b"GET / HTTP/1.1\r\n"),
            CoverDecision::ProxyToUpstream
        );
        assert_eq!(
            classify_peeked_bytes(b"POST /x HTTP/1.1\r\n"),
            CoverDecision::ProxyToUpstream
        );
        assert_eq!(
            classify_peeked_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n"),
            CoverDecision::ProxyToUpstream
        );
    }

    #[test]
    fn classify_random_is_obfs4() {
        let b = [0x7f, 0x9a, 0x11, 0x00, 0xff, 0x01, 0x02, 0x03];
        assert_eq!(classify_peeked_bytes(&b), CoverDecision::TryObfs4);
    }
}
