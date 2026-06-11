#![allow(dead_code)]
//! Site forwarding — forward unauthenticated connections to the cover application.
//!
//! The constant-shape requirement: failed auth MUST NOT behave differently from
//! a normal browser request. We simply forward the raw bytes to the cover site
//! backend (local nginx, or any HTTP server) and let it handle the response.
//!
//! The cover site MUST serve long-lived H2 traffic (SSE, WebSocket, etc.) so
//! the baseline traffic shape matches a tunnelled messenger.

use bytes::BytesMut;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Forward a connection to the cover site backend.
///
/// The `first_bytes` are the raw bytes already read from the TLS stream
/// (the client's first request). These must be forwarded to the backend
/// before starting bidirectional copy.
///
/// This function performs a raw TCP forward — no protocol parsing.
/// The cover site sees whatever the client sent, as-is.
pub async fn forward_to_site<S>(
    client_stream: S,
    first_bytes: BytesMut,
    site_addr: &str,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Connect to the cover site backend. `site_addr` is a `host:port` string,
    // resolved per connection so a recreated cover container (new Docker IP) is
    // picked up without restarting the relay.
    let mut site_conn = tokio::net::TcpStream::connect(site_addr).await?;
    site_conn.set_nodelay(true)?;

    // Send whatever the client already sent (TLS handshake + first request).
    if !first_bytes.is_empty() {
        site_conn.write_all(&first_bytes).await?;
    }

    // Bidirectional copy — raw TCP forward.
    // The TLS stream is still encrypted on the client side, but we already
    // terminated TLS, so this is cleartext to the site backend.
    // The site backend must be able to handle HTTP/1.1 or HTTP/2 cleartext.
    let (mut client_rd, mut client_wr) = io::split(client_stream);
    let (mut site_rd, mut site_wr) = site_conn.into_split();

    let client_to_site = async { io::copy(&mut client_rd, &mut site_wr).await };
    let site_to_client = async { io::copy(&mut site_rd, &mut client_wr).await };

    match tokio::try_join!(client_to_site, site_to_client) {
        Ok(_) => {
            debug!("site forwarding completed normally");
            Ok(())
        }
        Err(e) => {
            // Connection reset or EOF is normal — clients close unexpectedly.
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe
            {
                debug!("site forwarding closed (client disconnect)");
                Ok(())
            } else {
                warn!(error = %e, "site forwarding error");
                Err(e)
            }
        }
    }
}

/// Minimal cover site — serves a simple HTTP response for dev/testing.
///
/// In production, this is replaced by a real nginx/long-lived-H2 application.
/// This built-in site is only for M1 acceptance testing without a real cover app.
pub async fn serve_builtin_site<S>(
    mut stream: S,
    first_bytes: BytesMut,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Log what the client sent (first ~200 bytes for debugging).
    let preview = String::from_utf8_lossy(&first_bytes[..first_bytes.len().min(200)]);
    debug!(first_bytes = %preview, "received non-auth data, serving builtin site");

    // For TLS-terminated connections, we respond with a simple HTTP response.
    // The client already completed TLS handshake, so we speak HTTP over the
    // decrypted stream.
    let response = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "Content-Length: 184\r\n",
        "Connection: keep-alive\r\n",
        "\r\n",
        "<!DOCTYPE html>\n",
        "<html><head><title>Public Transit Live</title></head>\n",
        "<body>\n",
        "<h1>Transit Status Dashboard</h1>\n",
        "<p>Real-time sensor feeds. Connection is active.</p>\n",
        "<div id=\"feed\">Waiting for SSE stream...</div>\n",
        "</body></html>\n",
    );

    stream.write_all(response.as_bytes()).await?;

    // Keep the connection alive for a while to simulate long-lived H2.
    // In production, the real SSE stream would keep it alive naturally.
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    Ok(())
}
