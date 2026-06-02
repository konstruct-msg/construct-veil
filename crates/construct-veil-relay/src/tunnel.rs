//! Tunnel forwarding — ferry h2c gRPC traffic through the authenticated tunnel.
//!
//! After auth validation, the relay becomes a byte-faithful ferry between
//! the client's h2c gRPC stream and the Construct backend (also h2c).
//!
//! No protocol parsing — the relay doesn't inspect gRPC frames.

use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Forward tunnel traffic between an authenticated client and the backend.
///
/// `leftover` contains any buffered data from the client that arrived after
/// the AUTH frame was consumed. This may include early h2c SETTINGS or
/// WINDOW_UPDATE frames.
///
/// The relay simply copies bytes bidirectionally — no framing, no parsing.
pub async fn forward_tunnel<S>(
    client_stream: S,
    leftover: BytesMut,
    backend_addr: SocketAddr,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut backend = tokio::net::TcpStream::connect(backend_addr).await?;
    backend.set_nodelay(true)?;

    // Forward any leftover bytes (early tunnel data buffered during auth).
    if !leftover.is_empty() {
        backend.write_all(&leftover).await?;
        debug!(
            bytes = leftover.len(),
            "forwarded leftover tunnel data to backend"
        );
    }

    let (mut client_rd, mut client_wr) = io::split(client_stream);
    let (mut backend_rd, mut backend_wr) = backend.into_split();

    let client_to_backend = async { io::copy(&mut client_rd, &mut backend_wr).await };
    let backend_to_client = async { io::copy(&mut backend_rd, &mut client_wr).await };

    match tokio::try_join!(client_to_backend, backend_to_client) {
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
