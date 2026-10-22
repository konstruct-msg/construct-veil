//! Obfs4Obfuscator — adapts existing [`crate::Obfs4Stream`] to the [`Obfuscator`] trait.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::veil::fsm::MethodId;
use crate::veil::obfuscator::{ObfuscatorError, ObfuscatorHandle, ProbeRequest};

/// Obfs4 probe adapter.
pub struct Obfs4Obfuscator;

impl Obfs4Obfuscator {
    /// Create a new Obfs4Obfuscator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Obfs4Obfuscator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::veil::obfuscator::Obfuscator for Obfs4Obfuscator {
    fn method_id(&self) -> MethodId {
        MethodId::Obfs4
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
                result = probe_obfs4(&req) => result,
            }
        };

        let cancel_shutdown = cancel.clone();
        let shutdown = async move {
            cancel_shutdown.cancel();
        };

        Ok(ObfuscatorHandle::new(first_byte, shutdown))
    }
}

/// Execute the obfs4 probe: connect + TLS (if configured) + handshake.
async fn probe_obfs4(req: &ProbeRequest) -> Result<(), ObfuscatorError> {
    let config = crate::ClientConfig::from_bridge_line(&req.bundle)
        .map_err(|e| ObfuscatorError::Handshake(e.to_string()))?;

    let relay_addr = req.relay_addr.clone();

    // TCP connect with timeout
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&relay_addr))
        .await
        .map_err(|_| ObfuscatorError::Timeout)?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                ObfuscatorError::ConnectionRefused
            } else {
                ObfuscatorError::Io(e)
            }
        })?;

    let _ = tcp.set_nodelay(true);

    #[cfg(feature = "tls")]
    {
        let tls_sni = &req.tls_sni;
        let spki_hex = &req.spki_hex;
        let use_tls = !tls_sni.is_empty() || !spki_hex.is_empty();

        if use_tls {
            return probe_obfs4_over_tls(tcp, tls_sni, spki_hex, config).await;
        }
    }

    // Plain TCP obfs4
    let _stream = crate::Obfs4Stream::client_handshake_stream(tcp, config)
        .await
        .map_err(|e| classify_obfs4_error(&e))?;

    // Handshake completed successfully (including PrngSeed received from server).
    Ok(())
}

#[cfg(feature = "tls")]
async fn probe_obfs4_over_tls(
    tcp: TcpStream,
    tls_sni: &str,
    spki_hex: &str,
    config: crate::ClientConfig,
) -> Result<(), ObfuscatorError> {
    use crate::tls_pinned::build_connector;

    let (connector, server_name) = build_connector(
        tls_sni,
        spki_hex,
        "", // relay_addr not needed — we already have the TCP stream
        config.tls_profile,
        None,
    )
    .map_err(|e| ObfuscatorError::Tls(e.to_string()))?;

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ObfuscatorError::from_tls_connect(&e))?;

    let _stream = crate::Obfs4Stream::client_handshake_stream(tls_stream, config)
        .await
        .map_err(|e| classify_obfs4_error(&e))?;

    Ok(())
}

/// Classify an obfs4 handshake error.
///
/// By type, never by message: until 2026-10-22 an I/O error was matched on the
/// lowercase text "connection refused" (std spells it "Connection refused", so
/// that branch never fired) and an ntor AUTH mismatch — a wrong bridge bundle or
/// a MitM, nothing a DPI box does — counted as `FingerprintBlocked`, which the
/// scorer turns into a week-long block after five of them.
fn classify_obfs4_error(e: &crate::Error) -> ObfuscatorError {
    use std::io::ErrorKind;
    match e {
        crate::Error::HandshakeTimeout => ObfuscatorError::Timeout,
        crate::Error::HandshakeRejected
        | crate::Error::NtorAuthMismatch
        | crate::Error::InvalidServerPublicKey(_) => ObfuscatorError::Handshake(e.to_string()),
        crate::Error::Io(io_err) => match io_err.kind() {
            ErrorKind::ConnectionRefused => ObfuscatorError::ConnectionRefused,
            ErrorKind::TimedOut => ObfuscatorError::Timeout,
            kind => ObfuscatorError::Io(kind.into()),
        },
        _ => ObfuscatorError::Handshake(e.to_string()),
    }
}

#[cfg(test)]
mod classification {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    /// Mutation: restore `NtorAuthMismatch => FingerprintBlocked`, or match the
    /// refused error on its lowercase text — each reddens one assertion.
    #[test]
    fn obfs4_errors_classify_by_type() {
        assert!(matches!(
            classify_obfs4_error(&crate::Error::NtorAuthMismatch),
            ObfuscatorError::Handshake(_)
        ));
        assert!(matches!(
            classify_obfs4_error(&crate::Error::Io(IoError::from(
                ErrorKind::ConnectionRefused
            ))),
            ObfuscatorError::ConnectionRefused
        ));
        assert!(matches!(
            classify_obfs4_error(&crate::Error::Io(IoError::from(ErrorKind::TimedOut))),
            ObfuscatorError::Timeout
        ));
        assert!(matches!(
            classify_obfs4_error(&crate::Error::Io(IoError::new(
                ErrorKind::ConnectionReset,
                "connection refused handshake 40"
            ))),
            ObfuscatorError::Io(_)
        ));
    }
}
