//! WebTunnelObfuscator — adapts existing [`crate::WebTunnelStream`] to the [`Obfuscator`] trait.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::veil::fsm::MethodId;
use crate::veil::obfuscator::{ObfuscatorError, ObfuscatorHandle, ProbeRequest};

/// WebTunnel probe adapter.
pub struct WebTunnelObfuscator;

impl WebTunnelObfuscator {
    /// Create a new WebTunnelObfuscator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for WebTunnelObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::veil::obfuscator::Obfuscator for WebTunnelObfuscator {
    fn method_id(&self) -> MethodId {
        MethodId::WebTunnel
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
                result = probe_webtunnel(&req) => result,
            }
        };

        let cancel_shutdown = cancel.clone();
        let shutdown = async move {
            cancel_shutdown.cancel();
        };

        Ok(ObfuscatorHandle::new(first_byte, shutdown))
    }
}

/// Execute the WebTunnel probe: TCP + TLS + WebSocket upgrade.
async fn probe_webtunnel(req: &ProbeRequest) -> Result<(), ObfuscatorError> {
    let relay_addr = &req.relay_addr;

    // TCP connect with timeout
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

    let _ = tcp.set_nodelay(true);

    // TLS connector — WebTunnel always uses TLS
    let tls_sni = &req.tls_sni;
    let spki_hex = &req.spki_hex;
    let connector_result = crate::tls_pinned::build_connector(
        tls_sni,
        spki_hex,
        relay_addr,
        crate::TlsProfile::Chrome131,
        // WebSocket upgrade requires HTTP/1.1
        Some(vec![b"http/1.1".to_vec()]),
    );

    let (connector, server_name) =
        connector_result.map_err(|e| ObfuscatorError::Tls(e.to_string()))?;

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ObfuscatorError::from_tls_connect(&e))?;

    // WebSocket upgrade
    let host = if req.host_header.is_empty() {
        tls_sni.clone()
    } else {
        req.host_header.clone()
    };

    // Compute auth token (same logic as proxy_loop_webtunnel)
    let auth_token = {
        use sha2::{Digest, Sha256};
        // bridge_cert is extracted from the bundle
        let bridge_cert = extract_bridge_cert(&req.bundle).unwrap_or_default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let period = now / 300;
        let mut hasher = Sha256::new();
        hasher.update(bridge_cert.as_bytes());
        hasher.update(b"webtunnel-v1");
        hasher.update(period.to_be_bytes());
        let hash = hasher.finalize();
        hash[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    };

    let path = format!("{}/{}", req.wt_base_path.trim_end_matches('/'), auth_token);

    let _ws = crate::WebTunnelStream::connect(tls_stream, &host, &path)
        .await
        .map_err(|e| {
            let err_str = e.to_string();
            // Detect transparent proxy decoy response (non-101)
            if err_str.contains("expected 101")
                || err_str.contains("expected HTTP")
                || err_str.contains("switching")
            {
                ObfuscatorError::WebTunnelDecoyResponse
            } else if err_str.contains("connection") {
                ObfuscatorError::ConnectionRefused
            } else {
                ObfuscatorError::Handshake(err_str)
            }
        })?;

    // WebSocket upgrade succeeded — tunnel is verified.
    Ok(())
}

/// Extract the bridge cert from a bundle string.
/// The bundle format is "cert=<base64> iat-mode=<n>" or similar.
fn extract_bridge_cert(bundle: &str) -> Option<String> {
    for token in bundle.split_whitespace() {
        if let Some(v) = token.strip_prefix("cert=") {
            return Some(v.to_owned());
        }
    }
    None
}
