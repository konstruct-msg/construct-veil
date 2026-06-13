//! Rustls-based TLS connector with SPKI certificate pinning.
//!
//! Supports two DPI-evasion modes:
//!
//! - **No SNI** (`sni = ""`): derives `ServerName::IpAddress` from relay_addr —
//!   no SNI extension in ClientHello. DPI sees: TLS to IP:443, no hostname.
//!
//! - **Fake SNI** (`sni = "storage.yandexcloud.net"`): sends that domain as SNI
//!   (REALITY-style). DPI sees: TLS to Yandex Cloud IP with Yandex Cloud SNI.
//!   cert is verified by SPKI pin, not by CA chain — so the domain doesn't need
//!   to match the actual server cert.
//!
//! In both cases the certificate chain is **not** validated via the system CA
//! store. If `spki_hex` is non-empty, the SHA-256 of the cert's DER-encoded
//! SubjectPublicKeyInfo must match. If empty, any cert is accepted (use only
//! for backward-compat / testing).

use std::{net::IpAddr, sync::Arc};

use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio_rustls::TlsConnector;

use crate::tls_fingerprint::TlsProfile;

/// Build a `TlsConnector` + `ServerName` for the DPI-evasion TLS handshake.
///
/// # Parameters
/// - `sni`: SNI to advertise. Empty → IP-based `ServerName` (no SNI extension).
/// - `spki_hex`: lowercase hex SHA-256 of DER SubjectPublicKeyInfo. Empty →
///   accept any cert (no pinning).
/// - `relay_addr`: `"ip:port"` string — used to extract the IP when `sni` is empty.
/// - `profile`: TLS fingerprint profile. Controls cipher suite ordering and ALPN
///   to mimic a specific browser ClientHello.
/// - `alpn_override`: When `Some`, replaces the profile's ALPN list. Use to restrict
///   ALPN for transport-specific requirements (e.g. WebSocket requires `http/1.1` only).
pub fn build_connector(
    sni: &str,
    spki_hex: &str,
    relay_addr: &str,
    profile: TlsProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
) -> Result<(TlsConnector, ServerName<'static>), String> {
    let provider = profile.crypto_provider();
    let verifier = PinnedSpkiVerifier::new(spki_hex)?;

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let alpn = alpn_override.unwrap_or_else(|| profile.alpn());
    if !alpn.is_empty() {
        config.alpn_protocols = alpn;
    }

    // Cap TLS plaintext record size at the top veil-front length bucket so
    // coalescing of small frames into a giant record can't escape the bucket
    // distribution the codec emits. rustls 0.23 has no public record padder;
    // frame-level zero padding is in `construct_veil_protocol::VeilFrontCodec`.
    config.max_fragment_size = Some(
        construct_veil_protocol::LENGTH_BUCKETS[construct_veil_protocol::LENGTH_BUCKETS.len() - 1],
    );

    let server_name = resolve_server_name(sni, relay_addr)?;
    Ok((TlsConnector::from(Arc::new(config)), server_name))
}

// ── Pinned SPKI verifier ──────────────────────────────────────────────────────

#[derive(Debug)]
struct PinnedSpkiVerifier {
    /// SHA-256 of DER SubjectPublicKeyInfo, or `None` to accept any cert.
    expected: Option<[u8; 32]>,
}

impl PinnedSpkiVerifier {
    fn new(spki_hex: &str) -> Result<Self, String> {
        let expected = if spki_hex.is_empty() {
            None
        } else {
            let bytes = decode_hex(spki_hex)
                .ok_or_else(|| format!("invalid hex in SPKI pin: {spki_hex}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "SPKI SHA-256 must be 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        };
        Ok(Self { expected })
    }
}

impl ServerCertVerifier for PinnedSpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Some(expected) = &self.expected {
            let got = spki_sha256(end_entity)
                .ok_or_else(|| TlsError::General("failed to extract SPKI from cert".into()))?;
            if &got != expected {
                return Err(TlsError::General(
                    "SPKI pin mismatch — possible MitM or key rotation".into(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve a rustls `ServerName` from `sni` (preferred) or by parsing the IP
/// from `relay_addr` (when `sni` is empty).
fn resolve_server_name(sni: &str, relay_addr: &str) -> Result<ServerName<'static>, String> {
    if sni.is_empty() {
        // Derive from relay address. For IP addresses rustls omits the SNI extension.
        let host = relay_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(relay_addr);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let ip: IpAddr = host
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(sni.to_owned()).map_err(|e| e.to_string())
    }
}

/// Extract SHA-256 of DER SubjectPublicKeyInfo from a DER-encoded certificate.
fn spki_sha256(cert_der: &CertificateDer<'_>) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    let cert = Certificate::from_der(cert_der.as_ref()).ok()?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
    Some(Sha256::digest(&spki_der).into())
}

/// Minimal hex decoder — avoids pulling `hex` crate into non-dev dependencies.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod live_probe {
    use super::*;
    use crate::tls_fingerprint::TlsProfile;
    use tokio::net::TcpStream;

    /// Live veil-TLS handshake against the production relay. Ignored by default
    /// (requires network); run with:
    ///   cargo test -p construct-veil --lib tls_pinned::live_probe -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dial_live_relay() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let relay = "api.divany-kresla.uk:443";
            let sni = "api.divany-kresla.uk";
            let spki = "b2361c0448a33a10e6521300aa4de8d8fe402791dd4fd5b0fe10fbb09457570c";

            let (connector, server_name) =
                build_connector(sni, spki, relay, TlsProfile::Chrome131, Some(vec![b"h2".to_vec()]))
                    .expect("build_connector");
            let tcp = TcpStream::connect(relay).await.expect("tcp connect");
            tcp.set_nodelay(true).unwrap();
            match connector.connect(server_name, tcp).await {
                Ok(s) => {
                    let (_, conn) = s.get_ref();
                    eprintln!(
                        "HANDSHAKE OK — proto={:?} alpn={:?}",
                        conn.protocol_version(),
                        conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).to_string())
                    );
                }
                Err(e) => panic!("HANDSHAKE ERR: {e}  (kind={:?})", e.kind()),
            }
        });
    }
}
