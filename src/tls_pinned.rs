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
    let config = client_config(spki_hex, profile, alpn_override)?;
    let server_name = resolve_server_name(sni, relay_addr)?;
    Ok((TlsConnector::from(Arc::new(config)), server_name))
}

/// The client config [`build_connector`] dials with: the profile's provider and groups,
/// the SPKI pin, ALPN, and the record-size cap.
fn client_config(
    spki_hex: &str,
    profile: TlsProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
) -> Result<ClientConfig, String> {
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
    Ok(config)
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

    /// Live veil-TLS handshake against a real front. Ignored by default
    /// (requires network + env). Run with:
    ///   VEIL_TEST_RELAY=host:443 VEIL_TEST_SNI=host VEIL_TEST_SPKI=<hex> \
    ///   cargo test -p construct-veil --lib tls_pinned::tests::dial_live_relay -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dial_live_relay() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let relay = std::env::var("VEIL_TEST_RELAY")
                .expect("set VEIL_TEST_RELAY=host:443 (private ops inventory)");
            let sni = std::env::var("VEIL_TEST_SNI").unwrap_or_else(|_| {
                relay
                    .split_once(':')
                    .map(|(h, _)| h.to_string())
                    .unwrap_or_else(|| relay.clone())
            });
            let spki = std::env::var("VEIL_TEST_SPKI")
                .expect("set VEIL_TEST_SPKI=<sha256 hex of relay SPKI>");

            let (connector, server_name) = build_connector(
                &sni,
                &spki,
                &relay,
                TlsProfile::Chrome131,
                Some(vec![b"h2".to_vec()]),
            )
            .expect("build_connector");
            let tcp = TcpStream::connect(relay).await.expect("tcp connect");
            tcp.set_nodelay(true).unwrap();
            match connector.connect(server_name, tcp).await {
                Ok(s) => {
                    let (_, conn) = s.get_ref();
                    eprintln!(
                        "HANDSHAKE OK — proto={:?} alpn={:?}",
                        conn.protocol_version(),
                        conn.alpn_protocol()
                            .map(|a| String::from_utf8_lossy(a).to_string())
                    );
                }
                Err(e) => panic!("HANDSHAKE ERR: {e}  (kind={:?})", e.kind()),
            }
        });
    }
}

#[cfg(test)]
mod key_exchange {
    use super::*;
    use crate::tls_fingerprint::TlsProfile;
    use rustls::NamedGroup::{X25519, X25519MLKEM768};

    /// A server on aws-lc-rs offering `groups`, with a throwaway self-signed cert.
    fn server(groups: &[rustls::NamedGroup]) -> Arc<rustls::ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups.retain(|g| groups.contains(&g.name()));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key)
                .unwrap(),
        )
    }

    /// Full in-memory handshake: our client with `profile` against `server`; the group
    /// the server picked.
    fn negotiated(profile: TlsProfile, server: Arc<rustls::ServerConfig>) -> rustls::NamedGroup {
        let config = client_config("", profile, None).unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                .unwrap();
        let mut srv = rustls::ServerConnection::new(server).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            srv.read_tls(&mut &buf[..]).unwrap();
            srv.process_new_packets().unwrap();
            let mut buf = Vec::new();
            srv.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !srv.is_handshaking() {
                break;
            }
        }
        assert!(!srv.is_handshaking(), "handshake did not complete");
        srv.negotiated_key_exchange_group().unwrap().name()
    }

    /// Every profile offers the hybrid first, and a server that has it picks it.
    /// Mutation: drop X25519MLKEM768 from a profile's groups (what the `ring` profiles
    /// were until 2026-10-03) — that profile negotiates X25519 and this fails.
    #[test]
    fn every_profile_negotiates_the_hybrid() {
        for profile in [
            TlsProfile::Chrome131,
            TlsProfile::Firefox128,
            TlsProfile::Rustls,
        ] {
            assert_eq!(
                negotiated(profile, server(&[X25519MLKEM768, X25519])),
                X25519MLKEM768,
                "{profile:?}"
            );
        }
    }

    /// A front still on a classical relay keeps working: the hello carries an X25519
    /// share too, so the server picks it without a retry.
    #[test]
    fn a_classical_front_still_connects() {
        for profile in [
            TlsProfile::Chrome131,
            TlsProfile::Firefox128,
            TlsProfile::Rustls,
        ] {
            assert_eq!(
                negotiated(profile, server(&[X25519])),
                X25519,
                "{profile:?}"
            );
        }
    }
}
