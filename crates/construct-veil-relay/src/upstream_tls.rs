//! Minimal SPKI-pinned TLS client connector — for the relay's *upstream* hop
//! in chain relay mode (`relay_domestic` dialing `relay_clean`, see
//! `decisions/veil-relay-topology.md` §3).
//!
//! Deliberately simpler than `construct-veil`'s `tls_pinned`/`tls_fingerprint`
//! (no uTLS browser ClientHello mimicry) — this is a relay-to-relay link, not
//! a client impersonating a browser. Mimicry can be layered on later if DPI
//! between the two relays turns out to fingerprint the bare rustls ClientHello;
//! tracked as a follow-up, not a blocker for the first chain-mode cut.
//!
//! Trust is the SHA-256 of the upstream leaf's SubjectPublicKeyInfo, not a CA
//! chain. A certificate is public, so the pin only identifies the upstream
//! together with the handshake signature, which proves possession of the key:
//! the verifier checks that signature with the relay's crypto provider. Until
//! 2026-10-22 both signature callbacks returned `assertion()` unchecked, so a
//! MitM on the domestic→clean link could present the clean relay's own
//! certificate and terminate the session (todo 207).

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, OtherError,
    SignatureScheme,
};
use sha2::Digest;
use tokio_rustls::TlsConnector;

/// Why the upstream's certificate failed the pin. Surfaces as
/// `rustls::Error::InvalidCertificate(CertificateError::Other(_))`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// The leaf's SPKI hash is not the pinned one — MitM or key rotation upstream.
    Mismatch,
    /// The leaf could not be parsed as X.509, so it has no SPKI to compare.
    NoSpki,
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinError::Mismatch => f.write_str("upstream SPKI pin mismatch"),
            PinError::NoSpki => f.write_str("upstream certificate has no parsable SPKI"),
        }
    }
}

// rustls renders `CertificateError::Other` through `Debug`; keep the log line readable.
impl fmt::Debug for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PinError {}

impl From<PinError> for TlsError {
    fn from(e: PinError) -> Self {
        TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
    }
}

/// Verifies the upstream relay's certificate by SPKI pin instead of a CA chain,
/// and its handshake signature with the provider.
#[derive(Debug)]
struct SpkiPinVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let got = spki_sha256(end_entity).ok_or(PinError::NoSpki)?;
        if got != self.expected {
            return Err(PinError::Mismatch.into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SHA-256 of the DER-encoded SubjectPublicKeyInfo. `None` when the certificate
/// does not parse — that is a rejection, never a fallback to hashing something else.
fn spki_sha256(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    use x509_cert::der::{Decode, Encode};

    let x509 = x509_cert::Certificate::from_der(cert.as_ref()).ok()?;
    let spki_der = x509.tbs_certificate.subject_public_key_info.to_der().ok()?;
    Some(sha2::Sha256::digest(&spki_der).into())
}

/// Parse the configured pin: 64 hex digits, either case. The error does not
/// echo the input.
fn parse_pin(spki_hex: &str) -> Result<[u8; 32], TlsError> {
    hex::decode(spki_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| TlsError::General("upstream SPKI pin must be 64 hex digits".into()))
}

/// The client config the chain hop dials with: the relay's provider (hybrid key
/// exchange first), the pin, h2 ALPN.
pub(crate) fn upstream_client_config(spki_hex: &str) -> Result<ClientConfig, TlsError> {
    let expected = parse_pin(spki_hex)?;
    let provider = crate::tls::crypto_provider();
    let verifier = Arc::new(SpkiPinVerifier {
        expected,
        provider: provider.clone(),
    });

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Build a `TlsConnector` + `ServerName` for dialing the upstream relay.
///
/// `spki_hex` is required — chain relays always pin, unlike the
/// existing `--backend-tls` dialer in `main.rs` which trusts the public CA set.
pub fn build_upstream_connector(
    sni: &str,
    spki_hex: &str,
) -> Result<(TlsConnector, ServerName<'static>), TlsError> {
    let config = upstream_client_config(spki_hex)?;
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| TlsError::General(format!("invalid SNI '{sni}': {e}")))?;
    Ok((TlsConnector::from(Arc::new(config)), server_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls::version::{TLS12, TLS13};

    /// Drives an in-memory handshake; the client's verdict.
    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> Result<(), TlsError> {
        let mut client = rustls::ClientConnection::new(client, "localhost".try_into().unwrap())?;
        let mut srv = rustls::ServerConnection::new(server)?;
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            srv.read_tls(&mut &buf[..]).unwrap();
            let _ = srv.process_new_packets();
            let mut buf = Vec::new();
            srv.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !srv.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake did not complete");
    }

    /// Serves one certified key as given — `with_single_cert` would refuse a key
    /// that does not match the certificate, which is the impostor under test.
    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A server presenting `cert` and signing with `key_der`, which need not match.
    fn server_with(
        cert: CertificateDer<'static>,
        key_der: Vec<u8>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<rustls::ServerConfig> {
        let provider = crate::tls::crypto_provider();
        let key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::try_from(key_der).unwrap())
            .unwrap();
        let certified = Arc::new(CertifiedKey::new(vec![cert], key));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Fixed(certified))),
        )
    }

    fn pin_of(cert: &CertificateDer<'_>) -> String {
        hex::encode(spki_sha256(cert).unwrap())
    }

    /// The upstream must sign with the key behind the pinned certificate. Mutation:
    /// `verify_tls13_signature` returning `assertion()` — the impostor completes.
    #[test]
    fn pinned_upstream_must_be_backed_by_its_key() {
        let honest = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let impostor_key = rcgen::KeyPair::generate().unwrap();
        let client = Arc::new(upstream_client_config(&pin_of(honest.cert.der())).unwrap());

        for versions in [&[&TLS13][..], &[&TLS12][..]] {
            handshake(
                client.clone(),
                server_with(
                    honest.cert.der().clone(),
                    honest.key_pair.serialize_der(),
                    versions,
                ),
            )
            .unwrap_or_else(|e| panic!("honest upstream on {versions:?}: {e}"));

            let err = handshake(
                client.clone(),
                server_with(
                    honest.cert.der().clone(),
                    impostor_key.serialize_der(),
                    versions,
                ),
            )
            .err()
            .unwrap_or_else(|| panic!("impostor accepted on {versions:?}"));
            assert!(
                matches!(
                    err,
                    TlsError::InvalidCertificate(CertificateError::BadSignature)
                ),
                "{versions:?}: {err:?}"
            );
        }
    }

    /// Another key than the pinned one is a typed pin error with a readable message.
    #[test]
    fn another_key_than_the_pinned_one_is_rejected() {
        let honest = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = Arc::new(upstream_client_config(&pin_of(other.cert.der())).unwrap());

        let err = handshake(
            client,
            server_with(
                honest.cert.der().clone(),
                honest.key_pair.serialize_der(),
                &[&TLS13],
            ),
        )
        .err()
        .unwrap_or_else(|| panic!("mismatched pin accepted"));
        assert!(
            matches!(
                err,
                TlsError::InvalidCertificate(CertificateError::Other(_))
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("upstream SPKI pin mismatch"),
            "{err}"
        );
    }

    /// The pin is 64 hex digits in either case; anything else is refused up front
    /// and the error never repeats the input.
    #[test]
    fn pin_must_be_64_hex_digits() {
        let pin = "ab".repeat(32);
        assert!(upstream_client_config(&pin).is_ok());
        assert!(upstream_client_config(&pin.to_uppercase()).is_ok());
        for bad in [
            "",
            "abc",
            &"zz".repeat(32),
            &"ab".repeat(31),
            &"aé".repeat(16),
        ] {
            let err = build_upstream_connector("localhost", bad)
                .err()
                .unwrap_or_else(|| panic!("malformed pin accepted"));
            assert!(bad.is_empty() || !err.to_string().contains(bad), "{err}");
        }
    }
}
