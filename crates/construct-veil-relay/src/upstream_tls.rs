//! Minimal SPKI-pinned TLS client connector — for the relay's *upstream* hop
//! in chain relay mode (`relay_domestic` dialing `relay_clean`, see
//! `decisions/veil-relay-topology.md` §3).
//!
//! Deliberately simpler than `construct-veil`'s `tls_pinned`/`tls_fingerprint`
//! (no uTLS browser ClientHello mimicry) — this is a relay-to-relay link, not
//! a client impersonating a browser. Mimicry can be layered on later if DPI
//! between the two relays turns out to fingerprint the bare rustls ClientHello;
//! tracked as a follow-up, not a blocker for the first chain-mode cut.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::Digest;
use tokio_rustls::TlsConnector;

/// Verifies the upstream relay's certificate by SPKI pin instead of a CA chain.
#[derive(Debug)]
struct SpkiPinVerifier {
    expected_spki_hex: String,
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
        let spki_hex = compute_spki_hex(end_entity);
        if spki_hex.eq_ignore_ascii_case(&self.expected_spki_hex) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "SPKI pin mismatch: expected {}, got {spki_hex}",
                self.expected_spki_hex
            )))
        }
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
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// SHA-256 of the DER-encoded SubjectPublicKeyInfo, hex-encoded.
fn compute_spki_hex(cert: &CertificateDer<'_>) -> String {
    use x509_cert::der::{Decode, Encode};

    let x509 = match x509_cert::Certificate::from_der(cert.as_ref()) {
        Ok(c) => c,
        Err(_) => return hex::encode(sha2::Sha256::digest(cert.as_ref())),
    };
    let spki_der = x509
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap_or_default();
    hex::encode(sha2::Sha256::digest(&spki_der))
}

/// Build a `TlsConnector` + `ServerName` for dialing the upstream relay.
///
/// `spki_hex` is required (non-empty) — chain relays always pin, unlike the
/// existing `--backend-tls` dialer in `main.rs` which trusts the public CA set.
pub fn build_upstream_connector(
    sni: &str,
    spki_hex: &str,
) -> Result<(TlsConnector, ServerName<'static>), TlsError> {
    let verifier = Arc::new(SpkiPinVerifier {
        expected_spki_hex: spki_hex.to_ascii_lowercase(),
    });

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| TlsError::General(format!("invalid SNI '{sni}': {e}")))?;

    Ok((TlsConnector::from(Arc::new(config)), server_name))
}
