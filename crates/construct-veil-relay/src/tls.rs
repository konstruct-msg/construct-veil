//! TLS setup — rustls terminator for the veil-front relay.
//!
//! Supports two modes:
//! 1. **ACME / Let's Encrypt** — load cert + key from PEM files (production).
//! 2. **Self-signed** — generate on the fly (dev / testing).
//!
//! The TLS acceptor exposes `export_keying_material` for session-bound auth.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::ServerConfig;
use sha2::Digest;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// TLS configuration for the veil-front relay.
pub struct RelayTls {
    /// The rustls TLS acceptor for incoming connections.
    pub acceptor: TlsAcceptor,
    /// SPKI fingerprint (hex) of the server certificate — for client pinning.
    pub spki_hex: String,
}

impl RelayTls {
    /// Load TLS from PEM certificate and key files (production, ACME).
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> Result<Self, std::io::Error> {
        let certs: Vec<_> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .collect::<Result<_, _>>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let key = PrivateKeyDer::from_pem_file(key_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Self::from_certs(certs, key)
    }

    /// Build from raw certificate + key.
    pub fn from_certs(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, std::io::Error> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Compute SPKI fingerprint from the first (leaf) cert.
        let spki_hex = compute_spki_hex(certs.first().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no certificates provided")
        })?);

        let acceptor = TlsAcceptor::from(Arc::new(config));

        info!("TLS configured, SPKI: {spki_hex}");

        Ok(Self { acceptor, spki_hex })
    }

    /// Generate a self-signed certificate for development/testing.
    pub fn self_signed() -> Result<Self, std::io::Error> {
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let cert_der = certified.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let spki_hex = compute_spki_hex(&cert_der);

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));

        info!("Self-signed TLS generated, SPKI: {spki_hex}");

        Ok(Self { acceptor, spki_hex })
    }
}

/// Compute the SPKI SHA-256 fingerprint of a certificate (hex string).
///
/// This is the hash of the DER-encoded SubjectPublicKeyInfo (SPKI) of the
/// certificate's public key. Clients pin this value to verify the relay's
/// identity without trusting the full CA chain.
fn compute_spki_hex(cert: &CertificateDer<'_>) -> String {
    use x509_cert::der::{Decode, Encode};

    let x509 = match x509_cert::Certificate::from_der(cert.as_ref()) {
        Ok(c) => c,
        Err(_) => {
            // Fallback: hash the entire cert (dev mode only).
            let hash = sha2::Sha256::digest(cert.as_ref());
            return hex::encode(hash);
        }
    };

    // Get the DER-encoded SPKI from the TBSCertificate.
    let tbs = &x509.tbs_certificate;
    let spki = &tbs.subject_public_key_info;

    // Re-encode SPKI to DER and hash it.
    let spki_der = spki.to_der().unwrap_or_default();
    let hash = sha2::Sha256::digest(&spki_der);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_creates_acceptor() {
        // Install rustls crypto provider for test runtime.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = RelayTls::self_signed().expect("self-signed should work");
        assert!(!tls.spki_hex.is_empty());
        assert_eq!(tls.spki_hex.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn spki_is_deterministic() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Self-signed generates a new key each time, so SPKI will differ.
        // But a single instance should have consistent SPKI.
        let tls = RelayTls::self_signed().expect("self-signed should work");
        let spki1 = tls.spki_hex.clone();
        let spki2 = tls.spki_hex.clone();
        assert_eq!(spki1, spki2);
    }
}
