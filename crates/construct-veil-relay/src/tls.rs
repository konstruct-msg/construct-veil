//! TLS setup — rustls terminator for the veil-front relay.
//!
//! Supports two modes:
//! 1. **ACME / Let's Encrypt** — load cert + key from PEM files (production).
//! 2. **Self-signed** — generate on the fly (dev / testing).
//!
//! The TLS acceptor exposes `export_keying_material` for session-bound auth.

use std::sync::Arc;

use construct_veil_protocol::LENGTH_BUCKETS;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::ServerConfig;
use sha2::Digest;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Cap on the plaintext size of any TLS record this relay emits.
///
/// rustls 0.23 has no public `RecordPadder` callback, so length bucketing is
/// done at the veil-front codec layer (zero-pad inside the frame). Setting
/// `max_fragment_size` to the top bucket prevents rustls from coalescing
/// multiple sub-bucket plaintext writes into a single oversized record that
/// would fall outside the bucket distribution.
const MAX_TLS_PLAINTEXT: usize = {
    // const indexing of a slice is not stable; LENGTH_BUCKETS is sorted, top last.
    LENGTH_BUCKETS[LENGTH_BUCKETS.len() - 1]
};

/// The crypto provider every TLS config of this relay is built on: aws-lc-rs, whose key
/// exchange groups put the hybrid X25519MLKEM768 first.
///
/// Until 2026-10-03 the relay used `ring`, which has no ML-KEM. Two costs: the tunnel's
/// key exchange was classical only, and the front stood out — the cover site behind the
/// same IP (Caddy) negotiates X25519MLKEM768 with a client that offers it, while the front
/// name picked X25519, and refused a client offering the hybrid alone (alert 40).
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A server config on [`crypto_provider`], with the record-size cap.
fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, std::io::Error> {
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // See MAX_TLS_PLAINTEXT comment — caps the record size so coalescing
    // can't escape the bucket distribution emitted by the codec.
    config.max_fragment_size = Some(MAX_TLS_PLAINTEXT);
    Ok(config)
}

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
        let config = server_config(certs.clone(), key)?;

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
        .map_err(std::io::Error::other)?;

        let cert_der = certified.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
            .map_err(std::io::Error::other)?;

        let spki_hex = compute_spki_hex(&cert_der);

        let config = server_config(vec![cert_der], key_der)?;

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
        let tls = RelayTls::self_signed().expect("self-signed should work");
        assert!(!tls.spki_hex.is_empty());
        assert_eq!(tls.spki_hex.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn spki_is_deterministic() {
        // Self-signed generates a new key each time, so SPKI will differ.
        // But a single instance should have consistent SPKI.
        let tls = RelayTls::self_signed().expect("self-signed should work");
        let spki1 = tls.spki_hex.clone();
        let spki2 = tls.spki_hex.clone();
        assert_eq!(spki1, spki2);
    }

    /// Accepts any server certificate: these tests are about key exchange, not trust.
    #[derive(Debug)]
    struct AnyCert(Arc<CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AnyCert {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Runs a full in-memory handshake against the relay's config with a client offering
    /// exactly `groups`, and returns the group the relay picked.
    fn negotiated_group(groups: &[rustls::NamedGroup]) -> rustls::NamedGroup {
        let tls = RelayTls::self_signed().expect("self-signed should work");
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups.retain(|g| groups.contains(&g.name()));
        provider
            .kx_groups
            .sort_by_key(|g| groups.iter().position(|n| *n == g.name()));
        let provider = Arc::new(provider);
        let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .unwrap();
        let mut server = rustls::ServerConnection::new(tls.acceptor.config().clone()).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets().unwrap();
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!server.is_handshaking(), "handshake did not complete");
        server.negotiated_key_exchange_group().unwrap().name()
    }

    /// A client offering the hybrid and X25519 — as Chrome, Safari and Firefox do — gets
    /// the hybrid, as it does from the cover site on the same IP. Mutation: build the
    /// provider without the hybrid group (what `ring` was) — this picks X25519.
    #[test]
    fn hybrid_offered_is_hybrid_negotiated() {
        use rustls::NamedGroup::{X25519, X25519MLKEM768};
        assert_eq!(negotiated_group(&[X25519MLKEM768, X25519]), X25519MLKEM768);
    }

    /// A client offering only the hybrid completes the handshake. On `ring` this was
    /// alert 40 (handshake_failure). Same mutation reddens it.
    #[test]
    fn hybrid_only_client_is_accepted() {
        use rustls::NamedGroup::X25519MLKEM768;
        assert_eq!(negotiated_group(&[X25519MLKEM768]), X25519MLKEM768);
    }

    /// A classical client still connects.
    #[test]
    fn classical_client_still_connects() {
        use rustls::NamedGroup::X25519;
        assert_eq!(negotiated_group(&[X25519]), X25519);
    }
}
