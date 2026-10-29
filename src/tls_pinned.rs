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
//! store: trust is the SHA-256 of the leaf's DER-encoded SubjectPublicKeyInfo.
//! The pin alone proves nothing — a certificate is public, so anyone can present
//! the front's leaf. What makes the pin a proof of identity is the handshake
//! signature (CertificateVerify / ServerKeyExchange), which only the holder of
//! the private key can produce. [`build_connector`] therefore always verifies
//! that signature with the profile's crypto provider, and a pin is mandatory.
//! Until 2026-10-22 both signature callbacks returned `assertion()` unchecked, so
//! an on-path attacker could terminate the TLS session with the front's own
//! certificate ([[todo/207]]).
//!
//! `build_connector_unpinned` exists only in tests. Its last production caller,
//! the TLS-wrapped obfs4 proxy (which authenticated inside the session with ntor),
//! was removed on 2026-10-22. It still verifies the handshake signature against
//! the presented certificate; it only skips the pin.

use std::{fmt, net::IpAddr, sync::Arc};

use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, OtherError,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio_rustls::TlsConnector;

use crate::tls_fingerprint::TlsProfile;

/// Build a `TlsConnector` + `ServerName` for the DPI-evasion TLS handshake.
///
/// # Parameters
/// - `sni`: SNI to advertise. Empty → IP-based `ServerName` (no SNI extension).
/// - `spki_hex`: hex SHA-256 of DER SubjectPublicKeyInfo (64 hex digits, either
///   case). Required: an empty or malformed pin is an error, never "no pinning"
///   — tests use `build_connector_unpinned` instead.
/// - `relay_addr`: `"ip:port"` string — used to extract the IP when `sni` is empty.
/// - `profile`: TLS fingerprint profile. Controls cipher suite ordering and ALPN
///   to mimic a specific browser ClientHello.
/// - `alpn_override`: When `Some`, replaces the profile's ALPN list. Use to restrict
///   ALPN for transport-specific requirements (e.g. WebSocket requires `http/1.1` only).
///
/// The error string never echoes `spki_hex` (it names a front; this repo is public).
pub fn build_connector(
    sni: &str,
    spki_hex: &str,
    relay_addr: &str,
    profile: TlsProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
) -> Result<(TlsConnector, ServerName<'static>), String> {
    let pin = parse_spki_pin(spki_hex)?;
    let config = client_config(Some(pin), profile, alpn_override)?;
    let server_name = resolve_server_name(sni, relay_addr)?;
    Ok((TlsConnector::from(Arc::new(config)), server_name))
}

/// [`build_connector`] without an SPKI pin: any certificate is accepted, but the
/// handshake signature is still verified against it (so the peer at least holds
/// the key of the certificate it shows).
///
/// Tests only: a server whose key is not known in advance.
#[cfg(test)]
pub fn build_connector_unpinned(
    sni: &str,
    relay_addr: &str,
    profile: TlsProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
) -> Result<(TlsConnector, ServerName<'static>), String> {
    let config = client_config(None, profile, alpn_override)?;
    let server_name = resolve_server_name(sni, relay_addr)?;
    Ok((TlsConnector::from(Arc::new(config)), server_name))
}

/// Parse a hex SPKI pin into its 32 bytes.
///
/// Rejects an empty string, a wrong length, non-hex and non-ASCII input. The
/// error text describes the shape of the problem and never contains the input.
pub fn parse_spki_pin(spki_hex: &str) -> Result<[u8; 32], String> {
    if spki_hex.is_empty() {
        return Err("SPKI pin required (empty)".to_owned());
    }
    let bytes = decode_hex(spki_hex).ok_or_else(|| "SPKI pin is not hex".to_owned())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("SPKI SHA-256 must be 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

/// A change the embedding application makes to every client config before it dials a front.
pub type TlsClientHook = Arc<dyn Fn(&mut ClientConfig) + Send + Sync>;

static TLS_CLIENT_HOOK: std::sync::RwLock<Option<TlsClientHook>> = std::sync::RwLock::new(None);

/// Install `hook`, applied to the client config of every veil-front connection from now on
/// (`None` removes it). One per process, like the coordinator.
///
/// It exists for a ClientHello rustls does not build itself: an application linking a rustls
/// with a hello rewriter (the desktop, through `maxeliseyev/rustls`) sets it here, and
/// construct-veil keeps building against upstream rustls. The hook runs after the pin, ALPN and
/// record cap are set; it must not replace the certificate verifier.
pub fn set_tls_client_hook(hook: Option<TlsClientHook>) {
    *TLS_CLIENT_HOOK.write().unwrap_or_else(|e| e.into_inner()) = hook;
}

/// The client config [`build_connector`] dials with: the profile's provider and groups,
/// the SPKI pin (`None` = unpinned), ALPN, the record-size cap, then the application's hook.
pub(crate) fn client_config(
    pin: Option<[u8; 32]>,
    profile: TlsProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
) -> Result<ClientConfig, String> {
    let provider = profile.crypto_provider();
    let verifier = PinnedSpkiVerifier {
        expected: pin,
        provider: provider.clone(),
    };

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
    if let Some(hook) = TLS_CLIENT_HOOK
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        hook(&mut config);
    }
    Ok(config)
}

// ── Pin errors ────────────────────────────────────────────────────────────────

/// Why the presented certificate failed the SPKI pin. Surfaces as
/// `rustls::Error::InvalidCertificate(CertificateError::Other(_))`, so callers
/// classify a pin failure by type (a certificate problem) instead of by message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// The leaf's SPKI hash is not the pinned one — MitM or key rotation.
    Mismatch,
    /// The leaf could not be parsed as X.509, so it has no SPKI to compare.
    NoSpki,
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinError::Mismatch => f.write_str("SPKI pin mismatch — possible MitM or key rotation"),
            PinError::NoSpki => f.write_str("failed to extract SPKI from cert"),
        }
    }
}

/// rustls renders `CertificateError::Other` through `Debug`, so this is what a
/// log line or `veil_last_error` shows.
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

// ── Pinned SPKI verifier ──────────────────────────────────────────────────────

#[derive(Debug)]
struct PinnedSpkiVerifier {
    /// SHA-256 of DER SubjectPublicKeyInfo, or `None` to accept any cert.
    expected: Option<[u8; 32]>,
    /// Verifies the handshake signature — the part that proves key possession.
    provider: Arc<CryptoProvider>,
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
            let got = spki_sha256(end_entity).ok_or(PinError::NoSpki)?;
            if &got != expected {
                return Err(PinError::Mismatch.into());
            }
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
pub(crate) fn spki_sha256(cert_der: &CertificateDer<'_>) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    let cert = Certificate::from_der(cert_der.as_ref()).ok()?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
    Some(Sha256::digest(&spki_der).into())
}

/// Minimal hex decoder — avoids pulling `hex` crate into non-dev dependencies.
///
/// Works on bytes, so non-ASCII input is rejected instead of panicking on a
/// char boundary; digits only (no sign or whitespace, unlike `from_str_radix`).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !s.is_ascii() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
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

/// In-memory handshake harness shared by the test modules below.
#[cfg(test)]
mod harness {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    /// Drives a full in-memory handshake and returns the client's verdict: `Ok`
    /// once both sides are done, or the error the client raised.
    pub fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> Result<(rustls::ClientConnection, rustls::ServerConnection), TlsError> {
        let mut client = rustls::ClientConnection::new(client, "localhost".try_into().unwrap())?;
        let mut srv = rustls::ServerConnection::new(server)?;
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            srv.read_tls(&mut &buf[..]).unwrap();
            // The server may fail only after the client has already sent an
            // alert; the client's error is the one under test.
            let _ = srv.process_new_packets();
            let mut buf = Vec::new();
            srv.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !srv.is_handshaking() {
                return Ok((client, srv));
            }
        }
        panic!("handshake did not complete");
    }

    /// Always serves the one certified key it was built with — rustls's
    /// `with_single_cert` refuses a key that does not match the certificate,
    /// which is exactly the impostor this harness needs to be able to build.
    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A server on aws-lc-rs that presents `cert` and signs the handshake with
    /// `key_der` (PKCS#8), which need not be the certificate's key, speaking the
    /// given protocol `versions`.
    pub fn server_with(
        cert: CertificateDer<'static>,
        key_der: Vec<u8>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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

    /// Hex SPKI pin of a certificate, as an operator would configure it.
    pub fn pin_of(cert: &CertificateDer<'_>) -> String {
        hex::encode(spki_sha256(cert).unwrap())
    }
}

#[cfg(test)]
mod pinning {
    use super::harness::{handshake, pin_of, server_with};
    use super::*;
    use rustls::version::{TLS12, TLS13};

    fn pinned_client(pin_hex: &str) -> Arc<ClientConfig> {
        Arc::new(
            client_config(
                Some(parse_spki_pin(pin_hex).unwrap()),
                TlsProfile::Chrome131,
                None,
            )
            .unwrap(),
        )
    }

    /// The pin is only proof of identity together with the handshake signature.
    /// A server that shows the pinned certificate but signs with another key is
    /// an impostor and is rejected, on TLS 1.3 and 1.2 alike; the honest server
    /// with the same certificate completes.
    ///
    /// Mutation: make `verify_tls13_signature` return `assertion()` again (the
    /// code until 2026-10-22) — the impostor completes and this fails.
    #[test]
    fn pinned_certificate_must_be_backed_by_its_key() {
        let honest = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let impostor_key = rcgen::KeyPair::generate().unwrap();
        let client = pinned_client(&pin_of(honest.cert.der()));

        for versions in [&[&TLS13][..], &[&TLS12][..]] {
            handshake(
                client.clone(),
                server_with(
                    honest.cert.der().clone(),
                    honest.key_pair.serialize_der(),
                    versions,
                ),
            )
            .unwrap_or_else(|e| panic!("honest server on {versions:?}: {e}"));

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

    /// A certificate with a different key than the pinned one is rejected with a
    /// typed pin error, so callers classify it as a certificate problem, not as
    /// a DPI block.
    #[test]
    fn another_key_than_the_pinned_one_is_a_pin_error() {
        let honest = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = pinned_client(&pin_of(other.cert.der()));

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
        let pin_error = match &err {
            TlsError::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
                inner.downcast_ref::<PinError>().copied()
            }
            _ => None,
        };
        assert_eq!(pin_error, Some(PinError::Mismatch), "{err:?}");
        // What a log line shows: the reason, not an enum variant name.
        assert!(err.to_string().contains("SPKI pin mismatch"), "{err}");
    }

    /// Unpinned still means "the peer holds the key of the certificate it shows".
    #[test]
    fn unpinned_still_verifies_the_handshake_signature() {
        let honest = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let impostor_key = rcgen::KeyPair::generate().unwrap();
        let client = Arc::new(client_config(None, TlsProfile::Chrome131, None).unwrap());

        handshake(
            client.clone(),
            server_with(
                honest.cert.der().clone(),
                honest.key_pair.serialize_der(),
                &[&TLS13],
            ),
        )
        .expect("honest server");
        let err = handshake(
            client,
            server_with(
                honest.cert.der().clone(),
                impostor_key.serialize_der(),
                &[&TLS13],
            ),
        )
        .err()
        .unwrap_or_else(|| panic!("impostor accepted without a pin"));
        assert!(matches!(
            err,
            TlsError::InvalidCertificate(CertificateError::BadSignature)
        ));
    }

    /// A missing or malformed pin is an error, never silent "accept anything";
    /// the error does not echo the input; nothing panics on non-ASCII.
    #[test]
    fn pin_parsing_rejects_bad_input_without_echoing_it() {
        let bad = [
            String::new(),
            "abc".to_owned(),
            "zz".repeat(32),
            "aé".repeat(16), // 48 bytes, even — sliced through 'é' this used to panic
            "+f".repeat(32), // from_str_radix would take the sign
            "ab".repeat(31),
            "ab".repeat(33),
        ];
        for input in &bad {
            let err = parse_spki_pin(input).unwrap_err();
            assert!(
                input.is_empty() || !err.contains(input.as_str()),
                "error echoes the pin: {err}"
            );
            assert!(
                build_connector("", input, "127.0.0.1:443", TlsProfile::Chrome131, None).is_err(),
                "connector built with pin {input:?}"
            );
        }
        assert_eq!(parse_spki_pin(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(parse_spki_pin(&"AB".repeat(32)).unwrap(), [0xab; 32]);
        assert!(build_connector_unpinned("", "127.0.0.1:443", TlsProfile::Chrome131, None).is_ok());
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
        let config = Arc::new(client_config(None, profile, None).unwrap());
        let (_, srv) = super::harness::handshake(config, server).expect("handshake");
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

    /// The application's hook sees every client config built for a front, and stops seeing
    /// them once removed. It only counts, so tests running beside it are not disturbed.
    ///
    /// Mutation: drop the hook call from `client_config` — the count stays put.
    #[test]
    fn the_application_hook_is_applied_to_every_front_config() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        set_tls_client_hook(Some(Arc::new(|_config: &mut ClientConfig| {
            SEEN.fetch_add(1, Ordering::SeqCst);
        })));
        let before = SEEN.load(Ordering::SeqCst);
        build_connector(
            "localhost",
            &"ab".repeat(32),
            "127.0.0.1:443",
            TlsProfile::Chrome131,
            None,
        )
        .unwrap();
        assert!(SEEN.load(Ordering::SeqCst) > before, "the hook ran");
        set_tls_client_hook(None);
        let after = SEEN.load(Ordering::SeqCst);
        build_connector(
            "localhost",
            &"ab".repeat(32),
            "127.0.0.1:443",
            TlsProfile::Chrome131,
            None,
        )
        .unwrap();
        assert_eq!(SEEN.load(Ordering::SeqCst), after, "removed, it does not");
    }
}
