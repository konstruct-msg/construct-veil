//! TLS fingerprint profiles for browser mimicry.
//!
//! Each profile configures the TLS `CryptoProvider` with the cipher suite
//! ordering and key exchange groups used by the corresponding browser. This
//! shifts the TLS fingerprint away from the default "obviously rustls" pattern
//! towards something that resembles real browser traffic.
//!
//! # Limitations
//!
//! Pure-rustls fingerprint mimicry is approximate. The following features that
//! appear in Chrome/Firefox ClientHellos **cannot** be replicated without
//! BoringSSL or a custom low-level TLS stack:
//!
//! | Feature | Chrome ext# | Status |
//! |---------|-------------|--------|
//! | GREASE values | varies | ❌ not possible in rustls |
//! | renegotiation_info | 65281 | ❌ not supported |
//! | session_ticket | 35 | ⚠ sent empty, Chrome caches tickets |
//! | status_request / OCSP | 5 | ❌ not sent by default |
//! | signed_certificate_timestamp | 18 | ❌ not sent |
//! | compress_certificate | 27 | ❌ not supported |
//! | application_settings | 17513 | ❌ not supported |
//!
//! For exact JA3/JA4 matching, build with BoringSSL via `tokio-boring` (not
//! included — it breaks iOS static linking and requires a C toolchain).
//!
//! `ja3_string()` / `ja3_hash()` return values for what **we actually send**,
//! not the canonical browser JA3 — the two will differ due to the limitations
//! above. Use them for monitoring and comparing runs, not for claiming
//! "we are Chrome".
//!
//! ## What this buys you
//!
//! Even with the limitations above, a `Chrome131` profile:
//! - Sends Chrome's exact cipher suite ordering (9 of Chrome's 15 ciphers)
//! - Uses Chrome's key share group preference (x25519 → P-256 → P-384)
//! - Advertises `h2,http/1.1` ALPN as Chrome does
//! - Removes the distinctive default rustls cipher ordering
//!
//! This defeats heuristic DPI and hash-based blocklists that fingerprint
//! the default rustls negotiation. It does **not** defeat strict allowlists
//! that require an exact Chrome/Firefox JA3/JA4 match.

use rustls::crypto::{CryptoProvider, ring as rng};
use std::sync::Arc;

// ── Profile enum ──────────────────────────────────────────────────────────────

/// TLS fingerprint profile.
///
/// Controls cipher suite ordering, key exchange groups, and ALPN to mimic
/// a specific browser's ClientHello as closely as possible with pure rustls.
///
/// Pass to [`crate::transport::ClientConfig::with_tls_profile`] before calling
/// [`crate::transport::Obfs4Stream::connect_tls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsProfile {
    /// rustls defaults — recognizable TLS fingerprint. Use only in tests.
    ///
    /// JA3 ciphers: 4867-4866-4865-52393-52392-49199-49200-49195-49196
    Rustls,

    /// Chrome 131 cipher suite ordering + key groups. **Default for production.**
    ///
    /// JA3 ciphers: 4865-4866-4867-49195-49199-49196-49200-52393-52392
    /// (Chrome additionally sends 49171,49172,156,157,47,53 — CBC and RSA
    /// key-exchange suites not available in the rustls ring provider.)
    #[default]
    Chrome131,

    /// Firefox 128 cipher suite ordering + key groups.
    ///
    /// JA3 ciphers: 4865-4867-4866-49195-49199-52393-52392-49196-49200
    /// (Firefox additionally sends 49171,49172,47,53 — not in ring provider.)
    Firefox128,
}

impl TlsProfile {
    /// Build a custom [`CryptoProvider`] reflecting this profile's cipher /
    /// key-group ordering.
    pub(crate) fn crypto_provider(self) -> Arc<CryptoProvider> {
        match self {
            TlsProfile::Rustls => Arc::new(rng::default_provider()),
            TlsProfile::Chrome131 => Arc::new(chrome_131_provider()),
            TlsProfile::Firefox128 => Arc::new(firefox_128_provider()),
        }
    }

    /// ALPN protocol list for this profile.
    ///
    /// Empty = no ALPN extension. Chrome and Firefox both advertise
    /// `["h2", "http/1.1"]`.
    pub(crate) fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            TlsProfile::Rustls => vec![],
            TlsProfile::Chrome131 | TlsProfile::Firefox128 => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
        }
    }

    /// JA3 input string for what this configuration **actually sends**.
    ///
    /// Format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
    ///
    /// All GREASE values are pre-stripped. The ciphers and extensions reflect
    /// only what the rustls ring provider actually sends — see module-level
    /// docs for what is missing vs. a real browser.
    pub fn ja3_string(self) -> String {
        // Extensions sent by rustls ring (approximate, actual order may vary):
        //   server_name(0), extended_master_secret(23), supported_groups(10),
        //   ec_point_formats(11), signature_algorithms(13), supported_versions(43),
        //   key_share(51), psk_key_exchange_modes(45)
        //   + ALPN(16) when configured
        //
        // SSLVersion=771 (TLS 1.2 record layer, even when TLS 1.3 is negotiated).
        // Supported groups: x25519(29), secp256r1(23), secp384r1(24).
        // EC point formats: uncompressed(0).
        match self {
            TlsProfile::Rustls => {
                // Default ring provider cipher order (TLS 1.3 first, then 1.2):
                // CHACHA20(4867), AES256(4866), AES128(4865),
                // ECDHE-ECDSA-CHACHA20(52393), ECDHE-RSA-CHACHA20(52392),
                // ECDHE-RSA-AES128(49199), ECDHE-RSA-AES256(49200),
                // ECDHE-ECDSA-AES128(49195), ECDHE-ECDSA-AES256(49196)
                // No ALPN → no ext 16.
                "771,4867-4866-4865-52393-52392-49199-49200-49195-49196,\
                 0-23-10-11-13-43-51-45,29-23-24,0"
                    .to_owned()
            }
            TlsProfile::Chrome131 => {
                // Chrome 131 cipher order (ring-available subset, no GREASE/CBC/RSA)
                // AES128(4865), AES256(4866), CHACHA20(4867), then TLS 1.2 ECDSA→RSA
                // + ALPN(16) added since we configure h2/http1.1
                "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,\
                 0-23-10-11-16-13-43-51-45,29-23-24,0"
                    .to_owned()
            }
            TlsProfile::Firefox128 => {
                // Firefox 128: CHACHA20 second in TLS 1.3; ECDSA+RSA interleaved
                // AES128(4865), CHACHA20(4867), AES256(4866), then TLS 1.2
                // + ALPN(16) configured
                "771,4865-4867-4866-49195-49199-52393-52392-49196-49200,\
                 0-23-10-11-16-13-43-51-45,29-23-24,0"
                    .to_owned()
            }
        }
    }

    /// MD5 of [`ja3_string()`] — the standard JA3 fingerprint hex digest.
    ///
    /// MD5 is used here only because it is the [JA3 specification][ja3] format.
    /// It is not used for any security-critical operation.
    ///
    /// [ja3]: https://github.com/salesforce/ja3
    #[cfg(feature = "utls")]
    pub fn ja3_hash(self) -> String {
        md5_hex(self.ja3_string().as_bytes())
    }

    /// Human-readable display name for this profile.
    pub fn name(self) -> &'static str {
        match self {
            TlsProfile::Rustls => "rustls-default",
            TlsProfile::Chrome131 => "Chrome/131",
            TlsProfile::Firefox128 => "Firefox/128",
        }
    }

    /// Parse a profile from a case-insensitive string.
    ///
    /// Accepts: `"chrome131"`, `"chrome"`, `"firefox128"`, `"firefox"`,
    /// `"rustls"`, `""` (empty → `Rustls`).
    pub fn from_name(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "chrome131" | "chrome" => TlsProfile::Chrome131,
            "firefox128" | "firefox" => TlsProfile::Firefox128,
            _ => TlsProfile::Rustls,
        }
    }
}

// ── Provider builders ─────────────────────────────────────────────────────────

/// Chrome 131 TLS configuration:
/// - TLS 1.3 order: AES-128 → AES-256 → CHACHA20
/// - TLS 1.2 order: ECDSA variants before RSA (Chrome prefers ECDSA server certs)
/// - Key groups: x25519 → P-256 → P-384
fn chrome_131_provider() -> CryptoProvider {
    use rng::cipher_suite as cs;
    use rng::kx_group as kx;

    let mut provider = rng::default_provider();
    provider.cipher_suites = vec![
        // TLS 1.3 — Chrome 131 order
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2 — ECDSA first, then RSA (Chrome preference order)
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    // Chrome 131 key exchange groups: x25519 (preferred), P-256, P-384
    provider.kx_groups = vec![kx::X25519, kx::SECP256R1, kx::SECP384R1];
    provider
}

/// Firefox 128 TLS configuration:
/// - TLS 1.3 order: AES-128 → CHACHA20 → AES-256 (CHACHA20 preferred over AES-256)
/// - TLS 1.2 order: ECDSA+RSA interleaved, CHACHA20 after AES-128
/// - Key groups: x25519 → P-256 → P-384
fn firefox_128_provider() -> CryptoProvider {
    use rng::cipher_suite as cs;
    use rng::kx_group as kx;

    let mut provider = rng::default_provider();
    provider.cipher_suites = vec![
        // TLS 1.3 — Firefox 128 prefers CHACHA20 over AES-256
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
        // TLS 1.2 — interleaved ECDSA/RSA, CHACHA20 before AES-256
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];
    // Firefox 128 key groups: x25519 → P-256 → P-384
    provider.kx_groups = vec![kx::X25519, kx::SECP256R1, kx::SECP384R1];
    provider
}

// ── JA3 MD5 ──────────────────────────────────────────────────────────────────

/// Compute the lowercase hex MD5 digest of `data`.
///
/// Used only for the industry-standard JA3 fingerprint format.
/// Not security-critical.
#[cfg(feature = "utls")]
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let hash = Md5::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja3_strings_are_non_empty() {
        for profile in [
            TlsProfile::Rustls,
            TlsProfile::Chrome131,
            TlsProfile::Firefox128,
        ] {
            let s = profile.ja3_string();
            assert!(!s.is_empty(), "{:?} ja3_string is empty", profile);
            // JA3 format: 5 comma-separated sections
            assert_eq!(s.matches(',').count(), 4, "{:?} wrong JA3 format", profile);
        }
    }

    #[test]
    fn profiles_are_distinct() {
        assert_ne!(
            TlsProfile::Chrome131.ja3_string(),
            TlsProfile::Firefox128.ja3_string()
        );
        assert_ne!(
            TlsProfile::Rustls.ja3_string(),
            TlsProfile::Chrome131.ja3_string()
        );
    }

    #[test]
    fn from_str_round_trip() {
        assert_eq!(TlsProfile::from_name("chrome131"), TlsProfile::Chrome131);
        assert_eq!(TlsProfile::from_name("Chrome"), TlsProfile::Chrome131);
        assert_eq!(TlsProfile::from_name("firefox128"), TlsProfile::Firefox128);
        assert_eq!(TlsProfile::from_name("Firefox"), TlsProfile::Firefox128);
        assert_eq!(TlsProfile::from_name(""), TlsProfile::Rustls);
        assert_eq!(TlsProfile::from_name("unknown"), TlsProfile::Rustls);
    }

    #[cfg(feature = "utls")]
    #[test]
    fn ja3_hash_is_32_hex_chars() {
        for profile in [TlsProfile::Chrome131, TlsProfile::Firefox128] {
            let h = profile.ja3_hash();
            assert_eq!(h.len(), 32, "{:?} hash length wrong", profile);
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "non-hex in hash");
        }
    }

    #[test]
    fn chrome_provider_builds() {
        use rustls::crypto::ring::cipher_suite as cs;
        let p = TlsProfile::Chrome131.crypto_provider();
        // Chrome 131 order: AES-128-GCM-SHA256 must be first, AES-256 second, CHACHA20 third
        assert_eq!(
            p.cipher_suites[0].suite(),
            cs::TLS13_AES_128_GCM_SHA256.suite()
        );
        assert_eq!(
            p.cipher_suites[1].suite(),
            cs::TLS13_AES_256_GCM_SHA384.suite()
        );
        assert_eq!(
            p.cipher_suites[2].suite(),
            cs::TLS13_CHACHA20_POLY1305_SHA256.suite()
        );
    }

    #[test]
    fn firefox_provider_builds() {
        use rustls::crypto::ring::cipher_suite as cs;
        let p = TlsProfile::Firefox128.crypto_provider();
        // Firefox 128 TLS 1.3: AES-128 first, CHACHA20 before AES-256
        assert_eq!(
            p.cipher_suites[0].suite(),
            cs::TLS13_AES_128_GCM_SHA256.suite()
        );
        assert_eq!(
            p.cipher_suites[1].suite(),
            cs::TLS13_CHACHA20_POLY1305_SHA256.suite()
        );
        assert_eq!(
            p.cipher_suites[2].suite(),
            cs::TLS13_AES_256_GCM_SHA384.suite()
        );
    }
}
