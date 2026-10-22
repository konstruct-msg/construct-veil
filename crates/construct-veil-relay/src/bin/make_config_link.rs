//! make-config-link — generate a signed veil-front config link (+ terminal QR) for
//! manual tester bootstrap provisioning, before the in-band issuance service is wired.
//!
//! It mints a fresh **backend-signed capability** (the relay validates it offline
//! against the issuer public key — no tickets.json), wraps it in a config blob with
//! the relay coords, Ed25519-signs the canonical JSON exactly as the iOS client
//! verifies it, and prints a `konstruct://veil-config?d=…` link + a scannable QR.
//!
//! The signing key is the Ed25519 **private seed** (32-byte hex) = the issuer key
//! (`relayConfigSigningKey`). Keep it secret. The tool prints the derived public key —
//! it must equal both the app's `relayConfigSigningKey` AND the relay's `--issuer-pubkey`.
//!
//! ```text
//! make-config-link --signing-key-file issuer.seed --spki <relay-spki-hex> \
//!     --relay front.example.com:443 --scope "" --days 60
//! ```
//!
//! The seed comes from `--signing-key-file` or the `VEIL_SIGNING_KEY` environment
//! variable. `--signing-key <hex>` still works but puts the master key in `ps`
//! output and shell history, so it prints a warning.
//!
//! No relay restart / tickets.json needed: the relay validates the capability's
//! signature offline, so the link works as soon as the relay runs with the matching
//! `--issuer-pubkey`.

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::Parser;
use construct_veil_protocol::Capability;
use construct_veil_protocol::ticket::{AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN, Ticket};
use rand::RngCore;
use ring::signature::{Ed25519KeyPair, KeyPair};

#[derive(Parser, Debug)]
#[command(
    name = "make-config-link",
    about = "Issue a ticket + emit a signed veil-front config link + QR"
)]
struct Args {
    /// File holding the Ed25519 private seed (64 hex chars) = relayConfigSigningKey.
    #[arg(long, value_name = "PATH")]
    signing_key_file: Option<String>,

    /// The seed itself, on the command line. Discouraged: visible in `ps` and
    /// shell history. Prefer `--signing-key-file` or `VEIL_SIGNING_KEY`.
    #[arg(long)]
    signing_key: Option<String>,

    /// Relay address (host:port). Required — no production default (opsec).
    #[arg(long)]
    relay: String,

    /// TLS SNI (defaults to the host part of --relay).
    #[arg(long)]
    sni: Option<String>,

    /// Relay SPKI pin (hex SHA-256 of DER SubjectPublicKeyInfo). Must match the app's pin.
    #[arg(long)]
    spki: String,

    /// Ticket validity in days. Also sets the config-blob `exp`.
    #[arg(long, default_value_t = 60)]
    days: u64,

    /// Suite id (CLASSIC v1 = 1).
    #[arg(long, default_value_t = 1)]
    suite_id: u8,

    /// Relay scope the capability is valid on (must match the relay's --relay-scope;
    /// empty = any scope).
    #[arg(long, default_value = "")]
    scope: String,

    /// Also write the QR to an SVG file (open in a browser, scan, or send to a tester).
    #[arg(long, value_name = "PATH")]
    qr_svg: Option<String>,
}

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // ── Signing key ─────────────────────────────────────────────────────────
    let signing_key = resolve_signing_key(
        args.signing_key_file.as_deref(),
        std::env::var("VEIL_SIGNING_KEY").ok(),
        args.signing_key.as_deref(),
    )?;
    let seed = hex_decode(&signing_key).ok_or("signing key must be hex")?;
    if seed.len() != 32 {
        return Err(format!(
            "--signing-key must be 32 bytes (64 hex chars), got {}",
            seed.len()
        )
        .into());
    }
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| format!("invalid Ed25519 seed: {e}"))?;
    let pub_hex = hex_encode(key_pair.public_key().as_ref());

    // ── Issue a fresh ticket ────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let mut ticket_id = [0u8; TICKET_ID_LEN];
    rng.fill_bytes(&mut ticket_id);
    let mut key_bytes = [0u8; AUTH_KEY_LEN];
    rng.fill_bytes(&mut key_bytes);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let exp = now + args.days * 24 * 60 * 60;
    let ticket = Ticket {
        ticket_id,
        auth_key: AuthKey::new(key_bytes),
        not_before: now,
        not_after: exp,
        suite_id: args.suite_id,
    };
    // Sign the capability with the issuer seed (same key, domain "veil-cap-v1").
    let seed32: [u8; 32] = seed
        .as_slice()
        .try_into()
        .expect("seed length checked above");
    let capability = Capability::sign(ticket, args.scope.clone(), &seed32)?;
    let cap_b64 = base64::engine::general_purpose::STANDARD.encode(capability.encode());

    // ── Build + sign the config blob ────────────────────────────────────────
    let sni = args.sni.clone().unwrap_or_else(|| {
        args.relay
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| args.relay.clone())
    });
    // Canonical signed bytes: JSON of the blob WITHOUT `signature`, sorted keys,
    // compact, slashes not escaped — a BTreeMap serialized by serde_json matches the
    // iOS client's JSONSerialization(.sortedKeys, .withoutEscapingSlashes).
    let mut fields: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    fields.insert("relay", args.relay.clone().into());
    fields.insert("sni", sni.into());
    fields.insert("spki", args.spki.clone().into());
    fields.insert("capability", cap_b64.clone().into());
    fields.insert("exp", serde_json::Value::Number((exp as i64).into()));
    let canonical = serde_json::to_string(&fields)?;
    let sig = key_pair.sign(canonical.as_bytes());

    // Full blob (with signature) → base64url → the `d=` query value. The client
    // re-canonicalizes the non-signature fields, so this serialization need not be
    // canonical itself.
    let mut full = fields.clone();
    full.insert(
        "signature",
        format!("ed25519:{}", B64URL.encode(sig.as_ref())).into(),
    );
    let d = B64URL.encode(serde_json::to_string(&full)?.as_bytes());
    let link = format!("konstruct://veil-config?d={d}");

    // ── Output ──────────────────────────────────────────────────────────────
    // No tickets.json / restart: the relay validates the capability signature offline.
    eprintln!();
    eprintln!("signing/issuer pubkey: {pub_hex}");
    eprintln!("  (must equal the app's relayConfigSigningKey AND the relay's --issuer-pubkey)");
    eprintln!("relay:   {}", args.relay);
    eprintln!(
        "scope:   {}",
        if args.scope.is_empty() {
            "(any)"
        } else {
            &args.scope
        }
    );
    eprintln!("expires: {exp}  (+{} days)", args.days);
    eprintln!("capability (base64, for DEBUG baking if needed):");
    eprintln!("    {cap_b64}");
    eprintln!();
    // The link goes to stdout so it can be piped/copied; everything else is stderr.
    println!("{link}");
    eprintln!();
    match qrcode::QrCode::new(link.as_bytes()) {
        Ok(code) => {
            let qr = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            eprintln!("{qr}");
            if let Some(path) = &args.qr_svg {
                let svg = code
                    .render::<qrcode::render::svg::Color>()
                    .min_dimensions(256, 256)
                    .quiet_zone(true)
                    .build();
                // The QR is a credential (the link inside it admits the bearer).
                write_private(path, svg.as_bytes())?;
                eprintln!("✓ QR written to {path}");
            }
        }
        Err(e) => eprintln!("(QR render failed: {e})"),
    }
    Ok(())
}

/// Where the issuer seed comes from, in order of preference: a file, the
/// `VEIL_SIGNING_KEY` environment variable, then `--signing-key` (with a warning —
/// argv is readable by every local user via `ps` and lands in shell history).
/// Until 2026-10-22 argv was the only way.
fn resolve_signing_key(
    file: Option<&str>,
    env: Option<String>,
    argv: Option<&str>,
) -> Result<String, String> {
    if let Some(path) = file {
        return fs::read_to_string(path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| format!("reading --signing-key-file: {e}"));
    }
    if let Some(key) = env.filter(|k| !k.trim().is_empty()) {
        return Ok(key.trim().to_owned());
    }
    if let Some(key) = argv {
        eprintln!(
            "warning: --signing-key puts the issuer seed in `ps` output and shell history; \
             use --signing-key-file or VEIL_SIGNING_KEY"
        );
        return Ok(key.trim().to_owned());
    }
    Err("no signing key: pass --signing-key-file PATH or set VEIL_SIGNING_KEY".into())
}

/// Write a file only its owner can read (0600 on unix), replacing any old one.
fn write_private(path: &str, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let _ = fs::remove_file(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// File beats env beats argv; nothing at all is an error. Mutation: read
    /// argv first — the file path is ignored.
    #[test]
    fn the_signing_key_prefers_file_then_env_then_argv() {
        let mut path = std::env::temp_dir();
        path.push(format!("veil-mcl-{}-seed", std::process::id()));
        fs::write(&path, "  aa\n").unwrap();
        let file = path.to_str().unwrap();

        assert_eq!(
            resolve_signing_key(Some(file), Some("bb".into()), Some("cc")).unwrap(),
            "aa"
        );
        assert_eq!(
            resolve_signing_key(None, Some("bb".into()), Some("cc")).unwrap(),
            "bb"
        );
        assert_eq!(resolve_signing_key(None, None, Some("cc")).unwrap(), "cc");
        assert!(resolve_signing_key(None, Some("  ".into()), None).is_err());
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn the_qr_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let mut path = std::env::temp_dir();
        path.push(format!("veil-mcl-{}-qr.svg", std::process::id()));
        let path = path.to_str().unwrap().to_owned();
        write_private(&path, b"<svg/>").unwrap();
        write_private(&path, b"<svg>2</svg>").unwrap(); // regenerating replaces it
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"<svg>2</svg>");
        let _ = fs::remove_file(&path);
    }
}
