//! Measurement harness: brings up a REAL veil-front tunnel through the rustls
//! (Chrome131) client path via `VeilCoordinator`, so its traffic shape can be
//! captured. Test-only; secrets come from files, never argv.
//!
//! Build/run: cargo run --features coordinator,utls --example veil_front_probe -- \
//!     --link <file> --idle 10
//!
//! The link file carries a bearer capability (AUTH v2); with `--sk-hex <file>`
//! plus a v2 key-bound capability (`--capability-b64 <file>`) AUTH v3 is used
//! instead.

use std::time::{Duration, Instant};

use construct_veil::veil::{
    MethodSet, NetworkFingerprint, VeilConfig, VeilCoordinator, VeilFrontAuthV3,
    VeilFrontObfuscator, scoring::PersistentScores,
};
use tokio::io::AsyncWriteExt;

/// Extract a flat string field from a JSON object (no serde_json dependency).
fn json_str(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = json.find(&pat)? + pat.len();
    let rest = json[i..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            c => out.push(c),
        }
    }
    None
}

fn b64url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    let s = s.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .expect("bad base64 in link")
}

fn usage() -> ! {
    eprintln!(
        "usage: veil_front_probe (--link <file> | --relay H:P --sni S --spki HEX \
         --capability-b64 <file> [--sk-hex <file>]) [--idle SECS] [--active SECS]\n\n\
         Secrets (the link, the capability and the sk) come from files, never argv: a\n\
         URL in argv shows up in `ps` and shell history."
    );
    std::process::exit(2)
}

/// Read a secret from a file, trimmed of whitespace. Secrets stay out of argv.
fn read_secret_file(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| {
            eprintln!("cannot read secret file {path}: {e}");
            usage()
        })
        .trim()
        .to_string()
}

#[tokio::main]
async fn main() {
    let mut a = std::env::args().skip(1);
    let (mut link, mut relay, mut sni, mut spki, mut cap, mut sk) =
        (None, None, None, None, None, String::new());
    let (mut idle, mut active) = (0u64, 0u64);
    while let Some(k) = a.next() {
        let mut v = || a.next().unwrap_or_else(|| usage());
        match k.as_str() {
            "--link" => link = Some(v()),
            "--relay" => relay = Some(v()),
            "--sni" => sni = Some(v()),
            "--spki" => spki = Some(v()),
            "--capability-b64" => cap = Some(read_secret_file(&v())),
            "--sk-hex" => sk = read_secret_file(&v()),
            "--idle" => idle = v().parse().unwrap_or_else(|_| usage()),
            "--active" => active = v().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    if let Some(l) = link {
        // The link is a file whose content is the `konstruct://…` URL; reading the
        // URL straight from argv would leak it (ps, history).
        let raw = std::fs::read_to_string(&l).expect("read link file");
        // The link data is the `d=` query parameter; find it as a parameter, not
        // by the first `d=` substring (a `d=` earlier in the URL would misparse).
        let d = raw
            .trim()
            .split_once('?')
            .map(|(_, q)| q)
            .unwrap_or(raw.trim())
            .split(['&', '#'])
            .find_map(|kv| kv.strip_prefix("d="))
            .unwrap_or_else(|| usage());
        let json = String::from_utf8(b64url_decode(d)).expect("link JSON not utf8");
        relay = relay.or(json_str(&json, "relay").or(json_str(&json, "relay_addr")));
        sni = sni.or(json_str(&json, "sni"));
        spki = spki.or(json_str(&json, "spki"));
        cap = cap.or(json_str(&json, "capability"));
        if sk.is_empty() {
            sk = json_str(&json, "sk").unwrap_or_default();
        }
    }
    let (relay, sni, spki, cap) = match (relay, sni, spki, cap) {
        (Some(r), Some(s), Some(p), Some(c)) => (r, s, p, c),
        _ => usage(),
    };

    // Mirror ffi::veil_start: veil-front-only coordinator, in-memory scores.
    let scores = PersistentScores::open_default(":memory:")
        .await
        .expect("scores");
    let mut coord = VeilCoordinator::new(VeilConfig::default(), scores);
    coord.register(Box::new(VeilFrontObfuscator::new()));

    // v3 (key-bound) when a secret key is given; otherwise v2 bearer capability
    // travels as the ticket.
    let (ticket, v3) = if sk.is_empty() {
        (cap, VeilFrontAuthV3::default())
    } else {
        (
            String::new(),
            VeilFrontAuthV3 {
                capability_v2_b64: cap,
                veil_sk_hex: sk,
            },
        )
    };

    let t0 = Instant::now();
    let res = coord
        .start_session_with_params(
            relay.clone(),
            NetworkFingerprint::default(),
            MethodSet::from_bitmask(0),
            sni,
            spki,
            ticket,
            v3,
        )
        .await;
    let r = match res {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[probe] TUNNEL FAILED after {:?}: {e}", t0.elapsed());
            eprintln!("[probe] diag: {}", construct_veil::veil::diag::last());
            std::process::exit(1);
        }
    };
    eprintln!(
        "[probe] TUNNEL UP (veil-active, rpc-ok: AUTH accepted + h2 SETTINGS round-trip) \
         method={:?} latency_ms={} t={:?}",
        r.method,
        r.latency_ms,
        t0.elapsed()
    );
    eprintln!("[probe] local proxy port: {}", r.port);

    if active > 0 {
        eprintln!("[probe] active mode: {active}s");
        let end = Instant::now() + Duration::from_secs(active);
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", r.port))
            .await
            .expect("connect local proxy");
        let mut n = 0u32;
        while Instant::now() < end {
            let len = 64 + (n as usize * 37) % 193;
            let payload = vec![0x5au8; len];
            match s.write_all(&payload).await {
                Ok(()) => eprintln!("[probe] wrote {len} B"),
                Err(e) => {
                    eprintln!("[probe] write failed (backend/ferry tore down?): {e}");
                    break;
                }
            }
            n += 1;
            tokio::time::sleep(Duration::from_millis(2000 + (n as u64 * 700) % 3000)).await;
        }
    }
    if idle > 0 {
        eprintln!("[probe] idle mode: holding {idle}s");
        tokio::time::sleep(Duration::from_secs(idle)).await;
    }
    coord.stop().await;
    eprintln!("[probe] done");
}
