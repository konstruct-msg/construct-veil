//! Issue a veil-front ticket.
//!
//! Generates a fresh 65-byte ticket (random id + random auth key + validity
//! window) and prints it base64-encoded to stdout. Append to / overwrite the
//! relay's `tickets.json` (which is a JSON array of base64 blobs).
//!
//! ```text
//! issue-ticket --days 60 > /etc/veil-front/tickets.json
//! ```
//!
//! Or to add to an existing tickets file:
//! ```text
//! issue-ticket --days 60 --append /etc/veil-front/tickets.json
//! ```

use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::Parser;
use construct_veil_protocol::ticket::{
    AUTH_KEY_LEN, AuthKey, TICKET_ID_LEN, Ticket, ticket_to_bytes,
};
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(name = "issue-ticket", about = "Issue a veil-front ticket (base64)")]
struct Args {
    /// Validity window in days from now (default 60 = standard rotation).
    #[arg(long, default_value_t = 60)]
    days: u64,

    /// Suite id (CLASSIC v1 = 1; only suite currently defined).
    #[arg(long, default_value_t = 1)]
    suite_id: u8,

    /// Append to an existing tickets.json (JSON array of base64 strings) instead
    /// of writing to stdout. Creates the file if missing.
    #[arg(long, value_name = "PATH")]
    append: Option<String>,

    /// Replace an existing tickets.json with a single fresh ticket.
    #[arg(long, value_name = "PATH", conflicts_with = "append")]
    write: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut rng = rand::thread_rng();

    let mut ticket_id = [0u8; TICKET_ID_LEN];
    rng.fill_bytes(&mut ticket_id);

    let mut key_bytes = [0u8; AUTH_KEY_LEN];
    rng.fill_bytes(&mut key_bytes);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    let not_after = now + args.days * 24 * 60 * 60;

    let ticket = Ticket {
        ticket_id,
        auth_key: AuthKey::new(key_bytes),
        not_before: now,
        not_after,
        suite_id: args.suite_id,
    };

    let bytes = ticket_to_bytes(&ticket);
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);

    // ── Output mode ────────────────────────────────────────────────────────
    if let Some(path) = args.write {
        let json = serde_json::to_string_pretty(&vec![&b64])?;
        fs::write(&path, json)?;
        eprintln!("Wrote 1 ticket to {path}");
        eprintln!(
            "  ticket_id = {}",
            hex_encode(&ticket.ticket_id)
        );
        eprintln!("  not_after = {not_after} ({} days from now)", args.days);
    } else if let Some(path) = args.append {
        let mut existing: Vec<String> = match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        existing.push(b64.clone());
        let json = serde_json::to_string_pretty(&existing)?;
        fs::write(&path, json)?;
        eprintln!("Appended ticket to {path} (total = {})", existing.len());
        eprintln!(
            "  ticket_id = {}",
            hex_encode(&ticket.ticket_id)
        );
        eprintln!("  not_after = {not_after} ({} days from now)", args.days);
    } else {
        // stdout — print just the base64 so it can be piped / captured.
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        writeln!(h, "{b64}")?;
    }

    // Print client-facing ticket_id to stderr so it's available for the
    // manifest publisher script without contaminating stdout.
    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

