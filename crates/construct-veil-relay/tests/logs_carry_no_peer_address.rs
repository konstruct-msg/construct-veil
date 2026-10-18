//! A relay log above `debug` never names the client's address.
//!
//! `tunnel progress` wrote `peer=<ip>:<port>` at info every 3 s per tunnel; on one front that
//! was 53k lines a day of VEIL users' addresses in a docker log with no expiry (TODO 163,
//! 2026-10-16). Operators run at `info`, so anything at `info` and above is retained.

use std::fs;
use std::path::Path;

/// Every `info!(…)`, `warn!(…)` and `error!(…)` invocation in `src`, as (file:line, text).
fn above_debug_log_calls() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut calls = Vec::new();
    for entry in fs::read_dir(&src).expect("src dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        for mac in ["info!(", "warn!(", "error!("] {
            let mut from = 0;
            while let Some(at) = text[from..].find(mac) {
                let start = from + at;
                let open = start + mac.len() - 1;
                let mut depth = 0usize;
                let mut end = open;
                for (i, ch) in text[open..].char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = open + i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let line = text[..start].lines().count();
                calls.push((format!("{name}:{line}"), text[start..=end].to_string()));
                from = end + 1;
            }
        }
    }
    calls
}

#[test]
fn no_log_above_debug_names_the_peer() {
    let calls = above_debug_log_calls();
    assert!(
        calls.len() > 10,
        "the scan found the relay's log calls ({})",
        calls.len()
    );
    let leaks: Vec<_> = calls
        .iter()
        .filter(|(_, call)| call.contains("peer =") || call.contains("{peer"))
        .map(|(at, _)| at.as_str())
        .collect();
    assert!(
        leaks.is_empty(),
        "client address logged above debug at {leaks:?}"
    );
}
