//! Minimal global last-error sink.
//!
//! The iOS FFI only sees `veil_start() -> -1`; the real `ObfuscatorError`
//! (Timeout / CertProblem / Handshake / Io …) is otherwise lost because Rust
//! `tracing`/`eprintln!` is not captured by the host's unified log. The probe
//! path records the most specific failure here, and `veil_last_error()` surfaces
//! it to the host so a device log can name the exact failing stage.

use std::sync::Mutex;

static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

/// Overwrite the recorded failure with the most specific detail available.
pub fn record(s: impl Into<String>) {
    if let Ok(mut g) = LAST_ERROR.lock() {
        *g = s.into();
    }
}

/// Clear the sink at the start of a fresh `veil_start` so a stale error from a
/// previous attempt can't be misread as the current one.
pub fn clear() {
    if let Ok(mut g) = LAST_ERROR.lock() {
        g.clear();
    }
}

/// The most recent recorded failure (empty string if none).
pub fn last() -> String {
    LAST_ERROR.lock().map(|g| g.clone()).unwrap_or_default()
}
