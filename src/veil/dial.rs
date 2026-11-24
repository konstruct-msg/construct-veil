//! What each dial to a front came to, for whoever chooses fronts.
//!
//! The coordinator opens a connection to the front for every local connection, long after
//! `start_session` returned. Until 2026-11-25 a dial that failed there closed the local
//! connection and said nothing more: the host saw a broken stream, which proves nothing about
//! the front, and kept it (construct-docs `decisions/a-front-that-does-not-answer-is-left.md`).

use std::sync::Arc;

/// A dial is TCP and TLS, pin included. What comes after — the AUTH frame, our own expired
/// capability — is not the front's doing and not reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// The front answered under its pinned key.
    Up,
    /// No connection, no handshake, or none in time.
    Failed,
    /// Something answered the front's address under another key: the front changed it, or it is
    /// not the front.
    PinMismatch,
}

/// Told the front's address, as it was given, and what the dial came to. Called from the
/// coordinator's runtime: it must not block. A dial that is stopped before it ends is not told.
pub type DialObserver = Arc<dyn Fn(&str, DialOutcome) + Send + Sync>;

/// The outcome behind a TLS handshake error.
#[cfg(feature = "tls")]
pub(crate) fn outcome_of_tls_error(e: &std::io::Error) -> DialOutcome {
    use crate::tls_pinned::PinError;
    use rustls::{CertificateError, Error, OtherError};
    let pin = match e.get_ref().and_then(|inner| inner.downcast_ref::<Error>()) {
        Some(Error::InvalidCertificate(CertificateError::Other(OtherError(inner)))) => {
            inner.downcast_ref::<PinError>().copied()
        }
        _ => None,
    };
    if pin == Some(PinError::Mismatch) {
        DialOutcome::PinMismatch
    } else {
        DialOutcome::Failed
    }
}
