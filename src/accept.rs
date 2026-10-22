//! What an accept loop does when `accept()` fails.
//!
//! Every local listener here (the FFI proxies, the coordinator's proxy, the
//! host-terminated veil-front listener) used to handle an accept error in one of
//! two wrong ways: `break`, which killed the proxy on a transient error while its
//! slot still reported "running", or `continue`, which on EMFILE/ENFILE spun a
//! worker thread at 100 % CPU (accept fails immediately while the process is out
//! of descriptors) — battery drain on a phone. Both are replaced by
//! [`accept_retry_delay`].

use std::io::{Error, ErrorKind};
use std::time::Duration;

/// How long to wait before accepting again, or `None` when the listener itself
/// is broken and the loop should end.
///
/// - The peer gave up between SYN and accept, or a signal interrupted the call:
///   retry at once.
/// - Out of file descriptors or memory: retry after a pause, so descriptors held
///   by finishing tunnels can be freed instead of the loop spinning.
/// - Anything else (the listening socket is invalid, closed, or not a listener):
///   the listener is gone; end the loop.
pub(crate) fn accept_retry_delay(e: &Error) -> Option<Duration> {
    match e.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => Some(Duration::ZERO),
        _ => match e.raw_os_error() {
            Some(code) if is_resource_exhaustion(code) => Some(Duration::from_millis(100)),
            _ if e.kind() == ErrorKind::OutOfMemory => Some(Duration::from_millis(100)),
            _ => None,
        },
    }
}

#[cfg(unix)]
fn is_resource_exhaustion(code: i32) -> bool {
    // EMFILE / ENFILE / ENOBUFS / ENOMEM. Values differ between Linux and the BSDs
    // (Darwin), so they are spelled per platform rather than pulled from libc.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const CODES: [i32; 4] = [24, 23, 105, 12];
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const CODES: [i32; 4] = [24, 23, 55, 12];
    CODES.contains(&code)
}

#[cfg(not(unix))]
fn is_resource_exhaustion(_code: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutation: return `None` for EMFILE (the old `break`) or `Some(ZERO)` (the
    /// old `continue` spin) — one of the two assertions fails.
    #[test]
    fn transient_errors_retry_and_exhaustion_backs_off() {
        assert_eq!(
            accept_retry_delay(&Error::from(ErrorKind::ConnectionAborted)),
            Some(Duration::ZERO)
        );
        assert_eq!(
            accept_retry_delay(&Error::from(ErrorKind::Interrupted)),
            Some(Duration::ZERO)
        );
        let emfile = Error::from_raw_os_error(24);
        let delay = accept_retry_delay(&emfile).expect("EMFILE must not end the loop");
        assert!(
            delay >= Duration::from_millis(50),
            "EMFILE must not spin: {delay:?}"
        );
        // EBADF: the listener itself is gone.
        assert_eq!(accept_retry_delay(&Error::from_raw_os_error(9)), None);
        assert_eq!(
            accept_retry_delay(&Error::from(ErrorKind::InvalidInput)),
            None
        );
    }
}
