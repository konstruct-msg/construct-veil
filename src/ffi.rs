//! C FFI — the surface the iOS and Android apps call.
//!
//! ```c
//! int32_t  veil_start(VeilStartRequest req, VeilStartResult *out);
//! size_t   veil_last_error(char *buf, size_t cap);
//! int32_t  veil_stop(void);
//! int32_t  veil_is_alive(void);
//! uint16_t veil_port(void);
//! // Host-terminated TLS (iOS NWConnection, Android Conscrypt): one ferry per
//! // accepted local connection.
//! int32_t  veil_front_ferry_fd(int32_t local_fd, int32_t relay_fd,
//!                              const uint8_t *exporter, size_t exporter_len,
//!                              const char *capability_v2_b64, const char *veil_sk_hex,
//!                              const char *ticket_b64);
//! ```
//!
//! The per-method `veil_proxy_*` functions (obfs4, TLS-wrapped obfs4, WebTunnel,
//! the one-shot host-terminated listener) were removed on 2026-10-22; no shipped
//! client called them. See `decisions/veil-front-only-retire-obfs4`.

use std::{
    ffi::{CStr, c_char},
    sync::{Mutex, OnceLock},
};

use tokio::runtime::Runtime;

fn get_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("veil: failed to create tokio runtime")
    })
}

/// Run an exported function's body; a panic becomes `fallback` instead of
/// unwinding into the host.
///
/// An `extern "C"` function that panics aborts the process (edition 2024), so a
/// panic anywhere under one of these calls — `block_on` from a tokio thread, a
/// bug in the coordinator, an `expect` — used to kill the iOS/Android app. Every
/// exported function now goes through here and returns its documented failure
/// value. Panics inside spawned tasks are unaffected: tokio already contains them
/// to the task.
fn ffi_guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(v) => v,
        Err(payload) => {
            let what = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_owned());
            eprintln!("veil: ffi call panicked: {what}");
            crate::veil::diag::record(format!("internal error (panic): {what}"));
            fallback
        }
    }
}

// ── VEIL Coordinator FFI ──────────────────────────────────────────────────────

static COORDINATOR: OnceLock<std::sync::Arc<crate::veil::VeilCoordinator>> = OnceLock::new();

/// Request struct for the coordinator-based `veil_start`.
///
/// Fields that are not needed for a particular method should be set to 0/NULL.
///
/// The layout is the ABI the apps compile against, so the fields of the retired
/// transports stay in place and are ignored: `bundle` (obfs4), `host_header` and
/// `wt_base_path` (WebTunnel).
#[repr(C)]
pub struct VeilStartRequest {
    /// Relay address: "host:port" (required).
    pub relay_addr: *const c_char,
    /// Ignored (was the obfs4 bridge line). May be NULL.
    pub bundle: *const c_char,
    /// TLS SNI hostname. Empty = no SNI.
    pub tls_sni: *const c_char,
    /// SPKI hex pin of the front (required; empty or malformed fails the start).
    pub spki_hex: *const c_char,
    /// Ignored (was the WebTunnel Host header). May be NULL.
    pub host_header: *const c_char,
    /// Ignored (was the WebTunnel base path). May be NULL.
    pub wt_base_path: *const c_char,
    /// Network fingerprint bytes (opaque, caller-computed). NULL = default.
    pub network_fingerprint: *const u8,
    /// Length of the network fingerprint buffer.
    pub network_fingerprint_len: usize,
    /// Bitmask of allowed methods (0 = all). Bit N = MethodId(N).
    pub allowed_methods: u32,
    /// Path to the SQLite scores database. NULL = in-memory (no persistence).
    pub scores_path: *const c_char,
    /// Base64-encoded veil-front ticket (65 bytes binary, AUTH v2). Empty / NULL
    /// with no AUTH v3 material below means the probe fails at ticket parsing.
    /// Superseded (but not replaced) by `veil_capability_v2_b64` below — ticket
    /// B1 (`decisions/veil-ticket-provisioning-system.md`); kept as the fallback
    /// when the v2 fields are NULL/empty, no flag-day.
    pub veil_front_ticket_b64: *const c_char,
    /// Base64-encoded key-bound `CapabilityV2` blob (ticket B1, AUTH v3). NULL /
    /// empty = not configured — falls back to `veil_front_ticket_b64` (AUTH v2).
    /// Must be paired with `veil_sk_hex` below.
    pub veil_capability_v2_b64: *const c_char,
    /// Hex-encoded 32-byte Ed25519 `veil_sk` seed — the device/relay's own
    /// access keypair, generated and stored locally by the caller (Keychain on
    /// iOS). Never derived from or sent to the relay. NULL / empty = AUTH v3 not
    /// configured.
    pub veil_sk_hex: *const c_char,
}

/// Result struct returned by `veil_start`.
#[repr(C)]
pub struct VeilStartResult {
    /// Local TCP port the proxy is listening on.
    pub port: u16,
    /// Which method won the probe race: always 3 (veil-front) today. 0–2 were
    /// obfs4, WebTunnel and the never-built MASQUE.
    pub method: u8,
    /// Wall-clock ms from start to first byte through the tunnel.
    pub latency_ms: u32,
}

/// Ferry ONE host-terminated veil-front connection over an already-accepted local
/// socket (review §3.1 variant A, persistent-listener form).
///
/// This owns no listener and no slot: the host (Swift) binds the stable local gRPC listener, accepts each
/// connection, dials a fresh native `NWConnection` per accept, and calls this once
/// per (local connection, relay session) pair. That makes the local port outlive
/// any single gRPC connection — the one-shot listener forced a fresh port + proxy
/// restart on every reconnect, which is the startup flap.
///
/// - `local_fd`: the accepted local gRPC TCP socket. We adopt and close it.
/// - `relay_fd`: one end of a socketpair carrying the **decrypted** relay duplex
///   for a fresh `NWConnection`; the host pumps the other end. We adopt and close it.
/// - `exporter_ptr`/`exporter_len`: the 32-byte TLS exporter for THAT NWConnection.
/// - `capability_v2_b64` + `veil_sk_hex`: AUTH v3 material; empty `veil_sk_hex`
///   falls back to AUTH v2 with `ticket_b64`.
///
/// Both fds are adopted unconditionally (closed by us on every path); the caller
/// must not touch them after the call. Spawns the ferry and returns immediately —
/// 0 if it was started, -1 on bad arguments. The ferry ends when either side
/// closes; the host observes that as EOF on its socketpair end.
#[cfg(unix)]
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref, clippy::too_many_arguments)]
pub extern "C" fn veil_front_ferry_fd(
    local_fd: i32,
    relay_fd: i32,
    exporter_ptr: *const u8,
    exporter_len: usize,
    capability_v2_b64: *const c_char,
    veil_sk_hex: *const c_char,
    ticket_b64: *const c_char,
) -> i32 {
    ffi_guard(-1, || {
        use construct_veil_protocol::EXPORTER_LEN;
        use std::os::fd::FromRawFd;

        // A negative fd is the host's own failure and is never adopted (undefined
        // behaviour). The valid one is
        // still ours to close.
        if local_fd < 0 || relay_fd < 0 {
            for fd in [local_fd, relay_fd] {
                if fd >= 0 {
                    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
                }
            }
            return -1;
        }
        // Adopt both fds first so every return path closes them (unconditional owner).
        let std_local = unsafe { std::net::TcpStream::from_raw_fd(local_fd) };
        let std_relay = unsafe { std::os::unix::net::UnixStream::from_raw_fd(relay_fd) };

        if exporter_ptr.is_null() || exporter_len != EXPORTER_LEN {
            return -1;
        }
        let mut exporter = [0u8; EXPORTER_LEN];
        unsafe { std::ptr::copy_nonoverlapping(exporter_ptr, exporter.as_mut_ptr(), EXPORTER_LEN) };

        let cstr = |p: *const c_char| -> String {
            unsafe {
                p.as_ref()
                    .and_then(|p| CStr::from_ptr(p).to_str().ok())
                    .unwrap_or("")
                    .to_owned()
            }
        };
        let auth_v3 = crate::veil::obfuscator::VeilFrontAuthV3 {
            capability_v2_b64: cstr(capability_v2_b64),
            veil_sk_hex: cstr(veil_sk_hex),
        };
        let ticket_b64 = cstr(ticket_b64);

        if std_local.set_nonblocking(true).is_err() || std_relay.set_nonblocking(true).is_err() {
            return -1;
        }

        let rt = get_runtime();
        let result: Result<(), ()> = rt.block_on(async move {
            // `from_std` registers with the reactor, so it must run inside the runtime.
            let local = tokio::net::TcpStream::from_std(std_local).map_err(|_| ())?;
            let relay = tokio::net::UnixStream::from_std(std_relay).map_err(|_| ())?;
            rt.spawn(async move {
                let _ = crate::veil::veil_front_adapter::run_veil_front_ferry_external(
                    local,
                    relay,
                    &exporter,
                    &ticket_b64,
                    &auth_v3,
                )
                .await;
                // `local` and `relay` drop here → both fds are closed.
            });
            Ok(())
        });

        match result {
            Ok(()) => 0,
            Err(()) => -1,
        }
    })
}

/// What `veil_start` reads out of a [`VeilStartRequest`].
struct StartArgs {
    relay_addr: String,
    tls_sni: String,
    spki_hex: String,
    veil_front_ticket_b64: String,
    veil_front_auth_v3: crate::veil::VeilFrontAuthV3,
    fingerprint: crate::veil::NetworkFingerprint,
    allowed_methods: crate::veil::MethodSet,
}

/// Read and validate the request; `Err` is the reason for `veil_last_error`.
///
/// # Safety
///
/// Every non-NULL pointer in `req` points to what its field documents: a
/// NUL-terminated string, or `network_fingerprint_len` readable bytes.
unsafe fn read_start_request(req: &VeilStartRequest) -> Result<StartArgs, String> {
    use crate::veil::{MethodSet, NetworkFingerprint, VeilFrontAuthV3};

    let relay_addr = unsafe {
        req.relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .map(|s| s.to_owned())
    };
    let relay_addr = relay_addr.ok_or("relay_addr is NULL or not UTF-8")?;

    let tls_sni = unsafe {
        req.tls_sni
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    // The pin is the relay's identity on every TLS method; a missing or malformed
    // one is a configuration error the host must see, not a silent "accept any
    // certificate" (which is what an empty pin meant until 2026-10-22).
    let spki_hex = unsafe {
        req.spki_hex
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .map(|s| s.to_owned())
    };
    let spki_hex = spki_hex.ok_or("spki_hex is NULL or not UTF-8")?;
    crate::tls_pinned::parse_spki_pin(&spki_hex)?;
    let veil_front_ticket_b64 = unsafe {
        req.veil_front_ticket_b64
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let veil_capability_v2_b64 = unsafe {
        req.veil_capability_v2_b64
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let veil_sk_hex = unsafe {
        req.veil_sk_hex
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let veil_front_auth_v3 = VeilFrontAuthV3 {
        capability_v2_b64: veil_capability_v2_b64,
        veil_sk_hex,
    };
    let fingerprint = if !req.network_fingerprint.is_null() && req.network_fingerprint_len > 0 {
        let bytes = unsafe {
            std::slice::from_raw_parts(req.network_fingerprint, req.network_fingerprint_len)
        };
        NetworkFingerprint::new(bytes.to_vec())
    } else {
        NetworkFingerprint::default()
    };
    let allowed_methods = MethodSet::from_bitmask(req.allowed_methods);

    Ok(StartArgs {
        relay_addr,
        tls_sni,
        spki_hex,
        veil_front_ticket_b64,
        veil_front_auth_v3,
        fingerprint,
        allowed_methods,
    })
}

/// Start an VEIL session using the FSM-based coordinator.
///
/// Returns 0 on success, -1 on failure; the reason is then in [`veil_last_error`].
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_start(req: VeilStartRequest, out: *mut VeilStartResult) -> i32 {
    ffi_guard(-1, || {
        use crate::veil::{VeilConfig, VeilCoordinator, scoring::PersistentScores};

        // One start at a time. Two overlapping calls used to race on the coordinator
        // (`COORDINATOR.set` → "already set (race)") and on its active session; the
        // second now waits for the first. A poisoned lock only means an earlier call
        // panicked (and returned -1 via `ffi_guard`); the guard protects nothing else.
        static START: Mutex<()> = Mutex::new(());
        let _one_at_a_time = START.lock().unwrap_or_else(|p| p.into_inner());

        // Fresh attempt: clear the diagnostic sink so the host reads this call's
        // failure (not a stale one) via `veil_last_error`.
        crate::veil::diag::clear();

        let args = match unsafe { read_start_request(&req) } {
            Ok(args) => args,
            Err(reason) => {
                crate::veil::diag::record(format!("veil_start: {reason}"));
                return -1;
            }
        };

        // Default config: parallel probing (top_k_probes=2, happy-eyeballs).
        let config = VeilConfig::default();

        let rt = get_runtime();
        let result: Result<VeilStartResult, String> = rt.block_on(async {
            // Stop any existing session first.
            if let Some(coord) = COORDINATOR.get() {
                let _ = coord.stop().await;
            }

            // Build or reuse the coordinator.
            let coord = if let Some(c) = COORDINATOR.get() {
                c.clone()
            } else {
                // Open scores database.
                let scores = if !req.scores_path.is_null() {
                    let path_str =
                        unsafe { CStr::from_ptr(req.scores_path).to_str().ok().unwrap_or("") };
                    if !path_str.is_empty() {
                        PersistentScores::open_default(path_str)
                            .await
                            .map_err(|e| format!("scores open failed: {e}"))?
                    } else {
                        return Err("scores_path empty".to_string());
                    }
                } else {
                    // In-memory SQLite for testing.
                    PersistentScores::open_default(":memory:")
                        .await
                        .map_err(|e| format!("scores open (memory) failed: {e}"))?
                };

                let mut coordinator = VeilCoordinator::new(config, scores);
                // veil-front is the only transport (decision veil-front-only-retire-obfs4).
                coordinator.register(Box::new(crate::veil::VeilFrontObfuscator::new()));

                let arc = std::sync::Arc::new(coordinator);
                COORDINATOR
                    .set(arc.clone())
                    .map_err(|_| "COORDINATOR already set (race)".to_string())?;
                arc
            };

            let session_result = coord
                .start_session_with_params(
                    args.relay_addr,
                    args.fingerprint,
                    args.allowed_methods,
                    args.tls_sni,
                    args.spki_hex,
                    args.veil_front_ticket_b64,
                    args.veil_front_auth_v3,
                )
                .await;

            match session_result {
                Ok(r) => Ok(VeilStartResult {
                    port: r.port,
                    method: r.method as u8,
                    latency_ms: r.latency_ms,
                }),
                Err(e) => Err(format!("start_session: {e}")),
            }
        });

        match result {
            Ok(r) => {
                if !out.is_null() {
                    unsafe { *out = r };
                }
                0
            }
            Err(reason) => {
                // Prefer the specific per-probe detail recorded during probing; only
                // fall back to the generic coordinator error if nothing more specific
                // was captured (e.g. a failure before any probe ran).
                if crate::veil::diag::last().is_empty() {
                    crate::veil::diag::record(format!("veil_start: {reason}"));
                }
                tracing::error!(target: "veil::ffi", "veil_start failed: {}", reason);
                // Also emit to stderr so iOS unified-log captures it even without tracing-subscriber.
                eprintln!("[veil_start] FAILED: {}", reason);
                -1
            }
        }
    })
}

/// Copy the most recent `veil_start` failure reason into `buf` (NUL-terminated,
/// truncated to `cap`). Returns the full byte length of the reason excluding the
/// NUL (so a return >= `cap` means it was truncated). Call right after
/// `veil_start` returns -1. The string names the failing method + stage, e.g.
/// `"veil-front: timeout after 7003ms (no first byte)"`.
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_last_error(buf: *mut c_char, cap: usize) -> usize {
    ffi_guard(0, || {
        let s = crate::veil::diag::last();
        let bytes = s.as_bytes();
        if buf.is_null() || cap == 0 {
            return bytes.len();
        }
        let n = bytes.len().min(cap - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
            *buf.add(n) = 0;
        }
        bytes.len()
    })
}

/// Stop the active VEIL session. Returns 0 if stopped, -1 if nothing was running.
#[unsafe(no_mangle)]
pub extern "C" fn veil_stop() -> i32 {
    ffi_guard(-1, || {
        let rt = get_runtime();
        rt.block_on(async {
            match COORDINATOR.get() {
                Some(coord) if coord.stop().await => 0,
                _ => -1,
            }
        })
    })
}

/// Returns 1 if an VEIL session is currently active, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn veil_is_alive() -> i32 {
    ffi_guard(0, || {
        let rt = get_runtime();
        rt.block_on(async {
            match COORDINATOR.get() {
                Some(coord) if coord.is_alive().await => 1,
                _ => 0,
            }
        })
    })
}

/// Returns the local port the VEIL proxy is listening on, or 0 if not running.
#[unsafe(no_mangle)]
pub extern "C" fn veil_port() -> u16 {
    ffi_guard(0, || {
        let rt = get_runtime();
        rt.block_on(async {
            match COORDINATOR.get() {
                Some(coord) => coord.port().await,
                None => 0,
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Mutation: call `body()` without `catch_unwind` — the panic escapes.
    #[test]
    fn a_panicking_body_returns_the_fallback() {
        assert_eq!(ffi_guard(-1, || -> i32 { panic!("boom") }), -1);
        assert_eq!(ffi_guard(0u16, || 7u16), 7);
    }

    /// A negative fd from the host is refused, not adopted, and the valid fd of a
    /// half-bad pair is still closed. This pins the contract; it is not a
    /// regression test: without the `< 0` checks the old code also returned -1
    /// here (the later `set_nonblocking` fails on -1), so the mutant survives. The
    /// checks exist because adopting -1 is undefined behaviour, which no
    /// assertion can observe.
    #[cfg(unix)]
    #[test]
    fn negative_fds_are_refused() {
        use std::os::fd::IntoRawFd;

        let exporter = [0u8; construct_veil_protocol::EXPORTER_LEN];
        let empty = CString::new("").unwrap();
        let (ours, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Before the call: macOS refuses setsockopt (EINVAL) once the peer is gone.
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let raw = ours.into_raw_fd();
        assert_eq!(
            veil_front_ferry_fd(
                -1,
                raw,
                exporter.as_ptr(),
                exporter.len(),
                empty.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
            ),
            -1
        );
        // Closed → the peer reads EOF.
        use std::io::Read;
        let mut buf = [0u8; 1];
        assert_eq!((&peer).read(&mut buf).unwrap(), 0, "fd {raw} was leaked");
    }

    /// The fields of the retired transports are ignored: NULL `bundle`,
    /// `host_header` and `wt_base_path` no longer fail the start before the pin
    /// is even looked at. Mutation: require `bundle` again (the start fails
    /// without naming the pin).
    #[test]
    fn a_request_without_legacy_fields_reaches_the_pin_check() {
        let relay = CString::new("127.0.0.1:9").unwrap();
        let bad_pin = CString::new("not-hex").unwrap();
        let req = VeilStartRequest {
            relay_addr: relay.as_ptr(),
            bundle: std::ptr::null(),
            tls_sni: std::ptr::null(),
            spki_hex: bad_pin.as_ptr(),
            host_header: std::ptr::null(),
            wt_base_path: std::ptr::null(),
            network_fingerprint: std::ptr::null(),
            network_fingerprint_len: 0,
            allowed_methods: 0,
            scores_path: std::ptr::null(),
            veil_front_ticket_b64: std::ptr::null(),
            veil_capability_v2_b64: std::ptr::null(),
            veil_sk_hex: std::ptr::null(),
        };
        let reason = unsafe { read_start_request(&req) }
            .err()
            .unwrap_or_default();
        assert!(reason.contains("SPKI"), "{reason:?}");
    }
}
