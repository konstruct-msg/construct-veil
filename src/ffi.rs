//! C FFI — local TCP proxy for iOS integration.
//!
//! # Architecture
//!
//! ## Plain obfs4 mode (legacy)
//! ```text
//! [Swift gRPC] -> 127.0.0.1:PORT (plain TCP)
//!     -> [Rust proxy] -> Obfs4Stream -> relay:9443 (obfuscated)
//!     -> [relay VPS] -> main server
//! ```
//!
//! ## TLS-over-obfs4 mode (DPI evasion)
//! ```text
//! [Swift gRPC] -> 127.0.0.1:PORT (plain TCP)
//!     -> [Rust proxy] -> TLS(SNI=veil.domain) -> obfs4 handshake -> relay:443
//!     -> Traefik TCP passthrough -> gateway TLS termination
//!     -> obfs4 listener -> gRPC -> main server
//! ```
//!
//! # Usage (from Swift via bridging header)
//!
//! ```c
//! // Plain obfs4 (legacy)
//! int32_t veil_proxy_start(const char *bridge_line, const char *relay_addr, uint16_t *port_out);
//! // TLS-wrapped obfs4 for DPI evasion
//! int32_t veil_proxy_start_tls(const char *bridge_line, const char *relay_addr,
//!                             const char *tls_server_name, uint16_t *port_out);
//! int32_t veil_proxy_stop(void);
//! int32_t veil_proxy_is_running(void);
//! uint16_t veil_proxy_port(void);
//! ```

use std::{
    ffi::{CStr, c_char},
    sync::{Mutex, OnceLock},
};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::oneshot,
};

use crate::transport::{ClientConfig, Obfs4Stream};

fn get_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("veil: failed to create tokio runtime")
    })
}

struct ProxyHandle {
    port: u16,
    shutdown_tx: oneshot::Sender<()>,
}

static PROXY: Mutex<Option<ProxyHandle>> = Mutex::new(None);

#[unsafe(no_mangle)]
/// Start the obfs4 proxy.
///
/// `bridge_line` — bridge parameters string (e.g. `"cert=<base64> iat-mode=0"`).
/// `relay_addr`  — relay address in `"host:port"` format.
/// `port_out`    — output parameter: local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_proxy_start(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };

    let config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        // Check if already running without holding the lock across await
        {
            let guard = PROXY.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop(listener, relay_addr, config, shutdown_rx));
        let mut guard = PROXY.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[unsafe(no_mangle)]
/// Stop all running proxies (plain and TLS-wrapped). Returns 0 if at least one
/// was stopped, -1 if neither was running.
pub extern "C" fn veil_proxy_stop() -> i32 {
    let mut stopped = false;

    if let Ok(mut guard) = PROXY.lock()
        && let Some(handle) = guard.take()
    {
        let _ = handle.shutdown_tx.send(());
        stopped = true;
    }

    // Also stop the TLS proxy if it is running — prevents stale handles that
    // would cause veil_proxy_start_tls to return -1 on the next call.
    #[cfg(feature = "tls")]
    if let Ok(mut guard) = PROXY_TLS.lock()
        && let Some(handle) = guard.take()
    {
        let _ = handle.shutdown_tx.send(());
        stopped = true;
    }

    // Also stop the WebTunnel proxy — prevents stale handles that would cause
    // veil_proxy_start_webtunnel to return -1 when rotating to a different relay.
    #[cfg(feature = "webtunnel")]
    if let Ok(mut guard) = PROXY_WEBTUNNEL.lock()
        && let Some(handle) = guard.take()
    {
        let _ = handle.shutdown_tx.send(());
        stopped = true;
    }

    if stopped { 0 } else { -1 }
}

#[unsafe(no_mangle)]
/// Returns 1 if the proxy is currently running (plain-obfs4, TLS-wrapped, or WebTunnel), 0 otherwise.
pub extern "C" fn veil_proxy_is_running() -> i32 {
    // Plain-obfs4 mode
    if let Ok(guard) = PROXY.lock()
        && guard.is_some()
    {
        return 1;
    }
    // TLS-wrapped mode (used on iOS for DPI evasion)
    #[cfg(feature = "tls")]
    if let Ok(guard) = PROXY_TLS.lock()
        && guard.is_some()
    {
        return 1;
    }
    // WebTunnel mode (WebSocket-over-TLS, used for CDN fronting)
    #[cfg(feature = "webtunnel")]
    if let Ok(guard) = PROXY_WEBTUNNEL.lock()
        && guard.is_some()
    {
        return 1;
    }
    0
}

#[unsafe(no_mangle)]
/// Returns the local TCP port the proxy is listening on, or 0 if not running.
/// Prefers TLS-wrapped and WebTunnel modes (DPI-resistant) over plain-obfs4.
pub extern "C" fn veil_proxy_port() -> u16 {
    // TLS-wrapped mode (preferred — DPI-resistant, used on port 443)
    #[cfg(feature = "tls")]
    if let Ok(guard) = PROXY_TLS.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.port;
    }
    // WebTunnel mode (WebSocket-over-TLS CDN fronting)
    #[cfg(feature = "webtunnel")]
    if let Ok(guard) = PROXY_WEBTUNNEL.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.port;
    }
    // Plain-obfs4 mode (fallback relay, e.g. MSK relay on port 9443)
    if let Ok(guard) = PROXY.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.port;
    }
    0
}

#[unsafe(no_mangle)]
/// Returns the port of the TLS-wrapped proxy specifically, or 0 if not running.
/// Use this when both plain and TLS proxies are running simultaneously (dual-proxy
/// happy-eyeballs mode) to get each port independently.
#[cfg(feature = "tls")]
pub extern "C" fn veil_proxy_port_tls() -> u16 {
    if let Ok(guard) = PROXY_TLS.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.port;
    }
    0
}

#[unsafe(no_mangle)]
/// Returns the port of the plain-obfs4 proxy specifically, or 0 if not running.
/// In dual-proxy mode, this is the secondary relay (e.g. MSK TCP relay).
pub extern "C" fn veil_proxy_port_plain() -> u16 {
    if let Ok(guard) = PROXY.lock()
        && let Some(h) = guard.as_ref()
    {
        return h.port;
    }
    0
}

async fn proxy_loop(
    listener: TcpListener,
    relay_addr: String,
    config: ClientConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let addr = relay_addr.clone();
                        let cfg  = config.clone();
                        tokio::spawn(handle_connection(local, addr, cfg));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn handle_connection(mut local: TcpStream, relay_addr: String, config: ClientConfig) {
    match tokio::net::TcpStream::connect(&relay_addr).await {
        Ok(tcp) => {
            let _ = tcp.set_nodelay(true);
            match Obfs4Stream::client_handshake(tcp, config).await {
                Ok(mut remote) => {
                    let _ = copy_bidirectional(&mut local, &mut remote).await;
                }
                Err(e) => {
                    eprintln!("veil: obfs4 handshake failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("veil: relay connect failed: {e}");
        }
    }
}

// ── TLS-wrapped proxy ─────────────────────────────────────────────────────────
//
// `veil_proxy_start_tls` — backward-compat: TLS with SNI, no cert pinning.
// `veil_proxy_start_tls_pinned` — full DPI evasion: fake/empty SNI + SPKI pin.
//
// Both use rustls via `crate::tls_pinned::build_connector`.
//
// Supported SNI modes (set from Swift via Constants.swift):
//   sni = ""                         → no SNI extension (IP-based ServerName)
//   sni = "storage.yandexcloud.net"  → fake SNI, REALITY-style
//
// The `tls` Cargo feature must be enabled for these symbols to be compiled.

#[cfg(feature = "tls")]
static PROXY_TLS: Mutex<Option<ProxyHandle>> = Mutex::new(None);

#[cfg(feature = "tls")]
#[unsafe(no_mangle)]
/// Start the TLS-wrapped obfs4 proxy for DPI evasion.
///
/// Connections flow: local TCP → TLS to `relay_addr` (SNI=`tls_server_name`) → obfs4 → server.
///
/// `bridge_line`      — bridge parameters (e.g. `"cert=<base64> iat-mode=0"`).
/// `relay_addr`       — relay address: `"veil.example.com:443"`.
/// `tls_server_name`  — TLS SNI hostname: `"veil.example.com"`.
/// `port_out`         — local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure. Stop with [`veil_proxy_stop`].
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_proxy_start_tls(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    tls_server_name: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let tls_server_name = unsafe {
        match tls_server_name
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };

    let config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        {
            let guard = PROXY_TLS.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop_tls(
            listener,
            relay_addr,
            tls_server_name,
            String::new(), // no SPKI pin — backward-compat (CA chain not checked either,
            // but SNI is still sent so the server cert domain must match)
            config,
            shutdown_rx,
        ));
        let mut guard = PROXY_TLS.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[cfg(feature = "tls")]
#[unsafe(no_mangle)]
/// Start the TLS-wrapped obfs4 proxy with SPKI certificate pinning.
///
/// Connections flow: local TCP → TLS (SNI=`tls_sni`) → obfs4 → relay.
///
/// `bridge_line`  — bridge parameters (`"cert=<base64> iat-mode=<n>"`).
/// `relay_addr`   — relay IP:port (`"158.160.140.67:443"`).
/// `tls_sni`      — SNI for ClientHello. Empty string → no SNI (IP-based ServerName).
///                  Set to `"storage.yandexcloud.net"` for REALITY-style fake SNI.
/// `spki_hex`     — lowercase hex SHA-256 of DER SubjectPublicKeyInfo. Empty → no pinning.
/// `port_out`     — local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_proxy_start_tls_pinned(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    tls_sni: *const c_char,
    spki_hex: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let tls_sni = unsafe {
        tls_sni
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let spki_hex = unsafe {
        spki_hex
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    let config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        {
            let guard = PROXY_TLS.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop_tls(
            listener,
            relay_addr,
            tls_sni,
            spki_hex,
            config,
            shutdown_rx,
        ));
        let mut guard = PROXY_TLS.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[cfg(feature = "tls")]
async fn proxy_loop_tls(
    listener: TcpListener,
    relay_addr: String,
    tls_server_name: String,
    tls_spki_hex: String,
    config: ClientConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let addr = relay_addr.clone();
                        let sni  = tls_server_name.clone();
                        let spki = tls_spki_hex.clone();
                        let cfg  = config.clone();
                        tokio::spawn(handle_connection_tls(local, addr, sni, spki, cfg));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(feature = "tls")]
async fn handle_connection_tls(
    mut local: TcpStream,
    relay_addr: String,
    tls_server_name: String,
    tls_spki_hex: String,
    config: ClientConfig,
) {
    use tokio::net::TcpStream as TokioTcp;

    // Build rustls connector with SPKI pinning + SNI control.
    // sni = ""   → IP-based ServerName, no SNI extension in ClientHello (Path 1).
    // sni = name → sends as SNI; cert verified by SPKI pin, not CA chain (Path 2).
    let (connector, server_name) = match crate::tls_pinned::build_connector(
        &tls_server_name,
        &tls_spki_hex,
        &relay_addr,
        config.tls_profile,
        None,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("veil-tls: connector build failed: {e}");
            return;
        }
    };

    // Attempt the obfs4-over-TLS connection up to 2 times before giving up.
    // The server may momentarily reject a handshake (e.g. during restart or
    // due to clock-skew on epoch boundary); a single retry avoids false
    // "always relay" fallbacks on iOS.
    for attempt in 0u8..2 {
        // 1. TCP connect to relay (IP string — no DNS lookup)
        let tcp = match TokioTcp::connect(&relay_addr).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("veil-tls: tcp connect failed (attempt {attempt}): {e}");
                // ECONNREFUSED is often transient (relay restart / rate-limit window).
                // Retry once with a brief pause; any other error is persistent.
                if attempt == 0 && e.kind() == std::io::ErrorKind::ConnectionRefused {
                    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                    continue;
                }
                break;
            }
        };

        // Disable Nagle's algorithm so the obfs4 client request is sent
        // immediately without waiting for a full MSS — critical on iOS cellular
        // where Nagle can add ~200 ms of artificial latency.
        let _ = tcp.set_nodelay(true);

        // 2. TLS handshake via rustls.
        //    With SPKI pinning: ignores CA chain, verifies public key hash.
        //    With fake SNI: sends the configured domain in ClientHello but
        //    cert validation is still by pin — no domain match required.
        let tls_stream = match connector.connect(server_name.clone(), tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("veil-tls: TLS handshake failed (attempt {attempt}): {e}");
                break; // TLS failure is not transient
            }
        };

        // 3. obfs4 handshake over the TLS stream, then bidirectional proxy
        match Obfs4Stream::client_handshake_stream(tls_stream, config.clone()).await {
            Ok(mut remote) => {
                let _ = copy_bidirectional(&mut local, &mut remote).await;
                return; // Success — done
            }
            Err(e) => {
                eprintln!("veil-tls: obfs4 handshake failed (attempt {attempt}): {e}");
                if attempt == 0 {
                    // Brief pause before retry to avoid hammering the server
                    // during epoch-boundary MAC window (~1 second is sufficient).
                    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                }
            }
        }
    }
}

// ── uTLS profiled proxy ───────────────────────────────────────────────────────

/// Start a TLS-over-obfs4 proxy with a specific browser TLS fingerprint profile.
///
/// Identical to `veil_proxy_start_tls_pinned` but accepts a `tls_profile` string
/// that controls cipher suite ordering and ALPN:
///
/// - `"chrome131"` or `"chrome"` — Chrome 131 ordering
/// - `"firefox128"` or `"firefox"` — Firefox 128 ordering
/// - `""` or `"rustls"` — rustls defaults (same as `veil_proxy_start_tls_pinned`)
///
/// # Safety
/// All pointer parameters must be valid null-terminated C strings or null.
#[cfg(all(feature = "ffi", feature = "tls"))]
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_proxy_start_tls_profiled(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    tls_sni: *const c_char,
    spki_hex: *const c_char,
    tls_profile: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let tls_sni = unsafe {
        tls_sni
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let spki_hex = unsafe {
        spki_hex
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let profile_str = unsafe {
        tls_profile
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    let mut config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    config.tls_profile = crate::tls_fingerprint::TlsProfile::from_name(&profile_str);

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        {
            let guard = PROXY_TLS.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop_tls(
            listener,
            relay_addr,
            tls_sni,
            spki_hex,
            config,
            shutdown_rx,
        ));
        let mut guard = PROXY_TLS.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

// ── WebTunnel proxy ───────────────────────────────────────────────────────────

#[cfg(feature = "webtunnel")]
static PROXY_WEBTUNNEL: Mutex<Option<ProxyHandle>> = Mutex::new(None);

#[cfg(feature = "webtunnel")]
#[unsafe(no_mangle)]
/// Start the WebTunnel (WebSocket-over-TLS) proxy for DPI evasion.
///
/// Traffic flow: local TCP → TLS (SNI=`tls_sni`) → WebSocket → relay.
///
/// `relay_addr`   — relay IP:port (`"158.160.140.67:443"`).
/// `tls_sni`      — SNI for TLS ClientHello; set to CDN domain for fronting.
///                  Empty → IP-based ServerName (no SNI extension).
/// `spki_hex`     — lowercase hex SHA-256 of DER SubjectPublicKeyInfo. Empty → no pinning.
/// `host_header`  — HTTP `Host` header for WebSocket upgrade. Can differ from `tls_sni`.
/// `bridge_cert`  — base64-encoded obfs4 bridge cert from relay manifest (used for token derivation).
/// `wt_base_path` — WebSocket resource base path (e.g. `"/api/stream"`), without the token.
/// `port_out`     — local TCP port the proxy listens on.
///
/// The auth token is computed per-connection from `bridge_cert` and the current time period.
/// Returns 0 on success, -1 on failure. Stop with `veil_proxy_stop`.
///
/// TODO(refactor): 7 raw C pointers is fragile — group into `WebTunnelConfig` struct passed by
/// pointer, mirroring the pattern used by the bridging header on the Swift side. This also makes
/// adding future fields (e.g. obfs4 iat-mode, circuit isolation) a non-breaking change.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_proxy_start_webtunnel(
    relay_addr: *const c_char,
    tls_sni: *const c_char,
    spki_hex: *const c_char,
    host_header: *const c_char,
    bridge_cert: *const c_char,
    wt_base_path: *const c_char,
    port_out: *mut u16,
) -> i32 {
    fn parse_req(ptr: *const c_char) -> Option<String> {
        unsafe { ptr.as_ref() }
            .and_then(|p| unsafe { CStr::from_ptr(p) }.to_str().ok())
            .map(|s| s.to_owned())
    }
    fn parse_opt(ptr: *const c_char) -> String {
        unsafe { ptr.as_ref() }
            .and_then(|p| unsafe { CStr::from_ptr(p) }.to_str().ok())
            .unwrap_or("")
            .to_owned()
    }

    let relay_addr = match parse_req(relay_addr) {
        Some(s) => s,
        None => return -1,
    };
    let tls_sni = parse_opt(tls_sni);
    let spki_hex = parse_opt(spki_hex);
    let host = parse_opt(host_header);
    let bridge_cert = parse_opt(bridge_cert);
    let wt_base_path = {
        let p = parse_opt(wt_base_path);
        if p.is_empty() { "/".to_owned() } else { p }
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        {
            let guard = PROXY_WEBTUNNEL.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(());
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop_webtunnel(
            listener,
            relay_addr,
            tls_sni,
            spki_hex,
            host,
            bridge_cert,
            wt_base_path,
            shutdown_rx,
        ));
        let mut guard = PROXY_WEBTUNNEL.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[cfg(feature = "webtunnel")]
#[unsafe(no_mangle)]
/// Returns the local port the WebTunnel proxy is listening on (0 = not running).
pub extern "C" fn veil_proxy_port_webtunnel() -> u16 {
    PROXY_WEBTUNNEL
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|h| h.port))
        .unwrap_or(0)
}

#[cfg(feature = "webtunnel")]
#[allow(clippy::too_many_arguments)]
async fn proxy_loop_webtunnel(
    listener: TcpListener,
    relay_addr: String,
    tls_sni: String,
    tls_spki_hex: String,
    host_header: String,
    bridge_cert: String,
    wt_base_path: String,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let (addr, sni, spki, host, bc, bp) = (
                            relay_addr.clone(), tls_sni.clone(), tls_spki_hex.clone(),
                            host_header.clone(), bridge_cert.clone(), wt_base_path.clone(),
                        );
                        tokio::spawn(handle_connection_webtunnel(local, addr, sni, spki, host, bc, bp));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(feature = "webtunnel")]
async fn handle_connection_webtunnel(
    mut local: TcpStream,
    relay_addr: String,
    tls_sni: String,
    tls_spki_hex: String,
    host_header: String,
    bridge_cert: String,
    wt_base_path: String,
) {
    use crate::transport::webtunnel::WebTunnelStream;
    use tokio::net::TcpStream as TokioTcp;

    // Compute auth token for the current time period.
    // Token = SHA-256(bridge_cert || "webtunnel-v1" || period_be)[:8] as lowercase hex.
    // Period = unix_seconds / 300 (5-minute windows).
    let auth_token = {
        use sha2::{Digest, Sha256};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let period = now / 300;
        let mut hasher = Sha256::new();
        hasher.update(bridge_cert.as_bytes());
        hasher.update(b"webtunnel-v1");
        hasher.update(period.to_be_bytes());
        let hash = hasher.finalize();
        hash[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    };
    let path = format!("{}/{}", wt_base_path.trim_end_matches('/'), auth_token);

    let (connector, server_name) = match crate::tls_pinned::build_connector(
        &tls_sni,
        &tls_spki_hex,
        &relay_addr,
        crate::tls_fingerprint::TlsProfile::Chrome131,
        // RFC 6455 WebSocket upgrade requires HTTP/1.1.  Advertising h2 in ALPN
        // while then sending an HTTP/1.1 Upgrade request is inconsistent and can
        // be detected by DPI (e.g. ТСПУ).  Real Chrome uses http/1.1-only ALPN
        // for wss:// connections.
        Some(vec![b"http/1.1".to_vec()]),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("webtunnel: connector build failed: {e}");
            return;
        }
    };

    for attempt in 0u8..2 {
        let tcp = match TokioTcp::connect(&relay_addr).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("webtunnel: tcp connect failed (attempt {attempt}): {e}");
                if attempt == 0 && e.kind() == std::io::ErrorKind::ConnectionRefused {
                    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                    continue;
                }
                break;
            }
        };
        let _ = tcp.set_nodelay(true);

        let tls_stream = match connector.connect(server_name.clone(), tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("webtunnel: TLS failed (attempt {attempt}): {e}");
                break;
            }
        };

        match WebTunnelStream::connect(tls_stream, &host_header, &path).await {
            Ok(mut ws) => {
                let _ = copy_bidirectional(&mut local, &mut ws).await;
                return;
            }
            Err(e) => {
                eprintln!("webtunnel: WS upgrade failed (attempt {attempt}): {e}");
                if attempt == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                }
            }
        }
    }
}

// ── VEIL Coordinator FFI (Phase 1) ───────────────────────────────────────────
//
// New FFI surface using the FSM-based coordinator.
// Replaces the legacy `veil_proxy_start*` functions in Phase 3.
//
// ```c
// int32_t veil_start(VeilStartRequest req, VeilStartResult *out);
// void    veil_stop(void);
// bool    veil_is_alive(void);
// uint16_t veil_port(void);
// ```

#[cfg(feature = "coordinator")]
static COORDINATOR: OnceLock<std::sync::Arc<crate::veil::VeilCoordinator>> = OnceLock::new();

/// Request struct for the coordinator-based `veil_start`.
///
/// Fields that are not needed for a particular method should be set to 0/NULL.
#[cfg(feature = "coordinator")]
#[repr(C)]
pub struct VeilStartRequest {
    /// Relay address: "host:port" (required).
    pub relay_addr: *const c_char,
    /// Bridge line: "cert=<base64> iat-mode=<n>" (required).
    pub bundle: *const c_char,
    /// TLS SNI hostname. Empty = no SNI.
    pub tls_sni: *const c_char,
    /// SPKI hex pin. Empty = no pinning.
    pub spki_hex: *const c_char,
    /// WebTunnel: HTTP Host header.
    pub host_header: *const c_char,
    /// WebTunnel: WebSocket base path (e.g. "/api/stream").
    pub wt_base_path: *const c_char,
    /// Network fingerprint bytes (opaque, caller-computed). NULL = default.
    pub network_fingerprint: *const u8,
    /// Length of the network fingerprint buffer.
    pub network_fingerprint_len: usize,
    /// Bitmask of allowed methods (0 = all). Bit N = MethodId(N).
    pub allowed_methods: u32,
    /// Path to the SQLite scores database. NULL = in-memory (no persistence).
    pub scores_path: *const c_char,
    /// Base64-encoded veil-front ticket (65 bytes binary). Empty / NULL means
    /// veil-front is excluded from the race — its probe will fail at ticket
    /// parsing and the FSM moves on to the other methods. Must be set by
    /// clients that ship veil-front; obfs4 / WebTunnel callers can leave it
    /// NULL. Added in WIRE_VER 3 of the FFI — rebuild Swift/Kotlin bindings.
    pub veil_front_ticket_b64: *const c_char,
}

/// Result struct returned by `veil_start`.
#[cfg(feature = "coordinator")]
#[repr(C)]
pub struct VeilStartResult {
    /// Local TCP port the proxy is listening on.
    pub port: u16,
    /// Which method won the probe race: 0=obfs4, 1=webtunnel, 2=masque, 3=veil-front.
    pub method: u8,
    /// Wall-clock ms from start to first byte through the tunnel.
    pub latency_ms: u32,
}

/// Start an VEIL session using the FSM-based coordinator.
///
/// Sequential probing (top_k_probes=1) for Phase 1 backward compatibility.
/// Returns 0 on success, -1 on failure.
#[cfg(feature = "coordinator")]
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_start(req: VeilStartRequest, out: *mut VeilStartResult) -> i32 {
    use crate::veil::{
        MethodSet, NetworkFingerprint, VeilConfig, VeilCoordinator, scoring::PersistentScores,
    };

    // Fresh attempt: clear the diagnostic sink so the host reads this call's
    // failure (not a stale one) via `veil_last_error`.
    crate::veil::diag::clear();

    let relay_addr = unsafe {
        req.relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .map(|s| s.to_owned())
    };
    let bundle = unsafe {
        req.bundle
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .map(|s| s.to_owned())
    };
    let (relay_addr, bundle) = match (relay_addr, bundle) {
        (Some(r), Some(b)) => (r, b),
        _ => return -1,
    };

    let tls_sni = unsafe {
        req.tls_sni
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let spki_hex = unsafe {
        req.spki_hex
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let host_header = unsafe {
        req.host_header
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let wt_base_path = unsafe {
        req.wt_base_path
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let veil_front_ticket_b64 = unsafe {
        req.veil_front_ticket_b64
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
            .unwrap_or("")
            .to_owned()
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
            // veil-front-only (2026-06-12): obfs4 and WebTunnel are fundamentally
            // DPI-cut in the RU target network and are superseded by veil-front
            // (honest-front HTTPS). On `utls` builds (iOS/mac/android) we probe
            // veil-front exclusively — probing the dead methods only wasted a
            // per-start timeout. Non-`utls` builds keep the legacy transports so
            // no other consumer breaks. See decision: veil-front-only-retire-obfs4.
            #[cfg(feature = "utls")]
            coordinator.register(Box::new(crate::veil::VeilFrontObfuscator::new()));
            #[cfg(not(feature = "utls"))]
            {
                use crate::veil::{Obfs4Obfuscator, WebTunnelObfuscator};
                coordinator.register(Box::new(Obfs4Obfuscator::new()));
                coordinator.register(Box::new(WebTunnelObfuscator::new()));
            }

            let arc = std::sync::Arc::new(coordinator);
            COORDINATOR
                .set(arc.clone())
                .map_err(|_| "COORDINATOR already set (race)".to_string())?;
            arc
        };

        // Update probe requests with TLS/WebTunnel params.
        // For Phase 1, we pass the TLS params through a thread-local or re-create
        // the obfuscators with the params. For simplicity, we modify the coordinator
        // to accept the params in start_session.
        //
        // Actually, for Phase 1, the coordinator's execute_probe creates ProbeRequest
        // with empty params. We need to pass the params through.
        //
        // Simplest fix: the coordinator stores the params from the last start_session call.
        // Let me add an extra parameter set to start_session.

        let session_result = coord
            .start_session_with_params(
                relay_addr,
                bundle,
                fingerprint,
                allowed_methods,
                tls_sni,
                spki_hex,
                host_header,
                wt_base_path,
                veil_front_ticket_b64,
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
}

/// Copy the most recent `veil_start` failure reason into `buf` (NUL-terminated,
/// truncated to `cap`). Returns the full byte length of the reason excluding the
/// NUL (so a return >= `cap` means it was truncated). Call right after
/// `veil_start` returns -1. The string names the failing method + stage, e.g.
/// `"veil-front: timeout after 7003ms (no first byte)"`.
#[cfg(feature = "coordinator")]
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn veil_last_error(buf: *mut c_char, cap: usize) -> usize {
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
}

/// Stop the active VEIL session. Returns 0 if stopped, -1 if nothing was running.
#[cfg(feature = "coordinator")]
#[unsafe(no_mangle)]
pub extern "C" fn veil_stop() -> i32 {
    let rt = get_runtime();
    rt.block_on(async {
        if let Some(coord) = COORDINATOR.get()
            && coord.stop().await
        {
            return 0;
        }
        // Also try the legacy stop.
        veil_proxy_stop()
    })
}

/// Returns 1 if an VEIL session is currently active, 0 otherwise.
#[cfg(feature = "coordinator")]
#[unsafe(no_mangle)]
pub extern "C" fn veil_is_alive() -> i32 {
    let rt = get_runtime();
    rt.block_on(async {
        if let Some(coord) = COORDINATOR.get()
            && coord.is_alive().await
        {
            return 1;
        }
        veil_proxy_is_running()
    })
}

/// Returns the local port the VEIL proxy is listening on, or 0 if not running.
#[cfg(feature = "coordinator")]
#[unsafe(no_mangle)]
pub extern "C" fn veil_port() -> u16 {
    let rt = get_runtime();
    rt.block_on(async {
        if let Some(coord) = COORDINATOR.get() {
            let p = coord.port().await;
            if p != 0 {
                return p;
            }
        }
        veil_proxy_port()
    })
}
