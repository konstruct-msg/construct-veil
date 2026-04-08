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
//!     -> [Rust proxy] -> TLS(SNI=ice.domain) -> obfs4 handshake -> relay:443
//!     -> Traefik TCP passthrough -> gateway TLS termination
//!     -> obfs4 listener -> gRPC -> main server
//! ```
//!
//! # Usage (from Swift via bridging header)
//!
//! ```c
//! // Plain obfs4 (legacy)
//! int32_t ice_proxy_start(const char *bridge_line, const char *relay_addr, uint16_t *port_out);
//! // TLS-wrapped obfs4 for DPI evasion
//! int32_t ice_proxy_start_tls(const char *bridge_line, const char *relay_addr,
//!                             const char *tls_server_name, uint16_t *port_out);
//! int32_t ice_proxy_stop(void);
//! int32_t ice_proxy_is_running(void);
//! uint16_t ice_proxy_port(void);
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
            .expect("ice: failed to create tokio runtime")
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
pub extern "C" fn ice_proxy_start(
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
pub extern "C" fn ice_proxy_stop() -> i32 {
    let mut stopped = false;

    if let Ok(mut guard) = PROXY.lock()
        && let Some(handle) = guard.take()
    {
        let _ = handle.shutdown_tx.send(());
        stopped = true;
    }

    // Also stop the TLS proxy if it is running — prevents stale handles that
    // would cause ice_proxy_start_tls to return -1 on the next call.
    #[cfg(feature = "tls")]
    if let Ok(mut guard) = PROXY_TLS.lock()
        && let Some(handle) = guard.take()
    {
        let _ = handle.shutdown_tx.send(());
        stopped = true;
    }

    if stopped { 0 } else { -1 }
}

#[unsafe(no_mangle)]
/// Returns 1 if the proxy is currently running (either plain-obfs4 or TLS-wrapped), 0 otherwise.
pub extern "C" fn ice_proxy_is_running() -> i32 {
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
    0
}

#[unsafe(no_mangle)]
/// Returns the local TCP port the proxy is listening on, or 0 if not running.
/// Prefers TLS-wrapped mode (DPI-resistant) over plain-obfs4.
/// When both are running simultaneously (happy-eyeballs dual-proxy mode),
/// returns the TLS port — use `ice_proxy_port_plain()` to get the plain port.
pub extern "C" fn ice_proxy_port() -> u16 {
    // TLS-wrapped mode (preferred — DPI-resistant, used on port 443)
    #[cfg(feature = "tls")]
    if let Ok(guard) = PROXY_TLS.lock()
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
pub extern "C" fn ice_proxy_port_tls() -> u16 {
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
pub extern "C" fn ice_proxy_port_plain() -> u16 {
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
                    eprintln!("ice: obfs4 handshake failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("ice: relay connect failed: {e}");
        }
    }
}

// ── TLS-wrapped proxy ─────────────────────────────────────────────────────────
//
// `ice_proxy_start_tls` — backward-compat: TLS with SNI, no cert pinning.
// `ice_proxy_start_tls_pinned` — full DPI evasion: fake/empty SNI + SPKI pin.
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
/// `relay_addr`       — relay address: `"ice.example.com:443"`.
/// `tls_server_name`  — TLS SNI hostname: `"ice.example.com"`.
/// `port_out`         — local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure. Stop with [`ice_proxy_stop`].
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ice_proxy_start_tls(
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
pub extern "C" fn ice_proxy_start_tls_pinned(
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
    let (connector, server_name) =
        match crate::tls_pinned::build_connector(&tls_server_name, &tls_spki_hex, &relay_addr) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ice-tls: connector build failed: {e}");
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
                eprintln!("ice-tls: tcp connect failed (attempt {attempt}): {e}");
                break; // TCP failure is unlikely to be transient — stop retrying
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
                eprintln!("ice-tls: TLS handshake failed (attempt {attempt}): {e}");
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
                eprintln!("ice-tls: obfs4 handshake failed (attempt {attempt}): {e}");
                if attempt == 0 {
                    // Brief pause before retry to avoid hammering the server
                    // during epoch-boundary MAC window (~1 second is sufficient).
                    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                }
            }
        }
    }
}
