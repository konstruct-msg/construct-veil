//! C FFI — local TCP proxy for iOS integration.
//!
//! # Architecture
//!
//! ```text
//! [Swift gRPC] -> 127.0.0.1:PORT (plain TCP)
//!     -> [Rust proxy] -> Obfs4Stream -> relay:443 (obfuscated)
//!     -> [relay VPS] -> main server
//! ```
//!
//! # Usage (from Swift via bridging header)
//!
//! ```c
//! int32_t ice_proxy_start(const char *bridge_line, const char *relay_addr, uint16_t *port_out);
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
/// Stop the running proxy. Returns 0 on success, -1 if not running.
pub extern "C" fn ice_proxy_stop() -> i32 {
    let mut guard = match PROXY.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    match guard.take() {
        Some(handle) => {
            let _ = handle.shutdown_tx.send(());
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
/// Returns 1 if the proxy is currently running, 0 otherwise.
pub extern "C" fn ice_proxy_is_running() -> i32 {
    match PROXY.lock() {
        Ok(guard) => i32::from(guard.is_some()),
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
/// Returns the local TCP port the proxy is listening on, or 0 if not running.
pub extern "C" fn ice_proxy_port() -> u16 {
    match PROXY.lock() {
        Ok(guard) => guard.as_ref().map(|h| h.port).unwrap_or(0),
        Err(_) => 0,
    }
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
    match Obfs4Stream::connect(&relay_addr, config).await {
        Ok(mut remote) => {
            let _ = copy_bidirectional(&mut local, &mut remote).await;
        }
        Err(e) => {
            eprintln!("ice: relay connect failed: {e}");
        }
    }
}
