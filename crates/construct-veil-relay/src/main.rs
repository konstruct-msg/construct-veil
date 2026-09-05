//! construct-veil-relay — Veil-front honest-front HTTPS relay.
//!
//! Serves as a genuine HTTPS server that *also* tunnels for clients holding
//! a valid per-session ticket. Unauthenticated connections get the real site.
//!
//! # Usage
//!
//! ```bash
//! # Dev mode — self-signed cert, builtin site, no tickets
//! cargo run -p construct-veil-relay -- --dev
//!
//! # Production — ACME cert, real cover site, offline capability validation
//! cargo run -p construct-veil-relay --release -- \
//!   --cert /etc/letsencrypt/live/example.com/fullchain.pem \
//!   --key /etc/letsencrypt/live/example.com/privkey.pem \
//!   --issuer-pubkey <home-server-ed25519-public-key-hex> \
//!   --backend 127.0.0.1:50051 \
//!   --site 127.0.0.1:8080
//! ```

mod chain;
mod gate;
mod site;
mod tls;
mod tunnel;
mod upstream_tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use ed25519_dalek::SigningKey;
use gate::{GateResult, gate_with_exporter};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::chain::ChainConfig;
use crate::tls::RelayTls;

/// Veil-front relay CLI arguments.
#[derive(Parser, Debug)]
#[command(name = "construct-veil-relay")]
#[command(about = "Veil-front honest-front HTTPS relay")]
struct Args {
    /// Listen address.
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Dev mode — use self-signed cert and builtin cover site.
    #[arg(long, default_value_t = false)]
    dev: bool,

    /// Path to TLS certificate (PEM).
    #[arg(long)]
    cert: Option<String>,

    /// Path to TLS private key (PEM).
    #[arg(long)]
    key: Option<String>,

    /// Issuer (home-server) Ed25519 public key, hex (64 chars / 32 bytes). The relay
    /// validates each presented capability's signature against this key — offline, with
    /// no ticket store and no backend sync. Required outside --dev.
    #[arg(long)]
    issuer_pubkey: Option<String>,

    /// Relay scope id. A capability is accepted if its scope matches this (empty on
    /// either side = wildcard). Lets one issuer mint capabilities scoped to relay groups.
    #[arg(long, default_value = "")]
    relay_scope: String,

    /// Backend address (Construct gRPC). Accepts host:port or IP:port. Plaintext
    /// h2c by default; with --backend-tls the relay connects over TLS (ALPN h2).
    #[arg(long, default_value = "127.0.0.1:50051")]
    backend: String,

    /// Connect to the backend over TLS (ALPN h2) instead of plaintext h2c. Use
    /// this when the relay is remote and reaches the Construct backend via its
    /// public TLS endpoint (e.g. ams.konstruct.cc:443 → Traefik → envoy:8080).
    #[arg(long, default_value_t = false)]
    backend_tls: bool,

    /// SNI / certificate hostname for the TLS backend. Defaults to the host part
    /// of --backend. Only used with --backend-tls.
    #[arg(long)]
    backend_sni: Option<String>,

    /// Cover site address (local HTTP server with long-lived H2). Accepts host:port or IP:port.
    #[arg(long, default_value = "127.0.0.1:8080")]
    site: String,

    /// Ceiling on TLS handshakes in flight at once, across all peers. Bounds the
    /// CPU a handshake flood can consume; excess connections are dropped at
    /// accept time, the same shape an overloaded web server presents.
    #[arg(long, default_value_t = 512)]
    max_handshakes: usize,

    /// Ceiling on live connections from a single source IP. Stops one peer from
    /// consuming the whole `--max-handshakes` budget. 0 is clamped to 1.
    ///
    /// Sized well above a browser's ~6 connections per host so CGNAT'd mobile
    /// carriers (many real users behind one address) are not clipped, and well
    /// below the ~600 sockets a single peer held during the 2026-09-05 flood.
    #[arg(long, default_value_t = 64)]
    max_conns_per_ip: u32,

    /// Seconds a peer may take to finish the TLS handshake before the connection
    /// is dropped. Without this an abandoned handshake holds its slot forever.
    #[arg(long, default_value_t = 10)]
    handshake_timeout_secs: u64,

    /// Generate a new Ed25519 `veil_sk`/`veil_pk` keypair for chain relay mode
    /// and exit, printing the pubkey (hex) to stdout. The private seed is
    /// written to `--chain-veil-sk-file` (created with 0600 perms) and never
    /// printed. See decisions/veil-ticket-provisioning-system.md (B1).
    #[arg(long, default_value_t = false)]
    generate_relay_keypair: bool,

    /// Chain relay mode: upstream (`relay_clean`) address, host:port. When set
    /// (together with the other --chain-* flags), validated client tunnels are
    /// not forwarded to a local backend — they are ferried through this
    /// upstream relay instead. See decisions/veil-relay-topology.md §3.
    #[arg(long)]
    chain_upstream_addr: Option<String>,

    /// Chain relay mode: TLS SNI to present to the upstream relay.
    #[arg(long)]
    chain_upstream_sni: Option<String>,

    /// Chain relay mode: SPKI pin (hex) of the upstream relay's certificate.
    #[arg(long)]
    chain_upstream_spki: Option<String>,

    /// Chain relay mode: path to this relay's `ROLE_RELAY` capability
    /// (base64 `CapabilityV2` blob, issued by the upstream's home-server).
    #[arg(long)]
    chain_capability_file: Option<String>,

    /// Chain relay mode: path to this relay's `veil_sk` seed file (32 raw
    /// bytes or hex — see `--generate-relay-keypair`). Never logged.
    #[arg(long)]
    chain_veil_sk_file: Option<String>,
}

/// How the relay connects to the backend after authenticating a tunnel.
#[derive(Clone)]
enum BackendDialer {
    /// Plaintext h2c — a co-located backend (e.g. local envoy on the same host).
    Plain,
    /// TLS with ALPN h2 — a remote backend reached via its public TLS endpoint
    /// (e.g. ams.konstruct.cc:443, terminated by Traefik and routed to envoy).
    Tls {
        connector: tokio_rustls::TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    },
}

/// Admission control for the accept loop.
///
/// Two independent caps, both required. The global semaphore bounds the CPU that
/// concurrent handshakes (ClientHello parse + cert signing) can consume; the
/// per-IP cap stops a single peer from taking that whole budget for itself.
///
/// Why: the accept loop used to spawn an unbounded task per connection with no
/// handshake timeout. On 2026-09-05 two peers opened ~600 sockets each at
/// hundreds/sec; the accept backlog overflowed, backend dials started returning
/// ETIMEDOUT and the cover site went dark for everyone.
struct Admission {
    /// Permits for handshakes in flight. Released once TLS is established —
    /// a long-lived tunnel does not hold a handshake slot.
    handshakes: Arc<Semaphore>,
    /// Live connection count per source IP. Only ever holds entries for peers
    /// with at least one live connection.
    per_ip: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
}

impl Admission {
    fn new(max_handshakes: usize, max_per_ip: u32) -> Arc<Self> {
        Arc::new(Self {
            handshakes: Arc::new(Semaphore::new(max_handshakes.max(1))),
            per_ip: Mutex::new(HashMap::new()),
            // Clamped to >= 1 so `admit_ip` always increments past 0 and never
            // leaves a zero-valued entry behind (which would grow the map
            // without bound under a flood from many source IPs).
            max_per_ip: max_per_ip.max(1),
        })
    }

    /// Reserve a slot for `ip`, or `None` if that peer is already at its cap.
    fn admit_ip(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let mut map = lock(&self.per_ip);
        let count = map.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        drop(map);
        Some(IpGuard {
            admission: Arc::clone(self),
            ip,
        })
    }
}

/// Releases the per-IP slot when the connection task ends, by any path.
struct IpGuard {
    admission: Arc<Admission>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = lock(&self.admission.per_ip);
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Take a `Mutex` guard, recovering from poisoning.
///
/// The critical sections here are counter arithmetic with no `await` and no
/// panicking calls, so a poisoned lock carries no torn state — refusing to
/// serve because some unrelated task panicked would be the worse failure.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Connection outcomes, aggregated into one log line per interval.
///
/// This replaces a per-connection `warn!`. Under the flood that line was itself
/// an amplifier: hundreds of entries/sec into the container log, costing disk
/// I/O and CPU on a box already saturated. Individual failures are still
/// available at `debug`.
#[derive(Default)]
struct ConnStats {
    completed: AtomicU64,
    handshake_timeout: AtomicU64,
    handshake_failed: AtomicU64,
    handler_error: AtomicU64,
    shed_global: AtomicU64,
    shed_per_ip: AtomicU64,
}

impl ConnStats {
    /// Emit one summary line and reset the counters. Silent if nothing happened,
    /// so an idle relay stays quiet.
    fn flush(&self, window: Duration) {
        let completed = self.completed.swap(0, Ordering::Relaxed);
        let handshake_timeout = self.handshake_timeout.swap(0, Ordering::Relaxed);
        let handshake_failed = self.handshake_failed.swap(0, Ordering::Relaxed);
        let handler_error = self.handler_error.swap(0, Ordering::Relaxed);
        let shed_global = self.shed_global.swap(0, Ordering::Relaxed);
        let shed_per_ip = self.shed_per_ip.swap(0, Ordering::Relaxed);

        if completed
            | handshake_timeout
            | handshake_failed
            | handler_error
            | shed_global
            | shed_per_ip
            == 0
        {
            return;
        }

        info!(
            window_secs = window.as_secs(),
            completed,
            handshake_timeout,
            handshake_failed,
            handler_error,
            shed_global,
            shed_per_ip,
            "connection summary"
        );
    }
}

/// How often the aggregated connection summary is emitted.
const STATS_WINDOW: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls 0.23 requires explicit provider selection when multiple crypto
    // backends are compiled in (ring from rustls + aws-lc-rs from rcgen).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // ── Relay keypair generation (chain relay mode bootstrap) ──────────────
    // Operator-run, one-off: generates the keypair locally so the private
    // seed never leaves this box, prints only the pubkey, then exits.
    if args.generate_relay_keypair {
        let sk_path = args
            .chain_veil_sk_file
            .as_ref()
            .ok_or("--generate-relay-keypair requires --chain-veil-sk-file")?;
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        std::fs::write(sk_path, hex::encode(sk.to_bytes()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(sk_path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!("veil_pk: {}", hex::encode(sk.verifying_key().to_bytes()));
        println!(
            "veil_sk written to {sk_path} (0600) — send the pubkey above to the upstream's admin for capability issuance, the seed never leaves this box"
        );
        return Ok(());
    }

    // ── Chain relay mode config (optional) ──────────────────────────────────
    let chain_config = match (
        &args.chain_upstream_addr,
        &args.chain_upstream_sni,
        &args.chain_upstream_spki,
        &args.chain_capability_file,
        &args.chain_veil_sk_file,
    ) {
        (Some(addr), Some(sni), Some(spki), Some(cap_file), Some(sk_file)) => {
            let capability_v2_b64 = std::fs::read_to_string(cap_file)
                .map_err(|e| format!("reading --chain-capability-file: {e}"))?
                .trim()
                .to_string();
            let sk_hex = std::fs::read_to_string(sk_file)
                .map_err(|e| format!("reading --chain-veil-sk-file: {e}"))?
                .trim()
                .to_string();
            let sk_bytes = hex::decode(&sk_hex).map_err(|e| format!("veil_sk hex: {e}"))?;
            let seed: [u8; 32] = sk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "veil_sk must be 32 bytes".to_string())?;
            info!("Chain relay mode ENABLED — upstream {addr} (SNI {sni})");
            Some(Arc::new(ChainConfig {
                upstream_addr: addr.clone(),
                upstream_sni: sni.clone(),
                upstream_spki_hex: spki.clone(),
                capability_v2_b64,
                veil_sk: SigningKey::from_bytes(&seed),
            }))
        }
        (None, None, None, None, None) => None,
        _ => {
            return Err(
                "chain relay mode requires ALL of --chain-upstream-addr, --chain-upstream-sni, \
                 --chain-upstream-spki, --chain-capability-file, --chain-veil-sk-file"
                    .into(),
            );
        }
    };

    // ── TLS setup ──────────────────────────────────────────────────────────

    let relay_tls = if args.dev {
        info!("Running in DEV mode — self-signed TLS, builtin site");
        RelayTls::self_signed()?
    } else {
        let cert_path = args
            .cert
            .as_ref()
            .ok_or("Production mode requires --cert")?;
        let key_path = args.key.as_ref().ok_or("Production mode requires --key")?;
        RelayTls::from_pem_files(cert_path, key_path)?
    };

    // ── Issuer public key (capability verification) ─────────────────────────
    // The relay validates each presented capability's Ed25519 signature against
    // this key, offline. No ticket store, no sync, no secrets at rest.
    let issuer_pubkey: [u8; 32] = {
        let hex_key = args
            .issuer_pubkey
            .as_ref()
            .ok_or("--issuer-pubkey is required (home-server Ed25519 public key, 64 hex chars)")?;
        let bytes =
            hex::decode(hex_key.trim()).map_err(|e| format!("invalid --issuer-pubkey hex: {e}"))?;
        bytes.as_slice().try_into().map_err(|_| {
            format!(
                "--issuer-pubkey must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            )
        })?
    };
    let relay_scope: Arc<str> = Arc::from(args.relay_scope.as_str());

    // ── Backend dialer ─────────────────────────────────────────────────────
    // h2c by default (co-located backend); TLS+ALPN-h2 for a remote backend
    // reached over its public TLS endpoint (the front-relay-in-RU topology).
    let backend_dialer = if args.backend_tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let sni = args.backend_sni.clone().unwrap_or_else(|| {
            args.backend
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| args.backend.clone())
        });
        let server_name = rustls::pki_types::ServerName::try_from(sni.clone())
            .map_err(|e| format!("invalid backend SNI '{sni}': {e}"))?;
        info!("Backend TLS enabled — SNI={sni}, ALPN=h2");
        BackendDialer::Tls {
            connector: tokio_rustls::TlsConnector::from(Arc::new(client_config)),
            server_name,
        }
    } else {
        BackendDialer::Plain
    };

    // ── Banner ─────────────────────────────────────────────────────────────

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-veil-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen     {}", args.listen);
    info!(
        "║  backend    {} ({})",
        args.backend,
        if args.backend_tls { "TLS h2" } else { "h2c" }
    );
    info!("║  site       {} (cover app)", args.site);
    info!(
        "║  tls        {}",
        if args.dev {
            "self-signed (dev)"
        } else {
            "ACME"
        }
    );
    info!("║  spki       {}", relay_tls.spki_hex);
    info!(
        "║  issuer     {} (pubkey pfx)",
        hex::encode(&issuer_pubkey[..6])
    );
    info!(
        "║  scope      {}",
        if relay_scope.is_empty() {
            "(any)"
        } else {
            &relay_scope
        }
    );
    info!("╚══════════════════════════════════════════════════════════");

    // ── Bind ───────────────────────────────────────────────────────────────

    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|e| format!("Failed to bind {}: {}", args.listen, e))?;
    info!("Listening on {}", args.listen);

    // ── Accept loop ────────────────────────────────────────────────────────

    let acceptor = relay_tls.acceptor;
    // host:port strings, resolved per connection (not once at startup) so a
    // recreated backend / cover container with a new Docker IP is picked up
    // automatically — a startup-only resolve strands the relay on the old IP.
    let backend: Arc<str> = Arc::from(args.backend.as_str());
    let site: Arc<str> = Arc::from(args.site.as_str());

    let admission = Admission::new(args.max_handshakes, args.max_conns_per_ip);
    let stats = Arc::new(ConnStats::default());
    let handshake_timeout = Duration::from_secs(args.handshake_timeout_secs.max(1));
    info!(
        max_handshakes = args.max_handshakes,
        max_conns_per_ip = args.max_conns_per_ip,
        handshake_timeout_secs = handshake_timeout.as_secs(),
        "admission control active"
    );

    // Periodic aggregated summary — the only routine per-connection logging.
    {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STATS_WINDOW);
            ticker.tick().await; // the first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                stats.flush(STATS_WINDOW);
            }
        });
    }

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "TCP accept error");
                continue;
            }
        };

        // Shed before spending any work on the connection. Dropping `tcp` closes
        // it immediately — indistinguishable from an overloaded web server, and
        // notably not a silent blackhole.
        let Ok(handshake_permit) = Arc::clone(&admission.handshakes).try_acquire_owned() else {
            stats.shed_global.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(ip_guard) = admission.admit_ip(peer.ip()) else {
            stats.shed_per_ip.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        tcp.set_nodelay(true).ok();

        let acceptor = acceptor.clone();
        let dialer = backend_dialer.clone();
        let backend = Arc::clone(&backend);
        let site = Arc::clone(&site);
        let scope = Arc::clone(&relay_scope);
        let chain_config = chain_config.clone();
        let stats = Arc::clone(&stats);

        tokio::spawn(async move {
            // Held for the whole connection; the handshake permit is not.
            let _ip_guard = ip_guard;

            let tls_stream =
                match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
                        debug!(peer = %peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        stats.handshake_timeout.fetch_add(1, Ordering::Relaxed);
                        debug!(peer = %peer, "TLS handshake timed out");
                        return;
                    }
                };

            // TLS is up — free the slot so a long-lived tunnel does not occupy
            // handshake capacity for its entire lifetime.
            drop(handshake_permit);
            stats.completed.fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer, "TLS handshake complete");

            if let Err(e) = handle_connection(
                tls_stream,
                peer,
                &issuer_pubkey,
                &scope,
                &backend,
                dialer,
                &site,
                chain_config,
            )
            .await
            {
                stats.handler_error.fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer, error = %e, "connection handler error");
            }
        });
    }
}

/// Handle a single incoming connection.
#[allow(clippy::too_many_arguments)] // connection handler threads per-conn config + dialer
async fn handle_connection(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: SocketAddr,
    issuer_pubkey: &[u8; 32],
    relay_scope: &str,
    backend: &str,
    backend_dialer: BackendDialer,
    site: &str,
    chain_config: Option<Arc<ChainConfig>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The TLS handshake is done by the caller, under a timeout and a handshake
    // permit — neither of which should cover the connection's whole lifetime.

    // Run the constant-shape gate (offline capability validation).
    match gate_with_exporter(tls_stream, issuer_pubkey, relay_scope).await {
        Ok(GateResult::Tunnel { stream, leftover }) => {
            if let Some(cfg) = chain_config {
                // Chain relay mode — ferry through the upstream relay instead
                // of a local backend (decisions/veil-relay-topology.md §3).
                let upstream = chain::dial_upstream(&cfg).await?;
                chain::forward_chain(stream, leftover, upstream, peer).await?;
                return Ok(());
            }

            // Valid auth — connect to the backend (plain h2c or TLS+ALPN-h2) and tunnel.
            // `backend` is a host:port string, resolved here (per connection).
            let backend = tokio::net::TcpStream::connect(backend).await?;
            backend.set_nodelay(true)?;
            match &backend_dialer {
                BackendDialer::Plain => {
                    tunnel::forward_tunnel(stream, leftover, backend, peer).await?;
                }
                BackendDialer::Tls {
                    connector,
                    server_name,
                } => {
                    let tls_backend = connector.connect(server_name.clone(), backend).await?;
                    tunnel::forward_tunnel(stream, leftover, tls_backend, peer).await?;
                }
            }
        }
        Ok(GateResult::Site {
            stream,
            first_bytes,
        }) => {
            // Invalid auth — serve the cover site.
            if first_bytes.is_empty() {
                return Ok(());
            }

            // Forward raw bytes to the cover site backend.
            // The constant-shape requirement: we do NOT close/silence/delay differently.
            // The cover app's own error timing is the only timing on this branch.
            match site::forward_to_site(stream, first_bytes, site).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "site forwarding ended");
                }
            }
        }
        Err(e) => {
            debug!(peer = %peer, error = %e, "gate error, treating as site traffic");
        }
    }

    Ok(())
}
