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
//! # Production — ACME cert, real cover site, ticket store
//! cargo run -p construct-veil-relay --release -- \
//!   --cert /etc/letsencrypt/live/example.com/fullchain.pem \
//!   --key /etc/letsencrypt/live/example.com/privkey.pem \
//!   --tickets /etc/veil-front/tickets.json \
//!   --backend 127.0.0.1:50051 \
//!   --site 127.0.0.1:8080
//! ```

mod gate;
mod site;
mod tickets;
mod tls;
mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gate::{GateResult, gate_with_exporter};
use tokio::net::{TcpListener, lookup_host};
use tracing::{info, warn};

use crate::tickets::TicketStore;
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

    /// Path to tickets JSON file.
    #[arg(long)]
    tickets: Option<String>,

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

    // ── Ticket store ───────────────────────────────────────────────────────

    let ticket_store = TicketStore::new();

    if let Some(tickets_path) = &args.tickets {
        let count = ticket_store
            .load_from_json(tickets_path)
            .await
            .map_err(|e| format!("Failed to load tickets from {tickets_path}: {e}"))?;
        info!("Loaded {count} tickets from {tickets_path}");
    } else if !args.dev {
        warn!("No tickets loaded — all connections will route to site");
    }

    let ticket_store = Arc::new(ticket_store);

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
    info!("║  tickets    {}", ticket_store.len().await);
    info!("╚══════════════════════════════════════════════════════════");

    // ── Bind ───────────────────────────────────────────────────────────────

    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|e| format!("Failed to bind {}: {}", args.listen, e))?;
    info!("Listening on {}", args.listen);

    // ── Accept loop ────────────────────────────────────────────────────────

    let acceptor = relay_tls.acceptor;
    let backend_addr = resolve(&args.backend).await?;
    let site_addr = resolve(&args.site).await?;
    info!("Resolved backend => {backend_addr}, site => {site_addr}");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "TCP accept error");
                continue;
            }
        };

        tcp.set_nodelay(true).ok();

        let acceptor = acceptor.clone();
        let store = Arc::clone(&ticket_store);
        let dialer = backend_dialer.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(tcp, peer, acceptor, store, backend_addr, dialer, site_addr).await
            {
                warn!(peer = %peer, error = %e, "connection handler error");
            }
        });
    }
}

/// Resolve a host:port string to a SocketAddr.
async fn resolve(addr: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let resolved = lookup_host(addr)
        .await
        .map_err(|e| format!("Failed to resolve '{addr}': {e}"))?
        .next()
        .ok_or_else(|| format!("No addresses found for '{addr}'"))?;
    Ok(resolved)
}

/// Handle a single incoming connection.
async fn handle_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    store: Arc<TicketStore>,
    backend_addr: SocketAddr,
    backend_dialer: BackendDialer,
    site_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TLS handshake.
    let tls_stream = acceptor.accept(tcp).await?;
    info!(peer = %peer, "TLS handshake complete");

    // Run the constant-shape gate.
    match gate_with_exporter(tls_stream, &store).await {
        Ok(GateResult::Tunnel { stream, leftover }) => {
            // Valid auth — connect to the backend (plain h2c or TLS+ALPN-h2) and tunnel.
            let backend = tokio::net::TcpStream::connect(backend_addr).await?;
            backend.set_nodelay(true)?;
            match &backend_dialer {
                BackendDialer::Plain => {
                    tunnel::forward_tunnel(stream, leftover, backend).await?;
                }
                BackendDialer::Tls {
                    connector,
                    server_name,
                } => {
                    let tls_backend = connector.connect(server_name.clone(), backend).await?;
                    tunnel::forward_tunnel(stream, leftover, tls_backend).await?;
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
            match site::forward_to_site(stream, first_bytes, site_addr).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "site forwarding ended");
                }
            }
        }
        Err(e) => {
            warn!(peer = %peer, error = %e, "gate error, treating as site traffic");
        }
    }

    Ok(())
}
