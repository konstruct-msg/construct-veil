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
mod tls;
mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gate::{GateResult, gate_with_exporter};
use tokio::net::TcpListener;
use tracing::{info, warn};

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

    // ── Issuer public key (capability verification) ─────────────────────────
    // The relay validates each presented capability's Ed25519 signature against
    // this key, offline. No ticket store, no sync, no secrets at rest.
    let issuer_pubkey: [u8; 32] = {
        let hex_key = args.issuer_pubkey.as_ref().ok_or(
            "--issuer-pubkey is required (home-server Ed25519 public key, 64 hex chars)",
        )?;
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| format!("invalid --issuer-pubkey hex: {e}"))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("--issuer-pubkey must be 32 bytes (64 hex chars), got {}", bytes.len()))?
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
    info!("║  issuer     {} (pubkey pfx)", hex::encode(&issuer_pubkey[..6]));
    info!(
        "║  scope      {}",
        if relay_scope.is_empty() { "(any)" } else { &relay_scope }
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
        let dialer = backend_dialer.clone();
        let backend = Arc::clone(&backend);
        let site = Arc::clone(&site);
        let scope = Arc::clone(&relay_scope);

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(tcp, peer, acceptor, &issuer_pubkey, &scope, &backend, dialer, &site).await
            {
                warn!(peer = %peer, error = %e, "connection handler error");
            }
        });
    }
}

/// Handle a single incoming connection.
async fn handle_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    issuer_pubkey: &[u8; 32],
    relay_scope: &str,
    backend: &str,
    backend_dialer: BackendDialer,
    site: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TLS handshake.
    let tls_stream = acceptor.accept(tcp).await?;
    info!(peer = %peer, "TLS handshake complete");

    // Run the constant-shape gate (offline capability validation).
    match gate_with_exporter(tls_stream, issuer_pubkey, relay_scope).await {
        Ok(GateResult::Tunnel { stream, leftover }) => {
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
            warn!(peer = %peer, error = %e, "gate error, treating as site traffic");
        }
    }

    Ok(())
}
