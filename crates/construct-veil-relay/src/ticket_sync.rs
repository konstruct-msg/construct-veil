//! Ticket sync — subscribe to the backend's active veil-front ticket set.
//!
//! The backend (construct-server `VeilService`) is the source of truth for tickets.
//! The relay opens a long-lived, relay-authenticated `SubscribeVeilTickets` stream
//! (relay-initiated, so it traverses NAT and reuses the relay→backend trust path),
//! receives a `SNAPSHOT` on connect and `UPSERT`/`REVOKE` deltas thereafter, and
//! applies them to the in-memory `TicketStore` live — no restart.
//!
//! Resilient by design: on any error or stream end it reconnects with capped
//! backoff, and the store keeps serving the last-known set (or the `tickets.json`
//! bootstrap set) in the meantime.

use std::sync::Arc;
use std::time::Duration;

use construct_veil_protocol::ticket::{AuthKey, Ticket, AUTH_KEY_LEN, TICKET_ID_LEN};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{info, warn};

use crate::tickets::TicketStore;

/// Generated VeilService client (from vendored proto, build.rs).
pub mod pb {
    tonic::include_proto!("shared.proto.services.v1");
}

use pb::veil_service_client::VeilServiceClient;
use pb::veil_ticket_update::Kind;
use pb::{SubscribeVeilTicketsRequest, VeilTicket as PbTicket, VeilTicketUpdate};

/// Configuration for the ticket-sync task.
#[derive(Clone)]
pub struct TicketSyncConfig {
    /// gRPC endpoint of the backend ticket authority, e.g. `https://ams.konstruct.cc:443`.
    pub control_endpoint: String,
    /// TLS SNI / cert hostname for the endpoint.
    pub control_sni: String,
    /// This relay's identifier (scope) the backend filters tickets by.
    pub relay_id: String,
    /// Bearer credential proving this is an authorised relay.
    pub relay_token: String,
}

/// Spawn the background sync task. Returns immediately; the task runs until the
/// process exits, reconnecting forever.
pub fn spawn(store: Arc<TicketStore>, cfg: TicketSyncConfig) {
    tokio::spawn(async move {
        let mut backoff: u64 = 1;
        loop {
            match run_once(&store, &cfg).await {
                Ok(()) => {
                    warn!("ticket sync stream ended cleanly — reconnecting");
                    backoff = 1;
                }
                Err(e) => {
                    warn!(error = %e, "ticket sync error — retrying in {backoff}s");
                }
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(60);
        }
    });
}

async fn run_once(
    store: &TicketStore,
    cfg: &TicketSyncConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls = ClientTlsConfig::new()
        .domain_name(cfg.control_sni.clone())
        .with_webpki_roots();
    let channel = Channel::from_shared(cfg.control_endpoint.clone())?
        .tls_config(tls)?
        .connect()
        .await?;

    let bearer: MetadataValue<_> = format!("Bearer {}", cfg.relay_token).parse()?;
    let mut client = VeilServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
        req.metadata_mut().insert("authorization", bearer.clone());
        Ok(req)
    });

    let req = SubscribeVeilTicketsRequest {
        relay_id: cfg.relay_id.clone(),
    };
    let mut stream = client.subscribe_veil_tickets(req).await?.into_inner();
    info!(
        endpoint = %cfg.control_endpoint,
        relay_id = %cfg.relay_id,
        "ticket sync connected"
    );

    while let Some(update) = stream.message().await? {
        apply(store, update).await;
    }
    Ok(())
}

async fn apply(store: &TicketStore, update: VeilTicketUpdate) {
    match Kind::try_from(update.kind).unwrap_or(Kind::Snapshot) {
        Kind::Snapshot => {
            let tickets: Vec<Ticket> = update.tickets.into_iter().filter_map(convert).collect();
            let n = store.replace_all(tickets).await;
            info!("ticket sync: SNAPSHOT applied — {n} active tickets");
        }
        Kind::Upsert => {
            let tickets: Vec<Ticket> = update.tickets.into_iter().filter_map(convert).collect();
            let n = store.upsert_many(tickets).await;
            info!("ticket sync: UPSERT applied — {n} tickets");
        }
        Kind::Revoke => {
            let n = store.revoke_many(&update.revoked_ids).await;
            info!("ticket sync: REVOKE applied — {n} tickets removed");
        }
    }
}

/// Convert a wire `VeilTicket` into the protocol `Ticket`. Drops malformed entries
/// (wrong-length id/key) rather than failing the whole batch.
fn convert(t: PbTicket) -> Option<Ticket> {
    let ticket_id: [u8; TICKET_ID_LEN] = t.ticket_id.as_slice().try_into().ok()?;
    let auth_key: [u8; AUTH_KEY_LEN] = t.auth_key.as_slice().try_into().ok()?;
    Some(Ticket {
        ticket_id,
        auth_key: AuthKey::new(auth_key),
        not_before: t.not_before.max(0) as u64,
        not_after: t.not_after.max(0) as u64,
        suite_id: t.suite_id as u8,
    })
}
