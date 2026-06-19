//! Chain relay mode — `relay_domestic` acting as a veil-front *client* to an
//! upstream `relay_clean`, per `decisions/veil-relay-topology.md` §3:
//!
//! ```text
//! client (censored zone) → relay_domestic → relay_clean → backend
//! ```
//!
//! `relay_domestic` runs unchanged as a server on its client-facing listener
//! (gate.rs, tunnel.rs). When chain mode is configured, a validated
//! `ROLE_USER` tunnel decision is **not** forwarded to a local backend —
//! instead this module dials `relay_clean` as a client (its own `ROLE_RELAY`
//! capability), authenticates, and ferries DATA payloads between the two
//! independently-framed legs.
//!
//! **Hop isolation (load-bearing):** AUTH and CHAFF frames never cross a hop.
//! Each leg decodes its own frames, drops CHAFF, and re-frames DATA payloads
//! with its own codec instance before forwarding — so a captured AUTH frame
//! or a relay's own chaff pattern from one hop is never replayed onto the
//! other, and each hop's framing is independently observable shape only to
//! itself.
//!
//! **Known gap (documented, not silently dropped):** the client→upstream
//! direction does not inject synthetic CHAFF on idle (unlike upstream→client,
//! which mirrors `tunnel.rs`'s symmetric idle-chaff injection). Adding it is
//! tracked as the same M6 chaff-budget re-measurement flagged in the topology
//! doc's open questions — chaff budget for a relay-to-relay hop has not been
//! measured yet, so this module ships DATA-only on that direction rather than
//! guessing a budget.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use construct_veil_protocol::{
    AuthRecordV3, CapabilityV2, EXPORTER_LABEL, EXPORTER_LEN, FRAME_TYPE_CHAFF, FRAME_TYPE_DATA,
    Frame, LENGTH_BUCKETS, VeilFrontCodec,
};
use ed25519_dalek::SigningKey;
use rand::Rng;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, info, warn};

use crate::upstream_tls::build_upstream_connector;

/// CHAFF length buckets for the upstream→client idle-chaff injection.
/// Matches `tunnel.rs::CHAFF_BUCKETS`.
const CHAFF_BUCKETS: &[usize] = &[32, 64, 128, 256, 512];

/// Static configuration for dialing the upstream (`relay_clean`) relay.
///
/// `veil_sk` is this relay's own access keypair — generated locally via
/// `--generate-relay-keypair` (see `decisions/veil-ticket-provisioning-system.md`
/// B1) and never sent anywhere. `capability_v2_b64` is the `ROLE_RELAY`
/// capability the upstream's issuer signed for this relay's `veil_pk`.
#[derive(Clone)]
pub struct ChainConfig {
    /// Upstream relay address, `host:port`.
    pub upstream_addr: String,
    /// TLS SNI to present to the upstream relay.
    pub upstream_sni: String,
    /// SPKI pin (hex) for the upstream relay's certificate.
    pub upstream_spki_hex: String,
    /// Base64-encoded `CapabilityV2` blob, role = `ROLE_RELAY`.
    pub capability_v2_b64: String,
    /// This relay's Ed25519 `veil_sk` seed (32 bytes).
    pub veil_sk: SigningKey,
}

/// Error dialing or authenticating to the upstream relay.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// I/O error (connect, TLS handshake, or auth-frame write).
    #[error("chain I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS handshake or SPKI pin verification failed.
    #[error("chain TLS error: {0}")]
    Tls(String),
    /// `capability_v2_b64` did not decode/parse.
    #[error("chain capability error: {0}")]
    Capability(String),
}

/// Dial the upstream relay, complete TLS (SPKI-pinned), and send the AUTH v3
/// frame carrying this relay's `ROLE_RELAY` capability.
///
/// Returns the authenticated TLS stream — application data from here on must
/// be DATA/CHAFF frames (see [`ferry_client_to_upstream`] / [`ferry_upstream_to_client`]).
pub async fn dial_upstream(cfg: &ChainConfig) -> Result<ClientTlsStream<TcpStream>, ChainError> {
    let capability = {
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &cfg.capability_v2_b64,
        )
        .map_err(|e| ChainError::Capability(format!("base64 decode: {e}")))?;
        CapabilityV2::decode_slice(&raw)
            .ok_or_else(|| ChainError::Capability("malformed CapabilityV2 blob".into()))?
    };

    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&cfg.upstream_addr),
    )
    .await
    .map_err(|_| ChainError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect")))??;
    tcp.set_nodelay(true)?;

    let (connector, server_name) =
        build_upstream_connector(&cfg.upstream_sni, &cfg.upstream_spki_hex)
            .map_err(|e| ChainError::Tls(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ChainError::Tls(e.to_string()))?;

    let exporter = {
        let (_, conn) = tls_stream.get_ref();
        let mut exp = [0u8; EXPORTER_LEN];
        conn.export_keying_material(&mut exp, EXPORTER_LABEL.as_bytes(), Some(&[]))
            .map_err(|e| ChainError::Tls(format!("exporter: {e}")))?;
        exp
    };

    let auth = AuthRecordV3::from_capability(&capability, &cfg.veil_sk, &exporter);
    let mut auth_frame = BytesMut::new();
    VeilFrontCodec::default()
        .with_buckets(LENGTH_BUCKETS)
        .encode(Frame::auth_v3(auth.encode_payload()), &mut auth_frame)?;

    let mut tls_stream = tls_stream;
    tls_stream.write_all(&auth_frame).await?;
    tls_stream.flush().await?;

    Ok(tls_stream)
}

/// Generate a random idle-chaff payload from `CHAFF_BUCKETS`.
fn random_chaff(rng: &mut impl Rng) -> Bytes {
    let len = CHAFF_BUCKETS[rng.gen_range(0..CHAFF_BUCKETS.len())];
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    Bytes::from(buf)
}

/// Ferry one accepted client-facing tunnel through the upstream relay
/// connection, in both directions, dropping CHAFF and never forwarding raw
/// AUTH/CHAFF frames across the hop.
pub async fn forward_chain<S, U>(
    client_stream: S,
    leftover: BytesMut,
    upstream_stream: U,
    peer: SocketAddr,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_rd, client_wr) = io::split(client_stream);
    let (upstream_rd, upstream_wr) = io::split(upstream_stream);

    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let chaff_bytes = Arc::new(AtomicU64::new(0));

    let up = ferry_client_to_upstream(client_rd, leftover, upstream_wr, up_bytes.clone());
    let down = ferry_upstream_to_client(
        upstream_rd,
        client_wr,
        down_bytes.clone(),
        chaff_bytes.clone(),
    );

    let result = tokio::try_join!(up, down);
    info!(
        peer = %peer,
        up = up_bytes.load(Ordering::Relaxed),
        down = down_bytes.load(Ordering::Relaxed),
        chaff = chaff_bytes.load(Ordering::Relaxed),
        "chain tunnel closed"
    );
    match result {
        Ok(_) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            debug!("chain tunnel closed (peer disconnect)");
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, "chain tunnel forwarding error");
            Err(e)
        }
    }
}

/// Decode client DATA frames (drop CHAFF) and re-frame each payload as a
/// fresh DATA frame toward the upstream relay.
async fn ferry_client_to_upstream<R, W>(
    mut client_rd: R,
    leftover: BytesMut,
    mut upstream_wr: W,
    bytes: Arc<AtomicU64>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decode_codec = VeilFrontCodec::default();
    let mut encode_codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    let mut buf = leftover;

    loop {
        let mut wrote = false;
        while let Some(frame) = decode_codec.decode(&mut buf)? {
            match frame.frame_type {
                FRAME_TYPE_DATA => {
                    bytes.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                    let mut out = BytesMut::new();
                    encode_codec.encode(Frame::data(frame.payload), &mut out)?;
                    upstream_wr.write_all(&out).await?;
                    wrote = true;
                }
                FRAME_TYPE_CHAFF => { /* client's own chaff — hop isolation, drop */ }
                other => debug!(frame_type = other, "unexpected mid-chain frame, dropping"),
            }
        }
        if wrote {
            upstream_wr.flush().await?;
        }

        let n = client_rd.read_buf(&mut buf).await?;
        if n == 0 {
            upstream_wr.shutdown().await?;
            return Ok(());
        }
    }
}

/// Decode upstream DATA frames (drop CHAFF) and re-frame each payload as a
/// fresh DATA frame toward the client, injecting independent idle CHAFF
/// (mirrors `tunnel.rs`'s symmetric padding, same buckets).
async fn ferry_upstream_to_client<R, W>(
    mut upstream_rd: R,
    mut client_wr: W,
    bytes: Arc<AtomicU64>,
    chaff_bytes: Arc<AtomicU64>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decode_codec = VeilFrontCodec::default();
    let mut encode_codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        let read_fut = upstream_rd.read_buf(&mut buf);
        match tokio::time::timeout(Duration::from_millis(20), read_fut).await {
            Ok(Ok(0)) => {
                client_wr.shutdown().await?;
                return Ok(());
            }
            Ok(Ok(_n)) => {
                let mut wrote = false;
                while let Some(frame) = decode_codec.decode(&mut buf)? {
                    match frame.frame_type {
                        FRAME_TYPE_DATA => {
                            bytes.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                            let mut out = BytesMut::new();
                            encode_codec.encode(Frame::data(frame.payload), &mut out)?;
                            client_wr.write_all(&out).await?;
                            wrote = true;
                        }
                        FRAME_TYPE_CHAFF => { /* upstream's own chaff — hop isolation, drop */ }
                        other => debug!(frame_type = other, "unexpected mid-chain frame, dropping"),
                    }
                }
                if wrote {
                    client_wr.flush().await?;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let chaff = random_chaff(&mut rand::thread_rng());
                let mut out = BytesMut::new();
                encode_codec.encode(Frame::chaff(chaff), &mut out)?;
                client_wr.write_all(&out).await?;
                chaff_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_veil_protocol::{ROLE_RELAY, issuer_public_key};

    const SEED: [u8; 32] = [7u8; 32];
    const EXPORTER: [u8; 32] = [0xAAu8; 32];

    fn test_chain_config(spki_hex: &str) -> ChainConfig {
        let veil_sk = SigningKey::from_bytes(&[9u8; 32]);
        let veil_pk = veil_sk.verifying_key().to_bytes();
        let cap = CapabilityV2::sign(
            [0x55; 16],
            veil_pk,
            ROLE_RELAY,
            0,
            u64::MAX,
            1,
            String::new(),
            &SEED,
        );
        ChainConfig {
            upstream_addr: "127.0.0.1:1".into(),
            upstream_sni: "localhost".into(),
            upstream_spki_hex: spki_hex.into(),
            capability_v2_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                cap.encode(),
            ),
            veil_sk,
        }
    }

    #[test]
    fn chain_auth_record_verifies_against_issuer_and_exporter() {
        // Mirrors what `dial_upstream` builds, offline: the relay's own
        // ROLE_RELAY capability + veil_sk produce an AuthRecordV3 that the
        // upstream's gate would accept.
        let cfg = test_chain_config("ab");
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &cfg.capability_v2_b64,
        )
        .unwrap();
        let cap = CapabilityV2::decode_slice(&raw).unwrap();
        let rec = AuthRecordV3::from_capability(&cap, &cfg.veil_sk, &EXPORTER);
        let pubkey = issuer_public_key(&SEED);
        assert!(rec.verify(&pubkey, ROLE_RELAY, &EXPORTER, 1_000));
    }

    #[test]
    fn chain_config_capability_decodes_as_relay_role() {
        let cfg = test_chain_config("ab");
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &cfg.capability_v2_b64,
        )
        .unwrap();
        let cap = CapabilityV2::decode_slice(&raw).unwrap();
        assert_eq!(cap.role, ROLE_RELAY);
        let pubkey = issuer_public_key(&SEED);
        assert!(cap.verify_signature(&pubkey));
    }

    #[tokio::test]
    async fn forward_chain_ferries_data_and_drops_chaff_both_directions() {
        // In-memory duplex pairs stand in for the client-facing and upstream
        // TLS streams (frame-level behaviour doesn't depend on TLS itself).
        let (client_inner, client_test) = tokio::io::duplex(8192);
        let (upstream_inner, upstream_test) = tokio::io::duplex(8192);

        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let chain = tokio::spawn(async move {
            forward_chain(client_inner, BytesMut::new(), upstream_inner, peer).await
        });

        let (mut client_test_rd, mut client_test_wr) = tokio::io::split(client_test);
        let (mut upstream_test_rd, mut upstream_test_wr) = tokio::io::split(upstream_test);

        // Client sends DATA("ping") + CHAFF — only DATA should reach upstream.
        let mut codec = VeilFrontCodec::default();
        let mut out = BytesMut::new();
        codec
            .encode(Frame::data(Bytes::from_static(b"ping")), &mut out)
            .unwrap();
        codec
            .encode(Frame::chaff(Bytes::from(vec![0u8; 16])), &mut out)
            .unwrap();
        client_test_wr.write_all(&out).await.unwrap();

        let mut buf = BytesMut::with_capacity(1024);
        let mut got = Vec::new();
        while got.is_empty() {
            let n = upstream_test_rd.read_buf(&mut buf).await.unwrap();
            assert!(n > 0);
            while let Some(frame) = codec.decode(&mut buf).unwrap() {
                match frame.frame_type {
                    FRAME_TYPE_DATA => got.extend_from_slice(&frame.payload),
                    FRAME_TYPE_CHAFF => panic!("CHAFF must not cross the hop"),
                    other => panic!("unexpected frame type: {other}"),
                }
            }
        }
        assert_eq!(&got, b"ping");

        // Upstream replies DATA("pong") — client should receive it re-framed,
        // and may also see independent idle CHAFF, which it must tolerate.
        let mut reply = BytesMut::new();
        codec
            .encode(Frame::data(Bytes::from_static(b"pong")), &mut reply)
            .unwrap();
        upstream_test_wr.write_all(&reply).await.unwrap();

        let mut buf2 = BytesMut::with_capacity(1024);
        let mut got2 = Vec::new();
        while got2.is_empty() {
            let n = client_test_rd.read_buf(&mut buf2).await.unwrap();
            assert!(n > 0);
            while let Some(frame) = codec.decode(&mut buf2).unwrap() {
                match frame.frame_type {
                    FRAME_TYPE_DATA => got2.extend_from_slice(&frame.payload),
                    FRAME_TYPE_CHAFF => { /* independent idle chaff — expected */ }
                    other => panic!("unexpected frame type: {other}"),
                }
            }
        }
        assert_eq!(&got2, b"pong");

        drop(client_test_wr);
        drop(client_test_rd);
        drop(upstream_test_wr);
        drop(upstream_test_rd);
        let _ = chain.await;
    }
}
