//! Does Apple's TLS stack compute the same exporter as ours?
//!
//! The question this answers is blocking, not academic. veil-front binds its AUTH record to the
//! TLS session with an RFC 8446 §7.5 exporter, so the client has to be able to compute one. Today
//! that forces a rustls ClientHello on iOS — a fingerprint no iPhone otherwise emits. The system
//! stack would be the right fingerprint for free, but only if `sec_protocol_metadata_create_secret`
//! agrees with `rustls::ConnectionCommon::export_keying_material` byte for byte.
//!
//! Comparing two separate handshakes proves nothing: the exporter is per-session by construction.
//! So this is one handshake, both ends. The server below prints what rustls derives; the Swift
//! client in `exporter_probe.swift` prints what Security.framework derives for the same
//! connection. Equal or not equal is the whole result.
//!
//! Run: `cargo run -p construct-veil-relay --example exporter_probe`
//!      then `swift <path>/exporter_probe.swift <port>`

use std::sync::Arc;

use construct_veil_protocol::{EXPORTER_LABEL, EXPORTER_LEN};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Both ring (via rustls) and aws-lc-rs (via rcgen) are in the tree, so the provider has to be
    // named — same reason main.rs does it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    // The client speaks h2 in production; ALPN is part of the handshake transcript, so keep it.
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    println!("listening on 127.0.0.1:{port}");
    println!("run: swift crates/construct-veil-relay/examples/exporter_probe.swift {port}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    println!("handshake failed from {peer}: {e}");
                    return;
                }
            };

            let (_, conn) = tls.get_ref();
            let mut exporter = [0u8; EXPORTER_LEN];
            // `Some(&[])` is what gate.rs, chain.rs and the client adapter all pass. Under TLS 1.3
            // an empty context and no context derive the same secret, so this also tells us what a
            // caller passing `None` would get.
            match conn.export_keying_material(&mut exporter, EXPORTER_LABEL.as_bytes(), Some(&[])) {
                Ok(_) => {
                    println!("--- connection from {peer}");
                    println!("protocol : {:?}", conn.protocol_version());
                    println!(
                        "alpn     : {:?}",
                        conn.alpn_protocol().map(String::from_utf8_lossy)
                    );
                    println!("label    : {EXPORTER_LABEL:?}");
                    println!("rust     : {}", hex::encode(exporter));
                }
                Err(e) => println!("export failed: {e}"),
            }

            // Drain so the client sees a live connection rather than an instant RST.
            let mut sink = [0u8; 256];
            let _ = tls.read(&mut sink).await;
        });
    }
}
