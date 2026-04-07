//! Example: gRPC over obfs4 using `Obfs4Channel` + tonic.
//!
//! This demonstrates how to route tonic gRPC traffic through construct-ice,
//! making the connection look like random noise to DPI systems.
//!
//! ## Requirements
//!
//! - Feature flags: `tonic-transport` (for the channel adapter)
//! - tonic + prost in the application's Cargo.toml
//!
//! ## Connection stack
//!
//! ```text
//! App (tonic client)
//!   └─ Obfs4Channel  →  TCP connect + obfs4 handshake
//!        └─ HyperObfs4Io  (hyper Read + Write adapter)
//!             └─ Server (gRPC-over-obfs4 listener)
//! ```
//!
//! ## Running
//!
//! 1. Start an obfs4 server (e.g. using construct-ice's `Obfs4Listener`):
//!    ```sh
//!    cargo run --example interop_server --features tonic-transport
//!    ```
//!
//! 2. Connect the gRPC client:
//!    ```sh
//!    cargo run --example grpc_obfs4_client --features tonic-transport -- \
//!      "cert=BASE64_CERT iat-mode=0"
//!    ```
//!
//! ## How it works
//!
//! tonic's `Endpoint::connect_with_connector()` accepts any `tower::Service<Uri>`
//! that returns a hyper-compatible I/O type.  `Obfs4Channel` implements that
//! interface: on each `call(uri)` it TCP-connects to the relay, performs the
//! obfs4 Ntor handshake, and returns an `HyperObfs4Io` wrapper around the
//! resulting `Obfs4Stream<TcpStream>`.

#[cfg(not(feature = "tonic-transport"))]
fn main() {
    eprintln!("This example requires the `tonic-transport` feature.");
    eprintln!("Run with: cargo run --example grpc_obfs4_client --features tonic-transport");
    std::process::exit(1);
}

#[cfg(feature = "tonic-transport")]
fn main() {
    // NOTE: In a real application you would have generated gRPC stubs via prost.
    // This example shows the channel setup pattern without requiring a proto file.
    //
    // Typical usage in your application:
    //
    //   use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
    //   use tonic::transport::Endpoint;
    //
    //   let config = ClientConfig::from_bridge_cert(&bridge_cert)?;
    //   let channel = Endpoint::from_static("https://relay.example.com:9443")
    //       .connect_with_connector(Obfs4Channel::new(config))
    //       .await?;
    //   let mut client = MyServiceClient::new(channel);
    //   let response = client.my_rpc(MyRequest { ... }).await?;
    //
    // The Obfs4Channel is Clone — you can share it across tasks or wrap it in
    // tonic's load-balancing primitives.

    println!("construct-ice gRPC/tonic integration example.");
    println!();
    println!("Usage pattern:");
    println!();
    println!("  let config = ClientConfig::from_bridge_cert(\"<bridge_cert>\")?;");
    println!("  let channel = Endpoint::from_static(\"https://relay:9443\")");
    println!("      .connect_with_connector(Obfs4Channel::new(config))");
    println!("      .await?;");
    println!("  // Pass `channel` to your tonic client.");
    println!();
    println!("See src/transport/tonic_compat.rs for the full implementation.");
}
