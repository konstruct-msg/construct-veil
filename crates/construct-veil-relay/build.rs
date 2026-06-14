// Generates the VeilService gRPC *client* used by ticket_sync to subscribe to the
// backend's active ticket set. The proto is vendored from construct-server
// (shared/proto/services/veil_service.proto) — keep the two copies in sync.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/veil_service.proto");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/veil_service.proto"], &["proto/"])?;
    Ok(())
}
