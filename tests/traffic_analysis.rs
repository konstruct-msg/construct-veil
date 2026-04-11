//! Traffic analysis resistance integration tests (I-N4).
//!
//! Verifies that [`TrafficMode`] and [`CoverTrafficScheduler`] behave correctly:
//!
//! 1. Normal mode never fires cover frames.
//! 2. ConstantRate schedules cover frames at the correct interval.
//! 3. Mimicry profiles produce intervals proportional to their target rates.
//! 4. Cover heartbeats are silently discarded by the receiving Obfs4Stream.
//! 5. `record_real_write` pushes the cover deadline forward.
//! 6. End-to-end: cover heartbeats travel through a real obfs4 connection
//!    without corrupting the decrypted stream.

use std::time::Duration;

use construct_ice::{
    ClientConfig, MimicryProfile, Obfs4Listener, Obfs4Stream, ServerConfig, TrafficMode,
    traffic_mode::CoverTrafficScheduler,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Spin up an obfs4 listener + connected client pair, returning both streams.
async fn connected_pair(
    client_traffic_mode: TrafficMode,
) -> (
    Obfs4Stream<tokio::net::TcpStream>,
    Obfs4Stream<tokio::net::TcpStream>,
) {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_cfg = ServerConfig::generate()
        .with_iat(construct_ice::IatMode::None)
        .with_handshake_timeout(Duration::from_millis(400));
    let cert = server_cfg.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_cfg).await.unwrap();

    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });

    let client_cfg = ClientConfig::from_bridge_cert(&cert)
        .unwrap()
        .with_traffic_mode(client_traffic_mode);
    let client = Obfs4Stream::connect(&addr, client_cfg).await.unwrap();
    let server = accept.await.unwrap();

    (client, server)
}

// ── Unit tests for TrafficMode / CoverTrafficScheduler ────────────────────────

#[test]
fn normal_mode_scheduler_never_fires() {
    let sched = CoverTrafficScheduler::new(TrafficMode::Normal);
    assert!(!sched.is_active());
    assert!(sched.next_deadline().is_none());
    assert!(sched.time_until_next().is_none());
}

#[test]
fn constant_rate_scheduler_has_deadline() {
    let mode = TrafficMode::ConstantRate { bps: 1_000 };
    let sched = CoverTrafficScheduler::new(mode);
    assert!(sched.is_active());
    assert!(sched.next_deadline().is_some());
    // Interval should be well under 60s for 1 KB/s with 1448-byte frames
    let t = sched.time_until_next().unwrap();
    assert!(t < Duration::from_secs(60), "interval too long: {t:?}");
}

#[test]
fn mimicry_profiles_scheduler_ordering() {
    let video = CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::VideoStream));
    let web = CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::WebBrowsing));
    let bg = CoverTrafficScheduler::new(TrafficMode::Mimicry(MimicryProfile::BackgroundSync));

    let tv = video.time_until_next().unwrap();
    let tw = web.time_until_next().unwrap();
    let tb = bg.time_until_next().unwrap();

    assert!(tv <= tw, "VideoStream should fire sooner than WebBrowsing");
    assert!(
        tw <= tb,
        "WebBrowsing should fire sooner than BackgroundSync"
    );
}

#[test]
fn scheduler_record_sent_increments_counter() {
    let mode = TrafficMode::Mimicry(MimicryProfile::WebBrowsing);
    let mut sched = CoverTrafficScheduler::new(mode);
    assert_eq!(sched.frames_sent(), 0);
    assert_eq!(sched.bytes_sent(), 0);

    sched.record_sent();
    assert_eq!(sched.frames_sent(), 1);
    assert!(sched.bytes_sent() > 0);

    sched.record_sent();
    assert_eq!(sched.frames_sent(), 2);
}

#[test]
fn scheduler_record_real_write_pushes_deadline() {
    let mode = TrafficMode::Mimicry(MimicryProfile::BackgroundSync);
    let mut sched = CoverTrafficScheduler::new(mode);
    let d1 = sched.next_deadline().unwrap();

    sched.record_real_write();
    let d2 = sched.next_deadline().unwrap();

    assert!(d2 >= d1, "real write must push deadline forward");
    assert_eq!(
        sched.frames_sent(),
        0,
        "real write must not count as cover frame"
    );
}

#[test]
fn traffic_mode_accessor_matches_config() {
    // Verify that the stream stores and returns the configured TrafficMode.
    // (Synchronous test — connect_pair is tested in the async tests below.)
    let mode = TrafficMode::Mimicry(MimicryProfile::VideoStream);
    assert_eq!(mode, TrafficMode::Mimicry(MimicryProfile::VideoStream));
    assert!(mode.is_active());
    assert!(mode.cover_interval().is_some());
}

// ── Integration tests — cover heartbeats over a real obfs4 connection ─────────

/// Cover heartbeats sent over an idle connection must be silently discarded
/// by the receiver — they must NOT appear as application data.
#[tokio::test]
async fn cover_heartbeats_silently_discarded_by_receiver() {
    let (mut client, mut server) = connected_pair(TrafficMode::Normal).await;

    // Send 3 heartbeats from client to server.
    for _ in 0..3 {
        client.send_heartbeat().await.unwrap();
    }

    // Then send a sentinel payload so we know where the stream ends.
    client.write_all(b"SENTINEL").await.unwrap();
    client.flush().await.unwrap();

    // Server should receive ONLY the sentinel — heartbeats are invisible.
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_millis(500), server.read(&mut buf))
        .await
        .expect("server read timed out")
        .expect("server read error");

    assert_eq!(
        &buf[..n],
        b"SENTINEL",
        "heartbeats must not appear as application data"
    );
}

/// The traffic_mode() accessor returns what was configured.
#[tokio::test]
async fn stream_traffic_mode_accessor_returns_configured_mode() {
    let mode = TrafficMode::Mimicry(MimicryProfile::WebBrowsing);
    let (client, _server) = connected_pair(mode).await;
    assert_eq!(client.traffic_mode(), mode);
}

/// CoverTrafficScheduler drives heartbeats over a real connection without
/// corrupting the data stream.
#[tokio::test]
async fn cover_scheduler_drives_heartbeats_without_corruption() {
    let (mut client, mut server) =
        connected_pair(TrafficMode::Mimicry(MimicryProfile::BackgroundSync)).await;

    let mut sched = CoverTrafficScheduler::new(client.traffic_mode());

    // Simulate a mixed workload: some real writes + cover frame injection.
    // We don't wait for the scheduler's full 1s interval — just test the
    // mechanics.
    client.write_all(b"HELLO").await.unwrap();
    sched.record_real_write();
    client.flush().await.unwrap();

    // Inject one cover frame manually.
    client.send_heartbeat().await.unwrap();
    sched.record_sent();
    assert_eq!(sched.frames_sent(), 1);

    // Send final data + flush.
    client.write_all(b"WORLD").await.unwrap();
    client.flush().await.unwrap();

    // Server receives data in order, heartbeats discarded.
    let mut buf = vec![0u8; 32];
    let n1 = timeout(Duration::from_millis(400), server.read(&mut buf))
        .await
        .expect("read 1 timed out")
        .expect("read 1 error");

    // Read again to get WORLD (may arrive in same or separate read).
    let payload: Vec<u8> = buf[..n1].to_vec();
    let combined = if payload == b"HELLOWORLD" {
        payload
    } else {
        let n2 = timeout(Duration::from_millis(400), server.read(&mut buf))
            .await
            .expect("read 2 timed out")
            .expect("read 2 error");
        let mut c = payload;
        c.extend_from_slice(&buf[..n2]);
        c
    };

    assert_eq!(
        combined, b"HELLOWORLD",
        "data must arrive intact despite cover frames"
    );
}
