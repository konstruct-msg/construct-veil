//! The host-terminated-TLS ferry must not kill its host when a peer of one of its sockets has
//! gone (todo 313).
//!
//! `veil_front_ferry_fd` adopts two descriptors the host app made — the accepted local gRPC
//! socket and one end of a socketpair whose other end the app pumps into its own TLS
//! connection. On Darwin a write to a socket whose peer is closed raises SIGPIPE, and its
//! default action ends the process. A Rust binary ignores SIGPIPE before `main`; a Swift app
//! with Rust linked in does not. So this stand runs in a child process with SIGPIPE back at its
//! default, makes the descriptors with libc as `VeilFrontExternalDialer.swift` does, closes the
//! peer the way a VEIL stop does while traffic is in flight, and checks the child survives.

#![cfg(all(feature = "ffi", target_vendor = "apple"))]

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::Duration;

use base64::Engine;
use construct_veil_protocol::{CapabilityV2, ROLE_USER};
use ed25519_dalek::SigningKey;

const CHILD: &str = "VEIL_SIGPIPE_STAND";
const SURVIVED: &str = "sigpipe stand: survived";

/// Run `scenario` in a child of this test binary and report how it ended.
fn in_child(test: &str, scenario: &str) -> (Option<i32>, bool, String) {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, scenario)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.signal(), text.contains(SURVIVED), text)
}

/// The loopback listener + accept and the socketpair, made with libc as the Swift dialer makes
/// them (no SO_NOSIGPIPE, which std would set on sockets it creates itself).
fn host_sockets() -> (std::net::TcpStream, i32, i32, i32) {
    unsafe {
        let l = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as _;
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(
            libc::bind(l, &addr as *const _ as *const libc::sockaddr, len),
            0
        );
        assert_eq!(libc::listen(l, 1), 0);
        let mut bound: libc::sockaddr_in = std::mem::zeroed();
        let mut blen = len;
        libc::getsockname(l, &mut bound as *mut _ as *mut libc::sockaddr, &mut blen);
        let port = u16::from_be(bound.sin_port);
        // The gRPC client side (in the app: grpc-swift / NIO, which guards its own socket).
        let grpc = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let local_fd = libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut());
        assert!(local_fd >= 0);
        libc::close(l);
        let mut fds = [-1i32; 2];
        assert_eq!(
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()),
            0
        );
        // The host's own end — it writes the relay's bytes into it — is the host's to guard
        // (VeilFrontExternalDialer sets SO_NOSIGPIPE on it); this stand checks the two the ferry
        // adopts.
        let on: libc::c_int = 1;
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        assert_eq!(
            libc::setsockopt(
                fds[0],
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &on as *const _ as *const _,
                size
            ),
            0
        );
        (grpc, local_fd, fds[0], fds[1]) // grpc, local_fd, swift_fd, rust_fd
    }
}

fn read_some(fd: i32) -> usize {
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    n.max(0) as usize
}

/// Child body: hand the descriptors to the ferry, let AUTH go out, then break one side.
fn child(scenario: &str) {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) }; // what a Swift host has
    let veil_sk = SigningKey::from_bytes(&[3u8; 32]);
    let cap = CapabilityV2::sign(
        [0x11; 16],
        veil_sk.verifying_key().to_bytes(),
        ROLE_USER,
        0,
        u64::MAX,
        1,
        String::new(),
        &[7u8; 32],
    )
    .unwrap();
    let cap_b64 = base64::engine::general_purpose::STANDARD.encode(cap.encode());
    let sk_hex = hex::encode([3u8; 32]);
    let (mut grpc, local_fd, swift_fd, rust_fd) = host_sockets();

    let exporter = [0u8; 32];
    let c = |s: &str| std::ffi::CString::new(s).unwrap();
    let (cap_c, sk_c, ticket_c) = (c(&cap_b64), c(&sk_hex), c(""));
    let rc = construct_veil::ffi::veil_front_ferry_fd(
        local_fd,
        rust_fd,
        exporter.as_ptr(),
        exporter.len(),
        cap_c.as_ptr(),
        sk_c.as_ptr(),
        ticket_c.as_ptr(),
    );
    assert_eq!(rc, 0);
    assert!(
        read_some(swift_fd) > 0,
        "the ferry sent AUTH over the socketpair"
    );

    match scenario {
        // VEIL stop: the dialer tears the session down (its socketpair end closes) while gRPC
        // is still sending — the ferry writes the next DATA frame into a closed pair.
        "host-end-closed" => {
            unsafe { libc::close(swift_fd) };
            for _ in 0..20 {
                let _ = grpc.write_all(&[0x42; 1024]);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // The gRPC client dropped its connection while the relay is still answering — the
        // ferry writes the relay's bytes into a closed local socket.
        "grpc-closed" => {
            drop(grpc);
            std::thread::sleep(Duration::from_millis(50));
            let mut frame = bytes::BytesMut::new();
            tokio_util::codec::Encoder::encode(
                &mut construct_veil_protocol::VeilFrontCodec::default(),
                construct_veil_protocol::Frame::data(bytes::Bytes::from_static(&[0x42; 1024])),
                &mut frame,
            )
            .unwrap();
            for _ in 0..20 {
                unsafe { libc::write(swift_fd, frame.as_ptr() as *const _, frame.len()) };
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        other => panic!("unknown scenario {other}"),
    }
    std::thread::sleep(Duration::from_millis(200));
    println!("{SURVIVED}");
}

fn stand(test: &str, scenario: &str) {
    if let Ok(s) = std::env::var(CHILD) {
        if s == scenario {
            child(&s);
        }
        return;
    }
    let (signal, survived, out) = in_child(test, scenario);
    assert_eq!(
        signal, None,
        "the host died of signal {signal:?} (13 = SIGPIPE):\n{out}"
    );
    assert!(survived, "the child did not reach its end:\n{out}");
}

#[test]
fn a_stop_with_traffic_in_flight_does_not_kill_the_host() {
    stand(
        "a_stop_with_traffic_in_flight_does_not_kill_the_host",
        "host-end-closed",
    );
}

#[test]
fn a_closed_grpc_connection_does_not_kill_the_host() {
    stand(
        "a_closed_grpc_connection_does_not_kill_the_host",
        "grpc-closed",
    );
}
