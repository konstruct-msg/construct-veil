//! What the veil-front client costs its host: heap, threads, descriptors, wake-ups, disk.
//!
//! Drives the shipped C ABI (`veil_start`, `veil_front_ferry_fd`) under construct-core's release
//! profile, because the apps link that and not this repository's own. Not a test and not in CI:
//! a stand to run before and after a change (construct-docs todo 341).
//!
//! ```text
//! cargo build --release && target/release/client-resources <mode>
//! runtime | tunnels N | frames | bulk | bigframe | cycles | cycles-silent | start | panic
//! ```
//!
//! Counts (allocations, live heap, threads, descriptors, handshakes, frames) repeat on a loaded
//! machine. CPU time and throughput do not: look at `uptime` first, and run A/A. macOS only.
//! `panic` shows `ffi_guard` per profile (`release` mirrors core, `unwind` is `panic = "unwind"`).

mod meter;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use construct_veil::ffi::*;
use construct_veil_protocol::*;
use meter::*;
use std::ffi::CString;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use tokio_util::codec::{Decoder, Encoder};

#[global_allocator]
static A: Counting = Counting;

fn creds() -> (String, String) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let cap = CapabilityV2::sign(
        [0x11; 16],
        sk.verifying_key().to_bytes(),
        ROLE_USER,
        0,
        u64::MAX,
        1,
        String::new(),
        &[7u8; 32],
    )
    .unwrap();
    (
        base64::engine::general_purpose::STANDARD.encode(cap.encode()),
        hex::encode([3u8; 32]),
    )
}
fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms))
}
fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// One native-TLS ferry: (grpc client end, host's socketpair end).
fn ferry(
    l: &std::net::TcpListener,
    cap: &CString,
    sk: &CString,
    t: &CString,
) -> (std::net::TcpStream, std::os::unix::net::UnixStream) {
    use std::os::fd::IntoRawFd;
    let grpc = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    grpc.set_nodelay(true).unwrap();
    let (local, _) = l.accept().unwrap();
    let (host, rust) = std::os::unix::net::UnixStream::pair().unwrap();
    let e = [0u8; 32];
    assert_eq!(
        veil_front_ferry_fd(
            local.into_raw_fd(),
            rust.into_raw_fd(),
            e.as_ptr(),
            32,
            cap.as_ptr(),
            sk.as_ptr(),
            t.as_ptr()
        ),
        0
    );
    (grpc, host)
}

/// Frame reader without allocation: payload bytes of DATA, CHAFF and frame counts.
struct Parser {
    buf: Vec<u8>,
    len: usize,
}
impl Parser {
    fn new() -> Self {
        Self {
            buf: vec![0; 1 << 20],
            len: 0,
        }
    }
    /// (data payload, data frames, chaff wire bytes, chaff frames) in what one read brought
    fn read(&mut self, s: &mut impl Read) -> Option<[u64; 5]> {
        let n = match s.read(&mut self.buf[self.len..]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        self.len += n;
        let mut o = [0u64; 5];
        o[4] = n as u64;
        let mut p = 0;
        while let Some((ty, pl, total)) = hdr(&self.buf[p..self.len]) {
            if p + total > self.len {
                break;
            }
            if ty == FRAME_TYPE_DATA {
                o[0] += pl as u64;
                o[1] += 1
            } else if ty == FRAME_TYPE_CHAFF {
                o[2] += total as u64;
                o[3] += 1
            }
            p += total;
        }
        self.buf.copy_within(p..self.len, 0);
        self.len -= p;
        Some(o)
    }
}
fn vint(b: &[u8]) -> Option<(usize, usize)> {
    // whichever varint: use the crate's decoder
    let mut s = b;
    decode_varint(&mut s).map(|(v, n)| (v as usize, n))
}
fn hdr(b: &[u8]) -> Option<(u8, usize, usize)> {
    if b.len() < 4 {
        return None;
    }
    let (pl, a) = vint(&b[2..])?;
    if b.len() <= 2 + a {
        return None;
    }
    let (pad, d) = vint(&b[2 + a..])?;
    Some((b[1], pl, 2 + a + d + pl + pad))
}

fn runtime() {
    let a = snap();
    veil_port();
    sleep(200);
    let b = snap();
    show("first FFI call (runtime built)", a, b);
    sleep(10_000);
    show("10 s idle, no tunnel", b, snap());
}

fn tunnels(n: usize) {
    let (cap, sk) = creds();
    let (cap, sk, t) = (c(&cap), c(&sk), c(""));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    veil_port();
    sleep(200);
    let stats: &'static [AtomicU64; 4] = Box::leak(Box::new([const { AtomicU64::new(0) }; 4]));
    let z = snap();
    let mut keep = vec![];
    for _ in 0..n {
        let (g, h) = ferry(&l, &cap, &sk, &t);
        let mut r = h.try_clone().unwrap();
        let mut p = Parser::new(); // 1 MB, subtracted below
        std::thread::spawn(move || {
            while let Some(o) = p.read(&mut r) {
                stats[0].fetch_add(o[2], Relaxed);
                stats[1].fetch_add(o[3], Relaxed);
                stats[2].fetch_add(o[4], Relaxed);
                stats[3].fetch_add(1, Relaxed);
            }
        });
        keep.push((g, h));
    }
    sleep(100);
    let a = snap();
    let per = ((a.live - z.live) as f64 - n as f64 * (1 << 20) as f64) / n as f64 / 1024.;
    println!(
        "{n} tunnels open: live heap per tunnel {per:.1} KB (parser buffers excluded; includes one host thread each)"
    );
    sleep(3_900);
    let b = snap();
    show(&format!("{n} tunnels, chaff window"), a, b);
    let per = ((b.live - z.live) as f64 - n as f64 * (1 << 20) as f64) / n as f64 / 1024.;
    println!(
        "   after window: live per tunnel {per:.1} KB; chaff per tunnel: {} frames, {:.1} KB, wire total {:.1} KB, host reads {}",
        stats[1].load(Relaxed) / n as u64,
        stats[0].load(Relaxed) as f64 / 1024. / n as f64,
        stats[2].load(Relaxed) as f64 / 1024. / n as f64,
        stats[3].load(Relaxed) / n as u64
    );
    sleep(10_000);
    show(&format!("{n} tunnels, 10 s idle after"), b, snap());
}

fn frames() {
    let (cap, sk) = creds();
    let (cap, sk, t) = (c(&cap), c(&sk), c(""));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut g, mut h) = ferry(&l, &cap, &sk, &t);
    let mut p = Parser::new();
    h.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(4500) {
        let _ = p.read(&mut h);
    }
    h.set_read_timeout(None).unwrap();
    println!("after chaff; {} per row", 2000);
    for size in [100usize, 1024, 4096, 8192, 65536] {
        let msg = vec![0x42u8; size];
        let mut rx = vec![0u8; size.max(65536)];
        for dir in ["up", "down"] {
            let iters = if size > 10000 { 400u64 } else { 2000 };
            let mut enc = BytesMut::new();
            VeilFrontCodec::default()
                .with_buckets(LENGTH_BUCKETS)
                .encode(Frame::data(Bytes::from(msg.clone())), &mut enc)
                .unwrap();
            // the relay reads its backend 8 KB at a time
            let mut relay_wire = BytesMut::new();
            for ch in msg.chunks(8192) {
                VeilFrontCodec::default()
                    .with_buckets(LENGTH_BUCKETS)
                    .encode(Frame::data(Bytes::copy_from_slice(ch)), &mut relay_wire)
                    .unwrap();
            }
            let mut fr;
            for warm in [true, false] {
                let a = snap();
                let t0 = Instant::now();
                let it = if warm { 50 } else { iters };
                fr = 0;
                for _ in 0..it {
                    if dir == "up" {
                        g.write_all(&msg).unwrap();
                        let mut got = 0;
                        while got < size as u64 {
                            let o = p.read(&mut h).unwrap();
                            got += o[0];
                            fr += o[1];
                        }
                    } else {
                        std::thread::scope(|s| {
                            if relay_wire.len() > 4096 {
                                let mut hh = &h;
                                let w = &relay_wire;
                                s.spawn(move || hh.write_all(w).unwrap());
                            } else {
                                h.write_all(&relay_wire).unwrap();
                            }
                            g.read_exact(&mut rx[..size]).unwrap();
                        });
                    }
                }
                if !warm {
                    let b = snap();
                    let n = iters as f64;
                    println!(
                        "{dir:<4} {size:>6} B: allocs/msg {:>6.2} alloc bytes/msg {:>9.0} ({:.2}x payload) frames/msg {:.2} cpu {:>6.1} us/msg wall {:>6.1} us{}",
                        (b.allocs - a.allocs) as f64 / n,
                        (b.bytes - a.bytes) as f64 / n,
                        (b.bytes - a.bytes) as f64 / n / size as f64,
                        fr as f64 / n,
                        (b.cpu_us - a.cpu_us) as f64 / n,
                        t0.elapsed().as_micros() as f64 / n,
                        if dir == "down" && relay_wire.len() > 4096 {
                            " (includes a host thread spawn)"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }
}

/// Throughput of one ferry, one direction, host end sinking/sourcing.
fn bulk() {
    let (cap, sk) = creds();
    let (cap, sk, t) = (c(&cap), c(&sk), c(""));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut g, mut h) = ferry(&l, &cap, &sk, &t);
    let mut p = Parser::new();
    h.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(4500) {
        let _ = p.read(&mut h);
    }
    h.set_read_timeout(None).unwrap();
    let total = 64 << 20;
    let a = snap();
    let t0 = Instant::now();
    let w = std::thread::spawn(move || {
        let b = vec![0u8; 65536];
        for _ in 0..total / 65536 {
            g.write_all(&b).unwrap();
        }
        g
    });
    let (mut got, mut fr, mut wire) = (0u64, 0u64, 0u64);
    while got < total as u64 {
        let o = p.read(&mut h).unwrap();
        got += o[0];
        fr += o[1];
        wire += o[4];
    }
    let mut g = w.join().unwrap();
    let b = snap();
    println!(
        "up 64 MB: {:.0} MB/s wall, cpu {:.1} ms/MB, frames {fr} avg {} B, wire overhead {:.2} %, allocs/MB {}, alloc/MB {:.2} MB",
        64. / t0.elapsed().as_secs_f64(),
        (b.cpu_us - a.cpu_us) as f64 / 64000.,
        got / fr,
        (wire as f64 / got as f64 - 1.) * 100.,
        (b.allocs - a.allocs) / 64,
        (b.bytes - a.bytes) as f64 / 64. / 1048576.
    );
    let mut enc = BytesMut::new();
    for _ in 0..128 {
        VeilFrontCodec::default()
            .with_buckets(LENGTH_BUCKETS)
            .encode(Frame::data(Bytes::from(vec![1u8; 8192])), &mut enc)
            .unwrap();
    }
    let enc = enc.freeze();
    let a = snap();
    let t0 = Instant::now();
    let w = std::thread::spawn(move || {
        for _ in 0..64 {
            h.write_all(&enc).unwrap();
        }
        h
    });
    let mut rx = vec![0u8; 65536];
    let mut got = 0;
    while got < total {
        got += g.read(&mut rx).unwrap();
    }
    w.join().unwrap();
    let b = snap();
    println!(
        "down 64 MB: {:.0} MB/s wall, cpu {:.1} ms/MB, allocs/MB {}, alloc/MB {:.2} MB, peak-live since start {:.0} KB",
        64. / t0.elapsed().as_secs_f64(),
        (b.cpu_us - a.cpu_us) as f64 / 64000.,
        (b.allocs - a.allocs) / 64,
        (b.bytes - a.bytes) as f64 / 64. / 1048576.,
        PEAK.load(Relaxed) as f64 / 1024.
    );
}

/// What a down frame near max_payload costs (a front can send 1 MiB frames).
fn bigframe() {
    let (cap, sk) = creds();
    let (cap, sk, t) = (c(&cap), c(&sk), c(""));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (g, mut h) = ferry(&l, &cap, &sk, &t);
    sleep(200);
    let mut enc = BytesMut::new();
    VeilFrontCodec::default()
        .encode(Frame::data(Bytes::from(vec![1u8; 1 << 20])), &mut enc)
        .unwrap();
    let a = snap();
    h.write_all(&enc[..enc.len() - 1]).unwrap();
    sleep(300);
    show("1 MiB frame, last byte withheld", a, snap());
    h.write_all(&enc[enc.len() - 1..]).unwrap();
    let mut g2 = g;
    let mut rx = vec![0; 65536];
    let mut got = 0;
    while got < 1 << 20 {
        got += g2.read(&mut rx).unwrap();
    }
    sleep(200);
    show("1 MiB frame delivered", a, snap());
}

/// 100 reconnects; the host closes its end on EOF (as the apps do) or stays silent.
fn cycles(silent: bool) {
    let (cap, sk) = creds();
    let (cap, sk, t) = (c(&cap), c(&sk), c(""));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for _ in 0..5 {
        drop(ferry(&l, &cap, &sk, &t));
    }
    sleep(1000);
    let a = snap();
    let mut held = vec![];
    for _ in 0..100 {
        let (g, mut h) = ferry(&l, &cap, &sk, &t);
        sleep(10);
        drop(g); // gRPC client gone
        if silent {
            held.push(h)
        } else {
            let mut b = [0u8; 65536];
            while h.read(&mut b).unwrap_or(0) > 0 {}
        }
    }
    sleep(3000);
    show(
        if silent {
            "100 cycles, front stays silent"
        } else {
            "100 cycles, host closes on EOF"
        },
        a,
        snap(),
    );
    if silent {
        sleep(30_000);
        show("  +30 s", a, snap());
        drop(held);
        sleep(1000);
        show("  host ends dropped", a, snap());
    }
}

async fn serve() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    use x509_cert::der::{Decode, Encode as E2};
    let x = x509_cert::Certificate::from_der(cert.cert.der()).unwrap();
    use sha2::Digest;
    let pin = hex::encode(sha2::Sha256::digest(
        x.tbs_certificate.subject_public_key_info.to_der().unwrap(),
    ));
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("{} {pin}", l.local_addr().unwrap().port());
    loop {
        let (s, _) = l.accept().await.unwrap();
        s.set_nodelay(true).unwrap();
        let acc = acc.clone();
        tokio::spawn(async move {
            let Ok(mut s) = acc.accept(s).await else {
                println!("hs-fail");
                return;
            };
            println!("hs");
            let (mut up, mut codec, mut out) = (
                BytesMut::new(),
                VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS),
                BytesMut::new(),
            );
            loop {
                match s.read_buf(&mut up).await {
                    Ok(0) | Err(_) => break,
                    _ => {}
                }
                while let Ok(Some(f)) = codec.decode(&mut up) {
                    if f.is_data() {
                        codec.encode(f, &mut out).unwrap()
                    }
                }
                if !out.is_empty() {
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                    let _ = s.flush().await;
                    out.clear();
                }
            }
        });
    }
}

struct Front {
    child: std::process::Child,
    port: u16,
    pin: String,
    hs: Arc<AtomicU64>,
}
impl Drop for Front {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
fn front() -> Front {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("serve")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut r = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let (p, pin) = line.trim().split_once(' ').unwrap();
    let hs = Arc::new(AtomicU64::new(0));
    let h2 = hs.clone();
    let (port, pin) = (p.parse().unwrap(), pin.to_owned());
    std::thread::spawn(move || {
        let mut l = String::new();
        while r.read_line(&mut l).unwrap_or(0) > 0 {
            if l.trim() == "hs" {
                h2.fetch_add(1, Relaxed);
            }
            l.clear();
        }
    });
    Front {
        child,
        port,
        pin,
        hs,
    }
}
fn start(f: &Front, scores: Option<&CString>) -> (i32, VeilStartResult) {
    let (cap, sk) = creds();
    let (cap, sk, e) = (c(&cap), c(&sk), c(""));
    let (addr, pin, sni) = (
        c(&format!("127.0.0.1:{}", f.port)),
        c(&f.pin),
        c("localhost"),
    );
    let key = [9u8; 32];
    let req = VeilStartRequest {
        relay_addr: addr.as_ptr(),
        bundle: e.as_ptr(),
        tls_sni: sni.as_ptr(),
        spki_hex: pin.as_ptr(),
        host_header: e.as_ptr(),
        wt_base_path: e.as_ptr(),
        network_fingerprint: key.as_ptr(),
        network_fingerprint_len: 32,
        allowed_methods: 0,
        scores_path: scores.map_or(std::ptr::null(), |s| s.as_ptr()),
        veil_front_ticket_b64: e.as_ptr(),
        veil_capability_v2_b64: cap.as_ptr(),
        veil_sk_hex: sk.as_ptr(),
        scoring_key: key.as_ptr(),
        scoring_key_len: 32,
    };
    let mut out = VeilStartResult {
        port: 0,
        method: 0,
        latency_ms: 0,
    };
    (veil_start(req, &mut out), out)
}
fn startmode() {
    let f = front();
    let path = std::env::temp_dir().join(format!("veil-stand-{}.db", std::process::id()));
    let sc = c(path.to_str().unwrap());
    veil_port();
    sleep(200);
    let a = snap();
    let t0 = Instant::now();
    let (rc, out) = start(&f, Some(&sc));
    let el = t0.elapsed();
    let b = snap();
    show("first veil_start", a, b);
    println!(
        "   rc {rc} wall {:.1} ms reported {} ms, TLS handshakes {}",
        el.as_secs_f64() * 1e3,
        out.latency_ms,
        f.hs.load(Relaxed)
    );
    let a = snap();
    let t0 = Instant::now();
    let mut g = std::net::TcpStream::connect(("127.0.0.1", out.port)).unwrap();
    g.set_nodelay(true).unwrap();
    g.write_all(b"hello").unwrap();
    let mut x = [0u8; 5];
    g.read_exact(&mut x).unwrap();
    println!(
        "   first gRPC byte round trip {:.1} ms, TLS handshakes total {}",
        t0.elapsed().as_secs_f64() * 1e3,
        f.hs.load(Relaxed)
    );
    show("first tunnel (TLS in Rust)", a, snap());
    sleep(4000);
    let m = snap();
    show("  one TLS tunnel after chaff", a, m);
    // up/down echo bulk
    let mut gw = g.try_clone().unwrap();
    let t0 = Instant::now();
    let a2 = snap();
    let w = std::thread::spawn(move || {
        let b = vec![0u8; 65536];
        for _ in 0..512 {
            gw.write_all(&b).unwrap();
        }
    });
    let mut rx = vec![0u8; 65536];
    let mut got = 0;
    while got < 512 * 65536 {
        got += g.read(&mut rx).unwrap();
    }
    w.join().unwrap();
    let b2 = snap();
    println!(
        "   echo 32 MB through TLS ferry: {:.0} MB/s, client cpu {:.2} ms/MB (both ways), alloc/MB {:.2} MB",
        32. / t0.elapsed().as_secs_f64(),
        (b2.cpu_us - a2.cpu_us) as f64 / 32000.,
        (b2.bytes - a2.bytes) as f64 / 32. / 1048576.
    );
    sleep(500);
    let i = snap();
    sleep(10_000);
    show("TLS tunnel 10 s idle", i, snap());
    veil_stop();
    drop(g);
    sleep(1000);
    let a = snap();
    for _ in 0..30 {
        let (rc, o) = start(&f, Some(&sc));
        assert_eq!(rc, 0);
        let mut g = std::net::TcpStream::connect(("127.0.0.1", o.port)).unwrap();
        g.write_all(b"hello").unwrap();
        let mut x = [0u8; 5];
        g.read_exact(&mut x).unwrap();
        veil_stop();
    }
    sleep(2000);
    show("30 start/tunnel/stop", a, snap());
    // pure start cost split
    let a = snap();
    let t0 = Instant::now();
    for _ in 0..20 {
        assert_eq!(start(&f, Some(&sc)).0, 0);
        veil_stop();
    }
    println!(
        "   start+stop avg {:.1} ms wall, {:.1} ms cpu, {} allocs, {:.0} KB, {} KB disk",
        t0.elapsed().as_secs_f64() * 50.,
        (snap().cpu_us - a.cpu_us) as f64 / 20000.,
        (snap().allocs - a.allocs) / 20,
        (snap().bytes - a.bytes) as f64 / 20480.,
        (snap().diskw - a.diskw) / 20480
    );
    let _ = std::fs::remove_file(&path);
}

fn panicmode() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    println!(
        "calling veil_port() from a tokio thread (a panic ffi_guard is documented to contain)"
    );
    let r = rt.block_on(async { veil_port() });
    println!("SURVIVED, returned {r}");
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str).unwrap_or("") {
        "runtime" => runtime(),
        "tunnels" => tunnels(a[2].parse().unwrap()),
        "frames" => frames(),
        "bulk" => bulk(),
        "bigframe" => bigframe(),
        "cycles" => cycles(false),
        "cycles-silent" => cycles(true),
        "serve" => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve()),
        "start" => startmode(),
        "panic" => panicmode(),
        _ => eprintln!(
            "modes: runtime tunnels N frames bulk bigframe cycles cycles-silent start panic"
        ),
    }
}
