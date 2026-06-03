# construct-veil

Pluggable transport suite for Construct Messenger — makes gRPC traffic indistinguishable
from random noise or cover web traffic. DPI resistance for Iran, China, Russia.

## Workspace

```
construct-veil/
├── src/                          ← core obfs4 + coordinator (this crate)
├── crates/
│   ├── construct-veil-protocol/  ← veil-front wire protocol (frames, auth, tickets)
│   └── construct-veil-relay/     ← veil-front relay (TLS gate, tunnel, site forward)
```

## Status

### obfs4 (stable)

| Component | Status |
|-----------|--------|
| Elligator2 encode/decode | ✅ Randomized variant, Go cross-tested (10 vectors) |
| Keypair generation | ✅ Dirty pubkey from representative |
| ntor handshake crypto | ✅ Go cross-tested (KEY_SEED, AUTH) |
| KDF (HKDF-SHA256) | ✅ Go cross-tested (144-byte session keys) |
| Handshake (client + server) | ✅ Mark scanning, MAC with clock skew |
| Frame encoder/decoder | ✅ NaCl secretbox + SipHash OFB length obfuscation |
| Protocol polymorphism (PRNG seed) | ✅ Full re-key on every PrngSeed frame (IAT + length obf) |
| AsyncRead/AsyncWrite transport | ✅ Obfs4Stream, Obfs4Listener |
| WebTunnel v2 transport | ✅ HTTP UPGRADE, path auth token, TLS SNI domain-fronting |
| Prometheus metrics | ✅ Relay stats + replay eviction counter (feature = "metrics") |
| E2E tests | ✅ Echo, multi-round-trip, large payload, multi-session |
| iOS interop | ✅ FFI bindings via construct-core (UniFFI) |

### veil-front (PoC — M0–M7 complete)

| Component | Status |
|-----------|--------|
| Protocol types (varint, frames, tickets, auth) | ✅ `construct-veil-protocol` |
| TLS gate with constant-shape routing | ✅ `gate_with_exporter()` — exporter-bound tickets, anti-fingerprinting read |
| h2c tunnel (frame deframing/reframing) | ✅ Relay strips DATA → backend, re-wraps → client |
| H2 preface probe (round-trip DATA) | ✅ `VeilFrontObfuscator` — confirms tunnel via incoming DATA frame |
| Mode 0 chaff scheduler | ✅ `FrontChaffScheduler` — payload priority, 5ms cooldown, 3s front window, bucketed sizes |
| Chaff integrated into ferry | ✅ `WriteStrategy` — up-stream injects CHAFF during idle, DATA always wins |
| Coordinator integration | ✅ `MethodId::VeilFront` races alongside obfs4/WebTunnel |
| PersistentScores | ✅ SQLite-backed scoring with VeilFront support |
| FFI | ✅ `veil_start()` registers VeilFrontObfuscator (feature = "utls") |

## Architecture

### obfs4 data path

```
[iOS gRPC] ↔ [obfs4 client] ~~~ obfuscated TCP ~~~ [obfs4 server] ↔ [Traefik/Envoy]
```

### veil-front data path

```
[iOS gRPC] ↔ [VeilFront client] ~~~ TLS 1.3 (honest SNI) ~~~ [veil-front relay]
                                                        ├─ valid auth → h2c backend (Construct)
                                                        └─ invalid auth → cover site (SSE app)
```

### Source layout

```
src/
├── lib.rs                      ← Public surface: Obfs4Stream, Obfs4Listener
├── crypto/                     ← Elligator2, keypair, ntor, KDF
├── handshake/                  ← Client + server handshake state machines
├── framing/                    ← Frame encoder/decoder (NaCl + SipHash OFB)
├── transport/                  ← AsyncRead/AsyncWrite transport wrappers
├── iat.rs                      ← Inter-arrival timing jitter (IAT mode)
├── replay_filter.rs            ← Replay attack prevention
├── tls_fingerprint.rs          ← TLS fingerprint randomization
├── tls_pinned.rs               ← TLS pinning for client connections
├── traffic_mode.rs             ← Protocol polymorphism (PRNG seed re-keying)
├── ffi.rs                      ← FFI bindings (construct-core UniFFI, coordinator)
├── metrics.rs                  ← Prometheus metrics (feature = "metrics")
└── veil/
    ├── coordinator.rs          ← VeilCoordinator — FSM-driven probe orchestrator
    ├── fsm.rs                  ← Pure FSM: states, events, effects, reducer
    ├── scoring.rs              ← PersistentScores — SQLite-backed per-network scoring
    ├── obfuscator.rs           ← Obfuscator trait (shared interface)
    ├── obfs4_adapter.rs        ← Obfs4Obfuscator (feature = "tls")
    ├── webtunnel_adapter.rs    ← WebTunnelObfuscator (feature = "webtunnel")
    └── veil_front/
        ├── mod.rs              ← FrontChaffScheduler, WriteStrategy, PayloadQueue
        ├── padding/
        │   └── mode0_front.rs  ← Mode 0 chaff scheduling (connection start → taper)
        └── veil_front_adapter.rs  ← VeilFrontObfuscator: probe + ferry (feature = "utls")

crates/construct-veil-protocol/src/
├── lib.rs                      ← Re-exports, constants (EXPORTER_LABEL, FRAME_TYPE_*)
├── varint.rs                   ← LEB128 varint encode/decode
├── ticket.rs                   ← Ticket struct (session-bound, expiry, authkey)
├── auth.rs                     ← AuthRecord: ticket_id + authcode (exporter-bound)
└── framing.rs                  ← VeilFrontCodec: AUTH/DATA/CHAFF frames

crates/construct-veil-relay/src/
├── main.rs                     ← Entrypoint: TLS accept loop
├── tls.rs                      ← TLS server config (per-connection certs)
├── gate.rs                     ← Constant-shape gate: exporter auth → tunnel/site
├── tunnel.rs                   ← H2C tunnel: deframe client → backend, reframe → client
├── site.rs                     ← Cover site forwarder (constant-shape fallback)
├── tickets.rs                  ← TicketStore: in-memory + validation
```

## Protocol Polymorphism

Every construct-veil connection is cryptographically distinct from every other connection —
including connections from the same client to the same relay.

This is achieved through **PRNG seed re-keying**: during and after the handshake, both sides
exchange a `PrngSeed` frame containing 24 random bytes. On receipt, both sides independently
re-derive:

1. **IAT RNG state** — controls inter-arrival timing jitter. New seed = `ChaCha8(prng_seed)`.
2. **Length obfuscator key** — SipHash-2-4 OFB mode. New key+IV derived from `SHA-256(prng_seed)[0..24]`.

Because both sides apply the re-key to the same seed in the same order, they stay in sync
without any additional round-trip.

**Effect on DPI classifiers:** a machine learning classifier trained on one session's frame
length distribution will fail on any subsequent session — even from the same device to the
same relay — because the SipHash key changes every time.

### PrngSeed re-key sites

| Site | When | Who sends |
|------|------|-----------|
| Client handshake trailing bytes | After ntor KDF, before first data frame | Client |
| Server `accept_with_cert()` | After server sends seed, before first data frame | Server |
| `poll_read()` mid-stream | Any time the other side wishes to rotate | Either |

Both IAT RNG and length obfuscator are re-keyed at every site — the original Go obfs4
implementation only re-seeded the IAT RNG.

---

## Known Deviations from obfs4 Spec

### 1. Minimum client padding: 77 bytes (spec: 85)

The Go reference implementation sends a minimum of 85 bytes of client random padding.
construct-veil sends a minimum of **77 bytes** (`MAC_LENGTH(32) + MIN_HANDSHAKE_LENGTH(45)`).

**Reason:** Earlier iOS versions of the client relied on 77-byte minimum for packet
alignment. The deviation is safe — both values provide adequate padding to prevent
fingerprinting the handshake length. Go servers accept any padding ≥ 0.

**Wire compatibility:** ✅ Go server accepts construct-veil clients. Go clients accepted by
construct-veil server (Go sends ≥ 85, which is > 77 minimum).

### 2. Nonce wraparound: connection termination (spec: undefined)

The obfs4 spec does not define behavior when the 64-bit frame counter (nonce) wraps around.
construct-veil uses `u64::checked_add` for the nonce — if it would overflow, the encode/decode
returns an error and the connection is torn down cleanly.

**Practical impact:** 2⁶⁴ frames × minimum frame size ≈ **18 exabytes** of data per session.
A connection will not live long enough to encounter wraparound under any realistic usage.
The check is a defence-in-depth measure against potential counter-manipulation exploits.

### 3. Length obfuscator re-keying on PrngSeed (spec: IAT only)

The original obfs4 spec says PrngSeed updates the IAT RNG only. construct-veil also re-keys
the SipHash-2-4 length obfuscator. See [Protocol Polymorphism](#protocol-polymorphism) above.

**Wire compatibility:** ✅ Both sides use the same seed, so they derive the same new key.
Go clients connecting to a construct-veil server will **not** re-key their length obfuscator —
this is safe because the server re-keys only its encoder, which the Go client's decoder does
not need to know about.

---

## Coordinator / VEIL FSM

The `VeilCoordinator` (feature = "coordinator") drives automatic obfuscator selection:

1. **Probing** — races top-K methods in parallel (happy-eyeballs stagger)
2. **Scoring** — per-network SQLite-backed scores (`PersistentScores`)
3. **Selection** — EWMA success rate − recent failure penalty − latency penalty + recency bonus
4. **Degradation** — transport failures trigger re-probe; hard blocks (fingerprint_blocked) rotate immediately
5. **Cooldown** — all-probes-failed → wait → retry from Idle

Registered methods: `Obfs4` (0), `WebTunnel` (1), `Masque` (2), `VeilFront` (3).

## Build & Test

```bash
cargo build                           # default (no TLS/WebTunnel)
cargo build --features tls            # obfs4 client
cargo build --features webtunnel      # WebTunnel client
cargo build --features utls           # VeilFront client (uTLS)
cargo build --features coordinator    # VEIL FSM orchestrator
cargo build --features metrics        # Prometheus metrics (relay)

cargo build --features tls,webtunnel,utls,coordinator  # all client features

cargo test                            # unit tests
cargo test --test '*'                 # E2E integration tests

# Cross-compilation
cargo build --release --target aarch64-unknown-linux-gnu   # Raspberry Pi relays
cargo build --release --target aarch64-apple-ios           # iOS (via construct-core)
```

## Usage

### obfs4 client
```rust
use construct_veil::{ClientConfig, Obfs4Stream};

let config = ClientConfig::from_bridge_cert("base64_bridge_cert")?;
let mut stream = Obfs4Stream::connect("relay.example.com:443", config).await?;
// stream implements AsyncRead + AsyncWrite — pass to tonic/hyper
```

### obfs4 server
```rust
use construct_veil::{ServerConfig, Obfs4Listener};

let config = ServerConfig::generate();
println!("Bridge cert: {}", config.bridge_cert()); // distribute to clients
let listener = Obfs4Listener::bind("0.0.0.0:443", config).await?;
while let Ok((stream, addr)) = listener.accept().await {
    tokio::spawn(async move { /* handle(stream) */ });
}
```

### VEIL coordinator (auto-select)
```rust
use construct_veil::veil::{
    VeilCoordinator, VeilConfig, MethodSet, NetworkFingerprint,
    scoring::PersistentScores,
    Obfs4Obfuscator, WebTunnelObfuscator, VeilFrontObfuscator,
};

let scores = PersistentScores::open_default("scores.db").await?;
let mut coordinator = VeilCoordinator::new(VeilConfig::default(), scores);
coordinator.register(Box::new(Obfs4Obfuscator::new()));
coordinator.register(Box::new(WebTunnelObfuscator::new()));
#[cfg(feature = "utls")]
coordinator.register(Box::new(VeilFrontObfuscator::new()));

let result = coordinator.start_session_with_params(
    "ice.example.com:443".into(),
    "cert=... iat-mode=1".into(),
    NetworkFingerprint::new(ssid_hash),
    MethodSet::all(),
    "ice.example.com".into(),  // TLS SNI
    spki_hex.into(),           // SPKI pin
    "".into(),                 // host header (WebTunnel)
    "/construct-veil".into(),  // WS path (WebTunnel)
).await?;

println!("Active on 127.0.0.1:{} via {}", result.port, result.method);
```

## Testing

```bash
# Run all tests (unit + E2E + doctests)
cargo test --workspace --features utls,coordinator

# Run only Go cross-reference vector tests
cargo test go_reference

# Run E2E integration tests
cargo test --test '*'
```

## References

- [obfs4 spec](https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt)
- [Elligator2 paper](https://elligator.cr.yp.to/elligator-20130828.pdf)
- [Go reference implementation](https://gitlab.com/yawning/obfs4)
- [curve25519-elligator2](https://docs.rs/curve25519-elligator2)
- [veil-front protocol sketch](../construct-docs/raw/02_Core_Crypto/protocols/OBFUSCATION_PROTOCOL_SKETCH_veil-front.md)
- [veil-front implementation plan](../construct-docs/raw/02_Core_Crypto/protocols/OBFUSCATION_IMPLEMENTATION_PLAN_veil-front.md)
