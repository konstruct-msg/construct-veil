# construct-veil

**VEIL** — *Variable Encoded Interface Layer.*

Anti-censorship transport for Construct Messenger. The client reaches the
Construct backend through **veil-front**: a standard TLS 1.3 connection to an
honest HTTPS front. The front serves its real site to everyone; only a client
that presents a valid capability in its first application data is tunnelled to
the backend.

obfs4 and WebTunnel were the transports before veil-front. They were retired
on 2026-06-12, after obfs4 turned out to be cut by Russian DPI, and their code
was removed on 2026-10-22. The last revision that has it is the parent of the
removal commit.

## Workspace

```
construct-veil/
├── src/                          ← client: coordinator, veil-front adapter, C FFI
├── crates/
│   ├── construct-veil-protocol/  ← wire protocol: frames, varint, tickets, capabilities, AUTH
│   └── construct-veil-relay/     ← the relay: TLS gate, tunnel, cover-site forward
└── deploy/                       ← relay images and compose files
```

## Data path

```
[app gRPC] ↔ 127.0.0.1:PORT ↔ [veil-front client] ~~~ TLS 1.3 (honest SNI, SPKI pin) ~~~ [relay]
                                                         ├─ valid AUTH → h2c backend (Construct)
                                                         └─ anything else → cover site (deploy/COVER.md)
```

AUTH is bound to the TLS exporter of the session, so a recorded AUTH record is
useless on another connection. Two forms are accepted: v2 (a bearer ticket with
an HMAC authcode) and v3 (a key-bound capability signed by the issuer, plus the
client's signature over the exporter).

On iOS and Android the TLS session can be owned by the platform (NWConnection,
Conscrypt) for a native ClientHello; the app then hands the decrypted duplex to
`veil_front_ferry_fd`. Otherwise the client uses rustls with a browser-shaped
profile (`TlsProfile`).

## Source layout

```
src/
├── lib.rs
├── ffi.rs                      ← C ABI: veil_start/stop/is_alive/port/last_error, veil_front_ferry_fd
├── accept.rs                   ← accept() error back-off
├── tls_fingerprint.rs          ← ClientHello profiles (Chrome 131, Firefox 128)
├── tls_pinned.rs               ← SPKI-pinned rustls connector
└── veil/
    ├── coordinator.rs          ← VeilCoordinator: runs the FSM, probes, local proxy
    ├── fsm/                    ← pure reducer: states, events, effects, candidate scoring
    ├── scoring.rs              ← PersistentScores: per-network scores in SQLite
    ├── obfuscator.rs           ← Obfuscator trait, ProbeRequest, ObfuscatorError
    ├── veil_front_adapter.rs   ← VeilFrontObfuscator: probe + ferry
    ├── veil_front/             ← session framing and Mode 0 chaff
    └── diag.rs                 ← last-error sink behind veil_last_error

crates/construct-veil-protocol/src/
├── varint.rs  framing.rs       ← frame codec (AUTH / DATA / CHAFF)
├── ticket.rs  auth.rs          ← AUTH v2: ticket + exporter-bound authcode
└── capability.rs               ← AUTH v3: issuer-signed capability, client signature

crates/construct-veil-relay/src/
├── main.rs                     ← accept loop, limits, timeouts
├── tls.rs                      ← TLS server config
├── gate.rs                     ← first-record gate: AUTH → tunnel, otherwise → site
├── tunnel.rs                   ← client frames ↔ backend h2c
├── site.rs                     ← cover-site forward
├── chain.rs  upstream_tls.rs   ← relay → relay chaining
└── bin/make_config_link.rs     ← signed konstruct://veil-config links
```

## Coordinator

`VeilCoordinator` (feature `coordinator`) is an FSM that races the registered
methods, keeps per-network scores, and serves the winner on a local port.
veil-front is the only registered method today. `MethodId` still lists obfs4,
WebTunnel and MASQUE: their numbers are stored in the scores database and in the
`allowed_methods` bitmask of `VeilStartRequest`.

## Features

| Feature | What it adds |
|---------|--------------|
| `tls` | rustls and the ClientHello profiles (`TlsProfile`) |
| `utls` | `tls` + JA3 helpers |
| `coordinator` | the FSM, scoring (SQLite) and the veil-front adapter; implies `utls` |
| `ffi` | the C ABI; implies `coordinator`. This is what construct-core links |

## Build & test

```bash
cargo test --workspace --all-features
cargo check --features ffi --target aarch64-apple-ios
```

## References

- `construct-docs/decisions/veil-front-only-retire-obfs4.md`
- `construct-docs/cryptocore/OBFUSCATION_PROTOCOL_SKETCH_veil-front.md`
- `deploy/README.md`: running a relay

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
