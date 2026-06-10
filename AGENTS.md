# AGENTS.md — construct-veil

Context for AI agents working in this repository.

---

## What is construct-veil?

obfs4 pluggable transport implementation in Rust for Construct Messenger.
Makes gRPC traffic indistinguishable from random noise — DPI resistance for Iran, China, Russia.
Used by `construct-relay` (server-side) and `construct-core` FFI bindings (client-side).

---

## Architecture

```
src/
├── lib.rs              — Public surface: Obfs4Stream, Obfs4Listener
├── crypto/             — ntor handshake crypto, KDF, Elligator2
├── handshake/          — Client + server handshake state machines
├── framing/            — Frame encoder/decoder (NaCl secretbox + SipHash OFB length obf)
├── transport/          — AsyncRead/AsyncWrite transport wrappers
├── iat.rs              — Inter-arrival timing jitter (IAT mode)
├── replay_filter.rs    — Replay attack prevention
├── tls_fingerprint.rs  — TLS fingerprint randomization
├── tls_pinned.rs       — TLS pinning for client connections
├── traffic_mode.rs     — Protocol polymorphism (PRNG seed re-keying)
├── ffi.rs              — FFI bindings (used by construct-core UniFFI)
└── metrics.rs          — Prometheus metrics (feature = "metrics")
```

### Protocol polymorphism

Every connection is cryptographically distinct via PRNG seed re-keying:
after handshake, both sides exchange a `PrngSeed` frame → re-derive IAT RNG + SipHash key.
This defeats ML-based DPI classifiers that train on frame length distributions.

---

## Build & Test

```bash
cargo build                        # default build
cargo build --features metrics     # with Prometheus metrics
cargo test                         # unit tests
cargo test --test '*'              # integration tests (echo, multi-round-trip, etc.)

# Cross-compilation
cargo build --release --target aarch64-unknown-linux-gnu   # for Raspberry Pi relays
```

---

## Key conventions

- `Obfs4Stream` and `Obfs4Listener` are the only public API — keep the surface small
- All handshake vectors are cross-tested against the Go reference implementation
- `ffi.rs` exposes `Obfs4Connect` / `Obfs4Accept` for construct-core UniFFI
- Never disable the replay filter — it prevents connection replay attacks

---
---

## Documentation

All project documentation: `~/Code/construct-docs` (Obsidian vault).
**Authoritative map + writing rules: `~/Code/construct-docs/AGENTS.md`** (read it before contributing
docs). The vault is a flat domain-folder structure — there is no `raw/` or `wiki/` anymore.

### Vault layout (top-level domain folders)

| Folder | Holds |
|--------|-------|
| `overview/` | Vision, philosophy, high-level project overview |
| `architecture/` | Service map, data flows, server infrastructure, design principles |
| `backend/` | Server service-specific docs (auth, messaging, federation) |
| `client/` | Client docs (iOS, Android, desktop, shared); specs in `client/specs/` |
| `cryptocore/` | Crypto protocol specs and key management |
| `security/` | Security model, threat model, VEIL anti-censorship |
| `deployment/` · `testing/` · `compliance/` · `whitepaper/` | as named |
| `sessions/` | Session logs (this is where your session notes go) |
| `decisions/` | Architectural decision records (ADRs) |
| `_archive/` | Superseded docs — read-only |

### Where to save durable reasoning

After any session involving architectural changes, design decisions, API changes, or non-obvious implementation choices:

1. **Always** create or update `sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `# Why` — reasoning, alternatives considered, why rejected. Most important section.
3. If the decision constrains future work, also create `decisions/<topic>.md`.
4. Session notes: plain markdown, **no YAML frontmatter, no `[[wikilinks]]`** — olw adds those.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`
