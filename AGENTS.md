# AGENTS.md — construct-ice

Context for AI agents working in this repository.

---

## What is construct-ice?

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

## Shared Construct Docs Workflow

These instructions apply to GitHub Copilot, Codex, OpenCode, and similar coding agents.

### Division of labour — read this first

| Role | Tool | Responsibility |
|------|------|----------------|
| **Coding agent** (you) | Copilot / Codex | Write code + drop raw session notes into `wiki/sessions/` and `wiki/decisions/`. That is all. |
| **Wiki pipeline** | `obsidian-llm-wiki-local` (olw) | Reads `raw/`, synthesizes concepts, creates/updates wiki articles, generates cross-links. |
| **Developer** | Human + Obsidian | Reviews wiki draft articles, approves/rejects. Curates `raw/`. |

**Your job is code.** olw handles article synthesis. Write plain-markdown session notes; let the pipeline do the rest.

### Shared knowledge base

- Vault: `/Users/maximeliseyev/Code/constrcut-docs`
- `raw/` — source corpus. Do **not** rewrite or reorganize.
- `wiki/` — canonical curated knowledge base. **Read** from here before architectural work.
- `wiki/.drafts/` — **reserved for olw**. Never write here manually.
- `wiki/sessions/` — where coding agents write session notes.
- `wiki/decisions/` — where coding agents write long-lived decision records.

### Where to save durable reasoning

After any session involving architectural changes, design decisions, API changes, or non-obvious implementation choices:

1. **Always** create or update `wiki/sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `# Why` — reasoning, alternatives considered, why rejected. Most important section.
3. If the decision constrains future work, also create `wiki/decisions/<topic>.md`.
4. Session notes: plain markdown, **no YAML frontmatter, no `[[wikilinks]]`** — olw adds those.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `wiki/log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`

