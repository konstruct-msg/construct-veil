# AGENTS.md — construct-veil

Context for AI agents working in this repository.

---

## What is construct-veil?

The anti-censorship transport of Construct Messenger: the **veil-front** client
(coordinator, adapter, C FFI linked into construct-core), the wire protocol
(`crates/construct-veil-protocol`) and the relay (`crates/construct-veil-relay`).
obfs4 and WebTunnel were removed on 2026-10-22 (decision `veil-front-only-retire-obfs4`);
do not bring them back without a new decision.

---

## Architecture

See README.md, "Source layout". In short:

```
src/ffi.rs                 — C ABI the apps call (veil_start, veil_front_ferry_fd, …)
src/veil/                  — coordinator FSM, scoring, veil-front adapter
src/tls_pinned.rs          — SPKI-pinned rustls connector (pin is mandatory)
crates/construct-veil-protocol — frames, tickets, capabilities, AUTH v2/v3
crates/construct-veil-relay    — the relay binary
```

---

## Build & Test

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check --features ffi --target aarch64-apple-ios
```

---

## Key conventions

- `VeilStartRequest` / `VeilStartResult` are a C ABI the apps compile against: never
  reorder or remove fields; retired fields stay and are ignored.
- The SPKI pin is required on every client connection; there is no unpinned
  production path.
- Every fix carries a regression test that fails on the old code.

---
## Documentation

All project documentation: `~/Code/construct-docs` (Obsidian vault).
**Authoritative map + writing rules: `~/Code/construct-docs/AGENTS.md`** (read it before contributing
docs). The vault is a flat domain-folder structure.

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
4. Session notes: plain markdown, no YAML frontmatter; `[[wikilinks]]` to other notes are welcome.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`

## Git workflow (branch + PR only)

**Never commit on `main`.** Every change goes on a topic branch cut from an up-to-date `main`
(`feat|fix|docs|chore|test/<topic>`) and lands through a GitHub pull request. Agents push and
open the PR only when asked.

`main` is what a release is built from, so it moves only by a reviewed merge. From 2026-09-11 to
2026-10-01 changes went straight to `main` across the construct-* repos — two people on the
project made a branch per change look like ceremony. That was reversed on purpose: the habit has
to be in place before there is a release for it to break.

A commit that landed on `main` by mistake and is not pushed moves off it with
`git branch <topic> && git reset --keep origin/main && git switch <topic>`. Pushed history is
never rewritten.
