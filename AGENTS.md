# AGENTS.md — construct-veil

The rules this project paid for in its first year, and the invariants of this repository. Each
line is here because breaking it already cost something; the incident behind it lives in the
vault. If a rule here and your plan disagree, the rule wins until a `decisions/` note says
otherwise.

`construct-veil` is the anti-censorship transport of Construct Messenger: the **veil-front**
client (coordinator, adapter, C FFI linked into construct-core), the wire protocol
(`crates/construct-veil-protocol`) and the relay (`crates/construct-veil-relay`). obfs4 and
WebTunnel were removed on 2026-10-22; do not bring them back without a new decision.

## Read first

| Area | File |
|---|---|
| Why these rules exist | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Source layout | `README.md`, "Source layout" |
| veil-front only (obfs4 retired) | `~/Code/construct-docs/decisions/veil-front-only-retire-obfs4.md` |
| Front coordinates, delivery, logs | `~/Code/construct-docs/decisions/` — `veil-front-coordinates-are-not-public.md` · `veil-front-delivery-is-link-voucher.md` · `veil-front-in-logs-is-a-keyed-label.md` · `veil-front-topup-keep-two-usable.md` |
| Redundancy plan | `~/Code/construct-docs/decisions/veil-front-redundancy-execution-plan.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) · `security/` for VEIL |

Layout: `src/ffi.rs` (C ABI: `veil_start`, `veil_front_ferry_fd`, …) · `src/veil/` (coordinator
FSM, scoring, adapter) · `src/tls_pinned.rs` (SPKI-pinned rustls connector).

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md` — change it there first.

## Rules

1. **Prior art first.** Before any obfuscation or transport mechanism, write down what Tor,
   V2Ray / Reality, Snowflake or QUIC-based circumvention do and why we deviate.
2. **The core decides.** Session and crypto decisions belong to `construct-core`; veil moves bytes
   and decides only transport (which front, scoring, failover). It never touches ratchet or
   session state.
3. **Frames and handshakes name the state they mean** (AUTH version, ticket, capability). A fix
   that adds a timer or retry budget in place of an address is a signal to stop.
4. **Reproduce before fixing.** Every fix carries a regression test that fails on the old code.
5. **One meaning, one carrier.** A constant two crates must agree on lives in one place
   (`crates/construct-veil-protocol`); a comment saying "must match" means one should call the other.
6. **Bytes stay bytes** across the C ABI and the wire; no base64/JSON for binary payloads.
7. **Measure, then build.** Five obfuscation designs preceded the measurement that settled the
   question. A new mechanism needs a measurement on the real path first.
8. **Verify the effect, not the exit code:** a connection by traffic observed on the wire, a relay
   deploy by the version it reports.
9. **A test must be able to fail.** Put the decision in a pure function, test that, and
   mutation-check new tests (one mutation at a time, an unapplied mutation is fatal).
10. **Depth before breadth.** No new transport or front kind until the existing path is boring on
    a real device.
11. **A temporary exception has an end date and a check.**
12. **A branch and a PR, always** (see Git).

**A change on the delivery path answers three questions** in its commit message: (1) what does
the relay, a front or an observer learn that it did not before (including SNI, timing, sizes);
(2) what can a party withhold or substitute that it could not before; (3) which trust boundary
moves, and which way. An honest "something" to 1 or 2 is a `decisions/` note, not a merge.

**A producer with no consumer is a defect:** a frame type, capability or FFI field lands with its
reader in the same change, or is removed.

## Invariants of this repo

- **`VeilStartRequest` / `VeilStartResult` are a C ABI the apps compile against:** never reorder
  or remove fields; retired fields stay and are ignored. (Apps and core are built separately.)
- **The SPKI pin is required on every client connection;** there is no unpinned production path.
- **Only veil-front.** obfs4 and WebTunnel stay removed (decision `veil-front-only-retire-obfs4`).
- **Front coordinates are not public and appear in logs only as a keyed label** (the
  `veil-front-*` decisions above).

## Build and test

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo check --features ffi --target aarch64-apple-ios
```

## Git and process

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from an up-to-date
  `main`, PR into `main`; `main` is what a release is built from. Agents push and open the PR only
  when asked.
- Check `git branch --show-current` and `git status` before every commit: other sessions share the
  tree. Never `checkout -- .`, `restore .`, `reset --hard` or `stash`; name the files. Never
  rewrite pushed history. A commit made on `main` by mistake and not pushed moves with
  `git branch <topic> && git reset --keep origin/main && git switch <topic>`.
- The vault holds all documentation. After work: progress into the task note, a
  `decisions/<slug>.md` for anything that constrains future work, one line in `log.md`
  (`[YYYY-MM-DD HH:MM] note | <topic>`).
