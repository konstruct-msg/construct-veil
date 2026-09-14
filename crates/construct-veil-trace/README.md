# veil-trace — the measurement rig

Every padding claim in this repo is a claim about **shape**: record sizes, their order, the gaps
between them. None of it had been measured. `mode0_front.rs` says "~33% overhead" and "zero added
latency (confirmed by on-device benchmark)" — a latency measurement answering a shape question.

This tool produces the shape, from a capture, without any key: the TLS record header is cleartext,
so record sizes and arrival times are recoverable by anyone on the path. That is the adversary's
view, and it is the only view worth arguing with.

Background: construct-docs `decisions/veil-external-transport-review-2026-09` §2.8, §3.3.

## Use

```bash
# 1. capture (needs root for BPF)
sudo tcpdump -i en0 -s 0 -w /tmp/veil-idle.pcap 'tcp port 443 and host <front>'

# 2. recover the record stream — the only step that touches the capture
cargo run -p construct-veil-trace --bin veil-trace -- parse /tmp/veil-idle.pcap > idle.jsonl

# 3. look at it before believing any number
cargo run -p construct-veil-trace --bin veil-trace -- summary idle.jsonl

# 4. how well the cheap classifiers separate two sets
cargo run -p construct-veil-trace --bin veil-trace -- compare idle.jsonl cover.jsonl
```

Traces are plain JSONL (`{"conn":0,"t":…,"dir":"up","len":261,"ct":23}`), so they archive and
re-analyse without keeping traffic around.

## What the numbers mean

**`separation` is ROC-AUC folded around 0.5.** 0.5 means the classifier did no better than a coin
flip; 1.0 means it never erred. Read the **top row** — an adversary uses the feature that works, and
an average across features hides it behind the ones that do not.

**A connection is one observation.** Records inside a connection are not independent draws; pooling
them is how a rig talks itself into a result. Everything is computed per connection, then
aggregated. Below 20 connections a side the output says `SUGGESTIVE ONLY`, and means it.

**There are no p-values here, on purpose.** "The test did not reject" is not "the distributions are
equal", and it is certainly not "the traffic is unclassifiable" (review §14). A low separation is
evidence that *these* classifiers failed on *these* captures. It is not a safety claim.

## What it does not do

- No decryption, and none needed — everything comes from the cleartext record header.
- No TLS fingerprinting. That is the ClientHello question (§3.1), measured by other means.
- The handshake is excluded from shape features: a certificate's size would drown out the session.
- A direction that desyncs or loses bytes is reported as broken. Discard those connections; a
  capture-induced short trace is not a quiet session.

## The three captures worth taking first

| Trace | Why |
|---|---|
| The cover site from a browser | The baseline. Everything else is "how far from this". |
| VEIL idle | Mode 0 tapers after 3s; what remains is keepalive every 120s. Is that a rhythm? |
| VEIL in conversation | Whether bucketing holds once real payload is flowing. |

The immediate question they settle is §3.1: the client pins `max_fragment_size` to the top length
bucket, and `NWProtocolTLS` has no equivalent. Capturing both tells us what moving to Apple's TLS
stack would cost in shape — which is the difference between a decision and an opinion.
