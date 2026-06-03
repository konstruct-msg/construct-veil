# M4 sub-test 4 — constant-shape gate classifier

This is the **go/no-go test** for `veil-front` per
`OBFUSCATION_IMPLEMENTATION_PLAN_veil-front.md` §M4 sub-test 4. If a
gradient-boosted classifier trained on the first 32 KB of bytes from a
connection can distinguish tunnel sessions from cover-site sessions with
≥65 % accuracy, the gate is fingerprintable and the protocol must be
redesigned before proceeding past M4.

## Layout

| File | Purpose |
|---|---|
| `features.py` | Reads NDJSON dataset → flat feature vectors. |
| `train.py` | Trains xgboost + lightgbm, reports the **attacker-best** accuracy + verdict. |
| `synthetic.py` | Generates a synthetic NDJSON dataset for smoke-testing the pipeline before real captures exist. |
| `requirements.txt` | Python dependencies. |

## Verdict thresholds (per plan §M4)

| Attacker-best holdout accuracy | Verdict | Action |
|---|---|---|
| < 0.55 | **PASS** | Indistinguishability holds. Advance past M4. |
| 0.55 – 0.65 | **REDESIGN_OR_JUSTIFY** | Document why this band is acceptable, or rework the gate. |
| ≥ 0.65 | **FAIL** | Stop. The gate is fingerprintable. Redesign required. |

"Attacker-best" = the highest holdout accuracy across all models tried.
The defender does not get to pick the weakest classifier.

## Dataset schema (NDJSON, one row per connection)

```json
{
  "label": 0,
  "first_bytes_b64": "BASE64(≤32 KB of post-TLS-handshake application data)",
  "record_lengths": [1234, 567, 1500, ...],
  "inter_arrival_ms": [0.0, 1.7, 12.3, ...],
  "first_response_latency_ms": 18.4
}
```

| Field | Meaning |
|---|---|
| `label` | `0` = unauth branch (cover site: browser baseline OR random-probe), `1` = tunnel branch (valid veil-front client). Plan collapses (1) + (2) into class 0, (3) into class 1. |
| `first_bytes_b64` | Base64 of the first up to 32 768 bytes of decrypted application data after TLS handshake completes. Shorter is allowed; longer is truncated by `features.py`. |
| `record_lengths` | TLS record lengths in receive order, in bytes. Empty list allowed. |
| `inter_arrival_ms` | Milliseconds between successive TLS records (first entry should be 0). Same length as `record_lengths`. |
| `first_response_latency_ms` | Milliseconds from "client finished TLS handshake" to "first server byte of application data". |

The capture pipeline that produces this NDJSON is **not** part of this
harness — it lives wherever the real packet captures are produced
(suggested: a `tcpdump` + Python parser in the relay-ops repo). The
schema is the contract.

## Quick start (smoke test)

```bash
cd tests/classifier
pip install -r requirements.txt

# 1. Indistinguishable synthetic data → expect PASS (~50 % accuracy)
python synthetic.py --mode indistinguishable --n 1000 --out data/syn_pass.ndjson
python train.py data/syn_pass.ndjson --out results/syn_pass.json

# 2. Distinguishable synthetic data → expect FAIL (>>65 % accuracy)
python synthetic.py --mode distinguishable --n 1000 --out data/syn_fail.ndjson
python train.py data/syn_fail.ndjson --out results/syn_fail.json
```

If `syn_pass` reports `PASS` and `syn_fail` reports `FAIL`, the pipeline
is wired correctly. These synthetic runs are **not** acceptance evidence
for the protocol — only real packet captures against a deployed cover
application are.

## Real-run requirements (per plan §M4 sub-test 4)

- ≥ 1000 connections in total
- Mix of (1) browser w/ uTLS Chrome profile, no ticket; (2) `curl` with
  random first request; (3) valid veil-front tunnel client
- Captures made against the deployed M0 cover application — not a
  localhost dev relay
- Train/test split is stratified 80/20 with a fixed seed
  (`SEED = 0xC0FFEE`); 5-fold stratified CV is reported alongside
- Results committed to the repo as JSON evidence in `results/`
