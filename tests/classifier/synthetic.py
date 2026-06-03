"""Synthetic dataset generator — smoke-tests the harness pipeline.

NOT a substitute for real packet captures. The plan (§M4 sub-test 4)
requires >=1000 real connections against a deployed cover application.
This script exists so train.py can be exercised before the capture
pipeline lands.

Two modes:
  --mode indistinguishable   both classes sampled from the same
                             distribution. train.py should report
                             holdout ≈ 0.50 and verdict PASS.

  --mode distinguishable     class 1 has a visibly different byte and
                             timing distribution. train.py should report
                             holdout >> 0.65 and verdict FAIL.

Use both runs to verify that the harness can both pass and fail correctly.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import numpy as np

MAX_BYTES = 32_768


def gen_row(rng: np.random.Generator, label: int, distinguishable: bool) -> dict:
    if distinguishable and label == 1:
        first_bytes = rng.integers(0, 128, size=MAX_BYTES, dtype=np.uint8).tobytes()
        n_recs = int(rng.integers(40, 80))
        irt = rng.exponential(2.0, size=n_recs)
        rlen = rng.integers(800, 1400, size=n_recs)
        latency = float(rng.normal(15.0, 3.0))
    else:
        first_bytes = rng.integers(0, 256, size=MAX_BYTES, dtype=np.uint8).tobytes()
        n_recs = int(rng.integers(20, 60))
        irt = rng.exponential(8.0, size=n_recs)
        rlen = rng.integers(200, 1500, size=n_recs)
        latency = float(rng.normal(40.0, 10.0))

    irt[0] = 0.0
    return {
        "label": int(label),
        "first_bytes_b64": base64.b64encode(first_bytes).decode("ascii"),
        "record_lengths": [int(x) for x in rlen],
        "inter_arrival_ms": [float(x) for x in irt],
        "first_response_latency_ms": latency,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--mode",
        choices=["indistinguishable", "distinguishable"],
        required=True,
    )
    ap.add_argument(
        "--n",
        type=int,
        default=1000,
        help="Total rows (split 50/50 between classes). Default: 1000.",
    )
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=0xBEEF)
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    distinguishable = args.mode == "distinguishable"
    per_class = args.n // 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        for label in (0, 1):
            for _ in range(per_class):
                f.write(json.dumps(gen_row(rng, label, distinguishable)) + "\n")

    print(
        f"Wrote {per_class * 2} rows ({args.mode}) to {args.out}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
