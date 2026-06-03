"""Feature extraction for the M4 sub-test 4 classifier.

Per plan §M4 sub-test 4, the feature set is:
- byte histogram of the first 32 KB of post-TLS application data (256 bins)
- inter-record timing CDF summary (count, mean, std, percentiles)
- record-length CDF summary (count, mean, std, percentiles)
- first-response-byte latency (scalar)

Total: 256 + 10 + 10 + 1 = 277 features per connection.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Sequence

import numpy as np

MAX_BYTES = 32_768
PERCENTILES = (10, 25, 50, 75, 90, 95, 99)
CDF_KEYS = ("count", "mean", "std") + tuple(f"p{p}" for p in PERCENTILES)


def byte_histogram(blob: bytes) -> np.ndarray:
    """Normalized 256-bin histogram over the first MAX_BYTES of `blob`."""
    arr = np.frombuffer(blob[:MAX_BYTES], dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float64)
    total = hist.sum()
    return hist / total if total > 0 else hist


def cdf_summary(values: Sequence[float], prefix: str) -> dict[str, float]:
    out = {f"{prefix}_{k}": 0.0 for k in CDF_KEYS}
    if not values:
        return out
    a = np.asarray(values, dtype=np.float64)
    out[f"{prefix}_count"] = float(len(a))
    out[f"{prefix}_mean"] = float(a.mean())
    out[f"{prefix}_std"] = float(a.std())
    for p in PERCENTILES:
        out[f"{prefix}_p{p}"] = float(np.percentile(a, p))
    return out


def extract(row: dict) -> np.ndarray:
    """Flatten one NDJSON row into a feature vector. See feature_names()."""
    raw = base64.b64decode(row["first_bytes_b64"])
    hist = byte_histogram(raw)
    irt = cdf_summary(row.get("inter_arrival_ms", []), "irt")
    rlen = cdf_summary(row.get("record_lengths", []), "rlen")
    flbl = float(row.get("first_response_latency_ms", 0.0))
    return np.concatenate(
        [
            hist,
            np.fromiter(irt.values(), dtype=np.float64, count=len(CDF_KEYS)),
            np.fromiter(rlen.values(), dtype=np.float64, count=len(CDF_KEYS)),
            np.array([flbl], dtype=np.float64),
        ]
    )


def feature_names() -> list[str]:
    names = [f"byte_hist_{i:03d}" for i in range(256)]
    names += [f"irt_{k}" for k in CDF_KEYS]
    names += [f"rlen_{k}" for k in CDF_KEYS]
    names += ["first_response_latency_ms"]
    return names


def load_dataset(path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    """Load an NDJSON dataset. Returns (X, y) as numpy arrays."""
    X: list[np.ndarray] = []
    y: list[int] = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {e}") from e
            if "label" not in row or "first_bytes_b64" not in row:
                raise ValueError(
                    f"{path}:{lineno}: row missing required field "
                    "('label' or 'first_bytes_b64'); see README.md schema"
                )
            X.append(extract(row))
            y.append(int(row["label"]))
    if not X:
        raise ValueError(f"{path}: empty dataset")
    return np.vstack(X), np.asarray(y, dtype=np.int64)
