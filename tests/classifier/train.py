"""M4 sub-test 4 — train xgboost + lightgbm, report attacker-best accuracy.

Usage:
    python train.py path/to/dataset.ndjson [--out results.json]

Exit codes:
    0  PASS                       (attacker-best holdout < 0.55)
    1  REDESIGN_OR_JUSTIFY / FAIL (attacker-best holdout >= 0.55)
    2  No supported model installed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)

sys.path.insert(0, str(Path(__file__).parent))
from features import load_dataset  # noqa: E402

SEED = 0xC0FFEE
PASS_THRESHOLD = 0.55
FAIL_THRESHOLD = 0.65


def verdict(acc: float) -> tuple[str, str]:
    if acc < PASS_THRESHOLD:
        return (
            "PASS",
            f"Attacker-best holdout = {acc:.4f} < {PASS_THRESHOLD}. "
            "Indistinguishability holds; advance past M4.",
        )
    if acc >= FAIL_THRESHOLD:
        return (
            "FAIL",
            f"Attacker-best holdout = {acc:.4f} >= {FAIL_THRESHOLD}. "
            "Gate is fingerprintable — redesign required (plan §M4).",
        )
    return (
        "REDESIGN_OR_JUSTIFY",
        f"Attacker-best holdout = {acc:.4f} in [{PASS_THRESHOLD}, "
        f"{FAIL_THRESHOLD}). Document justification or redesign (plan §M4).",
    )


def train_one(name, model, X_tr, X_te, y_tr, y_te, X, y):
    model.fit(X_tr, y_tr)
    holdout = float(model.score(X_te, y_te))
    cv_scores = cross_val_score(
        model,
        X,
        y,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED),
        scoring="accuracy",
    )
    return {
        "model": name,
        "holdout_accuracy": holdout,
        "cv_mean": float(cv_scores.mean()),
        "cv_std": float(cv_scores.std()),
        "cv_scores": [float(x) for x in cv_scores],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset", type=Path, help="NDJSON dataset (see README.md)")
    ap.add_argument("--out", type=Path, default=Path("results.json"))
    args = ap.parse_args()

    X, y = load_dataset(args.dataset)
    n, d = X.shape

    classes, counts = np.unique(y, return_counts=True)
    if len(classes) < 2:
        print(
            f"ERROR: dataset has only one class ({classes.tolist()}); "
            "need both label=0 and label=1 rows.",
            file=sys.stderr,
        )
        sys.exit(2)

    if n < 200:
        print(
            f"WARNING: only {n} rows — plan §M4 calls for >=1000 connections. "
            "Verdict below is not authoritative.",
            file=sys.stderr,
        )

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )

    runs = []
    try:
        from xgboost import XGBClassifier

        runs.append(
            train_one(
                "xgboost",
                XGBClassifier(
                    n_estimators=200,
                    max_depth=6,
                    random_state=SEED,
                    eval_metric="logloss",
                    n_jobs=-1,
                    tree_method="hist",
                ),
                X_tr,
                X_te,
                y_tr,
                y_te,
                X,
                y,
            )
        )
    except ImportError:
        print("xgboost not installed, skipping", file=sys.stderr)

    try:
        from lightgbm import LGBMClassifier

        runs.append(
            train_one(
                "lightgbm",
                LGBMClassifier(
                    n_estimators=200,
                    max_depth=6,
                    random_state=SEED,
                    n_jobs=-1,
                    verbose=-1,
                ),
                X_tr,
                X_te,
                y_tr,
                y_te,
                X,
                y,
            )
        )
    except ImportError:
        print("lightgbm not installed, skipping", file=sys.stderr)

    if not runs:
        print(
            "Neither xgboost nor lightgbm available. Install requirements.txt.",
            file=sys.stderr,
        )
        sys.exit(2)

    attacker_best = max(runs, key=lambda r: r["holdout_accuracy"])
    label, note = verdict(attacker_best["holdout_accuracy"])

    report = {
        "n_samples": int(n),
        "n_features": int(d),
        "class_balance": {int(c): int(k) for c, k in zip(classes, counts)},
        "seed": SEED,
        "pass_threshold": PASS_THRESHOLD,
        "fail_threshold": FAIL_THRESHOLD,
        "runs": runs,
        "attacker_best_model": attacker_best["model"],
        "attacker_best_accuracy": attacker_best["holdout_accuracy"],
        "verdict": label,
        "note": note,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"Dataset: {args.dataset} | samples={n} features={d}")
    print(f"Class balance: {report['class_balance']}")
    for r in runs:
        print(
            f"  {r['model']:9s}  holdout={r['holdout_accuracy']:.4f}  "
            f"cv={r['cv_mean']:.4f} ± {r['cv_std']:.4f}"
        )
    print(
        f"\nAttacker-best: {attacker_best['model']} "
        f"@ {attacker_best['holdout_accuracy']:.4f}"
    )
    print(f"Verdict: {label}")
    print(note)
    print(f"Report written to {args.out}")

    sys.exit(0 if label == "PASS" else 1)


if __name__ == "__main__":
    main()
