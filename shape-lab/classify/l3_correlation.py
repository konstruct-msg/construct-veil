#!/usr/bin/env python3
"""Ступень 4b (L3/M2): можно ли связать двух собеседников по трафику.

Гейт (spec M2): «преимущество сопоставления» пар над случайным ~ 0. Аналитик,
видящий N визитов, пытается по сдвиговой кросс-корреляции найти, кто с кем.
A шлёт (up) -> партнёр получает (down) с задержкой сети/relay -> корреляция
A.up с B.down на некотором лаге. Если истинный партнёр стабильно в топе — утечка L3.

Конвенция меток: visit tag = "pair-<pairid>-<role>__<runid>", role in {A,B}.
Метрики: доля A, чей top-1 по корреляции == истинный B (baseline = 1/(N-1));
средний нормированный ранг истинного партнёра (0.5 = шум).
"""
import argparse, csv, sys
from collections import defaultdict
import numpy as np

DT = 0.020          # 20 мс сетка
MAX_LAG = 2.0       # искать сдвиг до ±2 c

def series(ts, t0, t1):
    n = int((t1 - t0) / DT) + 1
    s = np.zeros(max(n, 1))
    for t in ts:
        i = int((t - t0) / DT)
        if 0 <= i < len(s):
            s[i] += 1
    return s - s.mean()

def max_xcorr(a, b, max_lag_bins):
    if a.std() == 0 or b.std() == 0:
        return 0.0
    a = a / (np.linalg.norm(a) + 1e-9); b = b / (np.linalg.norm(b) + 1e-9)
    full = np.correlate(a, b, mode="full")
    mid = len(b) - 1
    lo, hi = mid - max_lag_bins, mid + max_lag_bins + 1
    return float(np.max(np.abs(full[max(0, lo):hi])))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records", nargs="+")
    a = ap.parse_args()
    rows = []
    for p in a.records:
        for r in csv.DictReader(open(p)):
            r["ts"] = float(r["ts"]); rows.append(r)
    # визит -> {up:[ts], down:[ts]}, pairid, role
    visits = defaultdict(lambda: {"up": [], "down": []})
    meta = {}
    for r in rows:
        v = r["session"].split("#")[0]
        visits[v][r["dir"]].append(r["ts"])
        tag = v.split("__")[0]              # pair-<id>-<role>
        parts = tag.split("-")
        if len(parts) >= 3 and parts[0] == "pair":
            meta[v] = (parts[1], parts[2])  # (pairid, role)
    A = [v for v in visits if meta.get(v, ("", ""))[1] == "A"]
    B = [v for v in visits if meta.get(v, ("", ""))[1] == "B"]
    if not A or not B:
        raise SystemExit("нужны визиты с ролями A и B (метки pair-<id>-<role>)")
    allts = [t for v in visits.values() for d in v.values() for t in d]
    t0, t1 = min(allts), max(allts)
    lag_bins = int(MAX_LAG / DT)
    up = {v: series(visits[v]["up"], t0, t1) for v in A}
    dn = {v: series(visits[v]["down"], t0, t1) for v in B}
    hits, ranks = 0, []
    for va in A:
        true_id = meta[va][0]
        scored = sorted(((max_xcorr(up[va], dn[vb], lag_bins), vb) for vb in B), reverse=True)
        order = [vb for _, vb in scored]
        true_b = [vb for vb in B if meta[vb][0] == true_id]
        if not true_b:
            continue
        rank = order.index(true_b[0])
        ranks.append(rank / max(len(B) - 1, 1))
        hits += (rank == 0)
    n = len(ranks)
    print(f"pairs A={len(A)} B={len(B)}")
    print(f"top-1 match rate = {hits/n:.3f}  (random baseline = {1/max(len(B)-1,1):.3f})")
    print(f"mean normalized rank of true partner = {np.mean(ranks):.3f}  (0.5 = noise/shum)")
    adv = hits/n - 1/max(len(B)-1, 1)
    print(f"matching advantage over random = {adv:+.3f}  "
          f"({'LEAK (L3)' if adv > 0.1 else 'ok (near noise)'})")

if __name__ == "__main__":
    main()
