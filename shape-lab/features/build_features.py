#!/usr/bin/env python3
"""Ступень 3 (features): записи CSV -> вектор признаков на ВИЗИТ.

Единица классификации — визит (episode): весь трафик одного клиента к origin
за окно захвата, а НЕ отдельный TCP-поток. Именно визит оценивает цензор.
Число TCP-потоков само становится признаком (реальный браузер: много коротких;
VEIL: один долгий) — это, по гипотезе, один из сильнейших телл-сигналов.

Идентификатор: session = "<tag>#<stream>", где tag = "<label>__<runid>".
visit = tag; label = часть tag до "__".

Вход: один или несколько records-CSV (из extract). Выход: features CSV, строка на визит.
"""
import argparse, csv, sys
from collections import defaultdict
import numpy as np

# LENGTH_BUCKETS из construct_veil_protocol — по ним же выравнивает кадры шейпер.
BUCKETS = [64,128,192,256,384,512,768,1024,1536,2048,3072,4096,6144,8192,12288,16384]
FFT_DT = 0.010          # 10 мс сетка для детектора периодичности (chaff)
BURST_GAP = 0.050       # >50 мс тишины разделяет пачки

def bucket_hist(sizes):
    h = np.zeros(len(BUCKETS))
    for s in sizes:
        idx = min(np.searchsorted(BUCKETS, s), len(BUCKETS) - 1)
        h[idx] += 1
    return h / h.sum() if h.sum() else h

def periodicity(ts):
    """Доля мощности в доминирующем не-DC пике спектра ряда событий.
    Ровный chaff/keepalive с фиксированной каденцией -> резкий пик ~1.0."""
    if len(ts) < 8:
        return 0.0, 0.0
    t0, t1 = min(ts), max(ts)
    n = int((t1 - t0) / FFT_DT) + 1
    if n < 8 or n > 2_000_000:
        return 0.0, 0.0
    series = np.zeros(n)
    for t in ts:
        series[int((t - t0) / FFT_DT)] += 1
    series -= series.mean()
    spec = np.abs(np.fft.rfft(series)) ** 2
    if len(spec) < 2 or spec[1:].sum() == 0:
        return 0.0, 0.0
    k = 1 + int(np.argmax(spec[1:]))
    freq = k / (n * FFT_DT)
    return float(spec[k] / spec[1:].sum()), float(freq)

def bursts(ts):
    if len(ts) < 2:
        return 0, 0.0
    d = np.diff(np.sort(ts))
    gaps = d[d > BURST_GAP]
    return int(len(gaps) + 1), float(gaps.mean()) if len(gaps) else 0.0

def visit_features(rows):
    up = [r for r in rows if r["dir"] == "up"]
    dn = [r for r in rows if r["dir"] == "down"]
    up_ts = np.array([r["ts"] for r in up]); dn_ts = np.array([r["ts"] for r in dn])
    up_sz = [r["record_len"] for r in up]; dn_sz = [r["record_len"] for r in dn]
    all_ts = np.array([r["ts"] for r in rows])
    streams = set(r["session"] for r in rows)
    dur = float(all_ts.max() - all_ts.min()) if len(all_ts) else 0.0
    bu, bd = sum(up_sz), sum(dn_sz)
    pu_peak, pu_freq = periodicity(up_ts)
    nb_up, gap_up = bursts(up_ts)
    def iat(t):
        t = np.sort(t)
        return (float(np.diff(t).mean()), float(np.diff(t).std())) if len(t) > 1 else (0.0, 0.0)
    iu_m, iu_s = iat(up_ts); id_m, id_s = iat(dn_ts)
    f = {
        "n_streams": len(streams), "duration": dur,
        "n_up": len(up), "n_down": len(dn),
        "bytes_up": bu, "bytes_down": bd,
        "ratio_up_down": bu / bd if bd else 0.0,
        "rec_up_mean": float(np.mean(up_sz)) if up_sz else 0.0,
        "rec_up_std": float(np.std(up_sz)) if up_sz else 0.0,
        "rec_down_mean": float(np.mean(dn_sz)) if dn_sz else 0.0,
        "rec_down_std": float(np.std(dn_sz)) if dn_sz else 0.0,
        "iat_up_mean": iu_m, "iat_up_std": iu_s,
        "iat_down_mean": id_m, "iat_down_std": id_s,
        "period_up_peak": pu_peak, "period_up_freq": pu_freq,
        "n_bursts_up": nb_up, "burst_gap_up_mean": gap_up,
    }
    for i, v in enumerate(bucket_hist(up_sz)):
        f[f"hu_{BUCKETS[i]}"] = float(v)
    for i, v in enumerate(bucket_hist(dn_sz)):
        f[f"hd_{BUCKETS[i]}"] = float(v)
    return f

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("records", nargs="+", help="один или несколько records-CSV")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    by_visit = defaultdict(list)
    for path in a.records:
        with open(path) as fh:
            for r in csv.DictReader(fh):
                r["ts"] = float(r["ts"]); r["record_len"] = int(r["record_len"])
                visit = r["session"].split("#")[0]
                by_visit[visit].append(r)
    out_rows = []
    for visit, rows in sorted(by_visit.items()):
        label = visit.split("__")[0]
        feat = {"visit": visit, "label": label}
        feat.update(visit_features(rows))
        out_rows.append(feat)
    if not out_rows:
        raise SystemExit("no visits parsed")
    cols = list(out_rows[0].keys())
    fh = open(a.out, "w", newline="") if a.out else sys.stdout
    w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); w.writerows(out_rows)
    if a.out: fh.close()
    sys.stderr.write(f"{len(out_rows)} visits, {len(cols)-2} features, "
                     f"labels={sorted(set(r['label'] for r in out_rows))}\n")

if __name__ == "__main__":
    main()
