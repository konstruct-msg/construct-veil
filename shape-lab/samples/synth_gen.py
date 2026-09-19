#!/usr/bin/env python3
"""Синтетические records-CSV для self-test пайплайна (НЕ реальные захваты).
Проверяем машинерию: стенд обязан (1) отличать заведомо разные классы,
(2) давать AUC~0.5 на negative control, (3) ловить кросс-корреляцию в парах
и не находить её у независимых. Это валидация СТЕНДА, не VEIL."""
import csv, random, sys, os
random.seed(7)
OUT = sys.argv[1] if len(sys.argv) > 1 else "."

def write(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["session","ts","dir","record_len","content_type"])
        w.writeheader(); w.writerows(rows)

def cover_visit(tag):
    """Браузер: несколько параллельных потоков, всплеск загрузки, потом уход."""
    rows = []; t = random.uniform(0, 1)
    for stream in range(random.randint(3, 8)):
        sess = f"{tag}#{stream}"
        st = t + random.uniform(0, 0.3)
        # запрос(ы) up, затем пачка крупных down (ассеты), затем тишина
        for _ in range(random.randint(1, 3)):
            rows.append(dict(session=sess, ts=st, dir="up", record_len=random.choice([200,300,500]), content_type="23"))
            st += random.uniform(0.001, 0.01)
        for _ in range(random.randint(10, 40)):
            rows.append(dict(session=sess, ts=st, dir="down", record_len=random.choice([1400,4096,8192,16384]), content_type="23"))
            st += random.uniform(0.0005, 0.005)
    return rows

def veil_visit(tag):
    """VEIL: один долгий поток, ровный chaff с фикс. каденцией + редкая переписка."""
    sess = f"{tag}#0"; rows = []; t = random.uniform(0, 1)
    end = t + random.uniform(30, 60)     # долгоживущий
    # ровный chaff каждые ~0.5с (детектор периодичности должен зажечься)
    ct = t
    while ct < end:
        rows.append(dict(session=sess, ts=ct, dir="up", record_len=random.choice([64,128]), content_type="23"))
        ct += 0.5 + random.uniform(-0.01, 0.01)
    # немного реальной переписки
    for _ in range(random.randint(5, 15)):
        mt = random.uniform(t, end)
        rows.append(dict(session=sess, ts=mt, dir="up", record_len=random.choice([256,512,1024]), content_type="23"))
        rows.append(dict(session=sess, ts=mt+0.05, dir="down", record_len=random.choice([256,512]), content_type="23"))
    return rows

def pair_visits(pairid, correlated):
    """A.up событие -> B.down через фикс. лаг (если correlated)."""
    a = f"pair-{pairid}-A__r#0"; b = f"pair-{pairid}-B__r#0"
    ra, rb = [], []; t0 = random.uniform(0, 1)
    events = sorted(random.uniform(t0, t0+40) for _ in range(30))
    for e in events:
        ra.append(dict(session=a, ts=e, dir="up", record_len=512, content_type="23"))
        bt = (e + 0.12) if correlated else random.uniform(t0, t0+40)  # лаг relay
        rb.append(dict(session=b, ts=bt, dir="down", record_len=512, content_type="23"))
    # обоим — фоновый chaff, чтобы задача не была тривиальной
    for sess, store in ((a, ra), (b, rb)):
        ct = t0
        while ct < t0+40:
            store.append(dict(session=sess, ts=ct, dir="down" if sess==a else "up", record_len=64, content_type="23"))
            ct += 0.5
    return ra + rb

# L2 dataset
cov, vil = [], []
for i in range(12):
    cov += cover_visit(f"cover-real__{i:03d}")
    vil += veil_visit(f"veil-active__{i:03d}")
write(os.path.join(OUT, "synth_cover.csv"), cov)
write(os.path.join(OUT, "synth_veil.csv"), vil)

# negative control: делим cover на два псевдо-класса
negA, negB = [], []
for i in range(12):
    negA += [r|{"session": r["session"].replace("cover-real", "negctl-a")} for r in cover_visit(f"negctl-a__{i:03d}")]
    negB += [r|{"session": r["session"].replace("cover-real", "negctl-b")} for r in cover_visit(f"negctl-b__{i:03d}")]
write(os.path.join(OUT, "synth_negA.csv"), negA)
write(os.path.join(OUT, "synth_negB.csv"), negB)

# L3 datasets
corr, indep = [], []
for i in range(8):
    corr += pair_visits(f"{i:02d}", correlated=True)
for i in range(8):
    indep += pair_visits(f"{i:02d}", correlated=False)
write(os.path.join(OUT, "synth_pairs_corr.csv"), corr)
write(os.path.join(OUT, "synth_pairs_indep.csv"), indep)
print("synthetic records written to", OUT)
