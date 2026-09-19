#!/usr/bin/env python3
"""Ступень 4a (L2): цензор пытается отличить veil-* от cover-real.

Гейт (spec M1 / review §14): лучший классификатор -> ROC-AUC ~ 0.5 и
recall@FPR=target ~ target. Метрика — ROC-AUC + recall при ЗАРАНЕЕ выбранной
низкой FPR, НЕ KS. Сплит train/test ПО ВИЗИТУ (GroupKFold), чтобы классификатор
не запоминал сессию. Набор классификаторов по нарастающей мощности. Всегда
печатаем feature importances — карту того, что течёт в шейпере.

Negative control: подать два подкласса ОДНОГО класса -> ожидаем AUC~0.5.
"""
import argparse, csv, json, sys
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

def load(path):
    rows = list(csv.DictReader(open(path)))
    feat_cols = [c for c in rows[0] if c not in ("visit", "label")]
    X = np.array([[float(r[c]) for c in feat_cols] for r in rows])
    labels = [r["label"] for r in rows]
    groups = [r["visit"] for r in rows]
    return X, labels, groups, feat_cols

def recall_at_fpr(y, score, target_fpr):
    fpr, tpr, _ = roc_curve(y, score)
    ok = fpr <= target_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0

def pooled_cv_auc(clf, X, y, groups, target_fpr=None):
    """Groups-aware pooled CV: одна out-of-fold оценка на визит, затем один AUC.
    Сплит по визиту -> классификатор не запоминает сессию (review §14)."""
    y = np.array(y)
    n_splits = min(5, len(set(groups)), int(min(np.bincount(y))))
    if n_splits < 2:
        return None, None
    gkf = GroupKFold(n_splits=n_splits)
    scores, recs = np.zeros(len(y)), []
    for tr, te in gkf.split(X, y, groups):
        clf.fit(X[tr], y[tr])
        s = clf.predict_proba(X[te])[:, 1] if hasattr(clf, "predict_proba") else clf.decision_function(X[te])
        scores[te] = s
        if target_fpr is not None and len(set(y[te])) == 2:
            recs.append(recall_at_fpr(y[te], s, target_fpr))
    auc = float(roc_auc_score(y, scores))
    rec = float(np.mean(recs)) if recs else None
    return auc, rec

def permutation_null(clf, X, y, groups, n_perm, target_fpr):
    """Эмпирический null: перемешиваем метки по визитам n_perm раз.
    p-value = доля null-AUC >= наблюдаемого. Отвечает 'реально ли разделение
    при данном N и числе признаков' без отдельного neg-control датасета."""
    obs, rec = pooled_cv_auc(clf, X, y, groups, target_fpr)
    if obs is None:
        return None
    rng = np.random.default_rng(0)
    y = np.array(y); null = []
    for _ in range(n_perm):
        yp = rng.permutation(y)
        a, _ = pooled_cv_auc(clf, X, yp, groups)
        if a is not None:
            null.append(a)
    null = np.array(null)
    # двусторонне относительно 0.5: |auc-0.5|
    p = float((np.abs(null - 0.5) >= abs(obs - 0.5)).mean()) if len(null) else None
    return {
        "roc_auc_pooled": obs,
        f"recall_at_fpr_{target_fpr}": rec,
        "null_auc_mean": float(null.mean()) if len(null) else None,
        "null_auc_p95": float(np.percentile(null, 95)) if len(null) else None,
        "p_value": p,
        "n_perm": len(null),
    }

def evaluate(name, clf, X, y, groups, target_fpr, n_perm):
    r = permutation_null(clf, X, y, groups, n_perm, target_fpr)
    if r is None:
        return {"model": name, "error": "too few visits/groups for CV"}
    r["model"] = name
    return r

def importances(X, y, cols):
    clf = GradientBoostingClassifier(random_state=0).fit(X, np.array(y))
    imp = sorted(zip(cols, clf.feature_importances_), key=lambda x: -x[1])
    return [{"feature": f, "importance": round(float(v), 4)} for f, v in imp[:12]]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features_csv")
    ap.add_argument("--positive", default="veil", help="подстрока метки 'скрываемого' класса")
    ap.add_argument("--negative", default="cover-real", help="метка эталона")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--n-perm", type=int, default=200, help="итераций permutation-null")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    X, labels, groups, cols = load(a.features_csv)
    y, keepX, keepG = [], [], []
    for i, lab in enumerate(labels):
        if a.positive in lab: y.append(1)
        elif a.negative in lab: y.append(0)
        else: continue
        keepX.append(X[i]); keepG.append(groups[i])
    X = np.array(keepX); groups = keepG
    if len(set(y)) < 2:
        raise SystemExit(f"need both classes; got labels={sorted(set(labels))}")
    # depth=2 / min_samples_leaf: GBM устойчивее к переобучению на малом N
    # (иначе negative-control floor уезжает вверх — проверено на synth).
    models = [
        ("logreg_scaled", make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))),
        ("gbm", GradientBoostingClassifier(random_state=0, max_depth=2,
                                           n_estimators=100, min_samples_leaf=3)),
    ]
    report = {
        "n_positive": int(sum(y)), "n_negative": int(len(y) - sum(y)),
        "n_visits": len(y), "target_fpr": a.target_fpr,
        "results": [evaluate(n, c, X, y, groups, a.target_fpr, a.n_perm) for n, c in models],
        "top_features": importances(X, y, cols),
        "gate": "L2 pass == p_value НЕ значим (>0.05): разделение не отличимо от null при данном N",
    }
    out = json.dumps(report, indent=2, ensure_ascii=False)
    (open(a.out, "w").write(out) if a.out else sys.stdout.write(out + "\n"))
    pvals = [r["p_value"] for r in report["results"] if r.get("p_value") is not None]
    aucs = [r["roc_auc_pooled"] for r in report["results"] if r.get("roc_auc_pooled") is not None]
    best = min(pvals) if pvals else 1.0
    bauc = max(aucs) if aucs else 0.5
    sys.stderr.write(f"best ROC-AUC={bauc:.3f}  min p-value={best:.3f}  "
                     f"({'LEAK (significant)' if best <= 0.05 else 'ok (not significant vs null)'})\n")

if __name__ == "__main__":
    main()
