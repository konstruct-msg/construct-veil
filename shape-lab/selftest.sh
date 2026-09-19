#!/usr/bin/env bash
# Регрессионный self-test СТЕНДА (не VEIL): на синтетике стенд обязан
#  (1) поймать заведомо разные классы (veil vs cover -> p~0),
#  (2) НЕ выдумать разницу на грани (neg-control -> p не сильно значим),
#  (3) поймать кросс-корреляцию пар и отвергнуть независимые.
# Гоняется без реальных захватов. Так проверяем машинерию до вложений в трафик.
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="$LAB/.venv/bin/python"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
"$PY" "$LAB/samples/synth_gen.py" "$TMP" >/dev/null

echo "== L2 signal (veil vs cover): ждём p~0 =="
"$PY" "$LAB/features/build_features.py" "$TMP/synth_cover.csv" "$TMP/synth_veil.csv" -o "$TMP/feat_l2.csv"
"$PY" "$LAB/classify/l2_classifier.py" "$TMP/feat_l2.csv" --positive veil --negative cover-real --n-perm 200 >/dev/null

echo "== L2 negative control: ждём (эталон малого N) =="
"$PY" "$LAB/features/build_features.py" "$TMP/synth_negA.csv" "$TMP/synth_negB.csv" -o "$TMP/feat_neg.csv"
"$PY" "$LAB/classify/l2_classifier.py" "$TMP/feat_neg.csv" --positive negctl-a --negative negctl-b --n-perm 200 >/dev/null

echo "== L3 correlated (ждём advantage>0.1) =="
"$PY" "$LAB/classify/l3_correlation.py" "$TMP/synth_pairs_corr.csv" | tail -1
echo "== L3 independent (ждём near noise) =="
"$PY" "$LAB/classify/l3_correlation.py" "$TMP/synth_pairs_indep.csv" | tail -1
