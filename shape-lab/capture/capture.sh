#!/usr/bin/env bash
# Ступень 1 (capture): помеченный pcap на relay через systemd-run.
# Один захват = один визит одного класса. Снимаем ВСЕ классы на ОДНОМ relay
# тем же tcpdump -> сопоставимость пути (требование методологии).
#
#   capture.sh <host-alias> <label> <seconds> [server_port]
#   host-alias: <redacted> | <redacted>   (ключи/адреса ниже)
#
# После запуска — параллельно генерим трафик класса:
#   veil-*     : поднять VEIL на устройстве (idle/переписка)
#   cover-real : ./baseline_browser.py <origin>  (браузер без тикета -> cover)
set -euo pipefail
case "${1:?host}" in
  <redacted>)  SSH="ssh -i $HOME/.ssh/<redacted-key> <redacted-user>@<redacted-ip>"; IF=any; PORT="${4:-443}";;
  <redacted>) SSH="ssh -i $HOME/.ssh/<redacted-key> <redacted-user>@<redacted-ip>";      IF=any; PORT="${4:-8443}";;  # за nginx relay слушает 8443
  *) echo "unknown host $1 (<redacted>|<redacted>)"; exit 1;;
esac
LABEL="${2:?label}"; SECS="${3:?seconds}"
RUN="$(date -u +%Y-%m-%dT%H-%M-%S)"
REMOTE="/tmp/shape_${LABEL}__${RUN}.pcap"
echo ">> capturing tcp port $PORT for ${SECS}s on $1 -> $REMOTE"
# systemd-run как одиночная команда (наш отлаженный паттерн, не цепочка sudo)
$SSH "sudo systemd-run --unit=shapecap_${RUN} --collect \
  tcpdump -i $IF -B 65536 -w $REMOTE tcp port $PORT" | cat
echo ">> генерируй трафик класса '$LABEL' СЕЙЧАС (${SECS}s)…"
sleep "$SECS"
$SSH "sudo systemctl stop shapecap_${RUN} 2>/dev/null || true" | cat
LOCAL="samples/${LABEL}__${RUN}.pcap"
$SSH "sudo chmod a+r $REMOTE" | cat
case "$1" in
  <redacted>)  scp -i "$HOME/.ssh/<redacted-key>" <redacted-user>@<redacted-ip>:"$REMOTE" "$LOCAL";;
  <redacted>) scp -i "$HOME/.ssh/<redacted-key>"      <redacted-user>@<redacted-ip>:"$REMOTE" "$LOCAL";;
esac
$SSH "sudo rm -f $REMOTE" | cat
echo ">> saved $LOCAL  (server_port=$PORT)"
echo ">> extract: ../extract/pcap_to_records.py $LOCAL --server-port $PORT --tag $LABEL -o ../samples/${LABEL}__${RUN}.csv"
