#!/usr/bin/env bash
# Ступень 1 (capture): помеченный pcap на relay через systemd-run.
# Один захват = один визит одного класса. Снимаем ВСЕ классы на ОДНОМ relay
# тем же tcpdump -> сопоставимость пути (требование методологии).
#
#   capture.sh <host-alias> <label> <seconds> [server_port]
#
# КООРДИНАТ ФРОНТОВ В РЕПОЗИТОРИИ НЕТ. Алиасы, SSH-цели, ключи и порты берутся
# из неотслеживаемого capture/hosts.local.sh (в .gitignore). Скопируй
# hosts.local.sh.example -> hosts.local.sh и впиши координаты из veil-ops ЛОКАЛЬНО.
# Публичный репозиторий открыт: любое реальное имя/IP тут = сожжённый фронт
# (см. decisions/no-bundled-veil-fronts в construct-docs).
#
# После запуска — параллельно генерим трафик класса:
#   veil-*     : поднять VEIL на устройстве (idle/переписка)
#   cover-real : ./baseline_browser.py <SITE_HOST>  (браузер без тикета -> cover)
set -euo pipefail
HOSTS="$(dirname "$0")/hosts.local.sh"
[ -f "$HOSTS" ] || { echo "нет $HOSTS — скопируй hosts.local.sh.example и впиши координаты из veil-ops"; exit 1; }
# shellcheck disable=SC1090
source "$HOSTS"               # задаёт host_<alias> () -> echo "<ssh-target> <key-path> <port>"
ALIAS="${1:?host-alias (см. hosts.local.sh)}"
LABEL="${2:?label}"; SECS="${3:?seconds}"
read -r SSH_TARGET KEY PORT < <("host_${ALIAS}" 2>/dev/null) \
  || { echo "неизвестный алиас '$ALIAS' (определи host_${ALIAS} в hosts.local.sh)"; exit 1; }
PORT="${4:-$PORT}"
SSH="ssh -i $KEY $SSH_TARGET"
RUN="$(date -u +%Y-%m-%dT%H-%M-%S)"
REMOTE="/tmp/shape_${LABEL}__${RUN}.pcap"
echo ">> capturing tcp port $PORT for ${SECS}s on $ALIAS -> $REMOTE"
# systemd-run как одиночная команда (наш отлаженный паттерн, не цепочка sudo)
$SSH "sudo systemd-run --unit=shapecap_${RUN} --collect \
  tcpdump -i any -B 65536 -w $REMOTE tcp port $PORT" | cat
echo ">> генерируй трафик класса '$LABEL' СЕЙЧАС (${SECS}s)…"
sleep "$SECS"
$SSH "sudo systemctl stop shapecap_${RUN} 2>/dev/null || true" | cat
LOCAL="samples/${LABEL}__${RUN}.pcap"
$SSH "sudo chmod a+r $REMOTE" | cat
scp -i "$KEY" "$SSH_TARGET:$REMOTE" "$LOCAL"
$SSH "sudo rm -f $REMOTE" | cat
echo ">> saved $LOCAL  (server_port=$PORT)"
echo ">> extract: ../extract/pcap_to_records.py $LOCAL --server-port $PORT --tag $LABEL -o ../samples/${LABEL}__${RUN}.csv"
