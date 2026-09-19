#!/usr/bin/env bash
# Клиентский захват (на этом Mac) — ВЕРНЫЙ вантаж: совпадает с точкой цензора,
# не размазывает каденцию chaff (в отличие от relay-захвата за межд. каналом).
#
#   capture_local.sh <label> <seconds> <relay-ip> [iface] [port]
#
# Для DESKTOP-клиента (Mac) или Playwright — фильтруем egress-интерфейс по IP relay.
# Для iOS-УСТРОЙСТВА (золотой стандарт, настоящая iOS-форма) — сперва подними
# виртуальный интерфейс и передай его как iface:
#     rvictl -s <UDID>            # создаст rvi0 ; UDID: idevice_id -l или Xcode
#     capture_local.sh veil-active 120 195.133.44.113 rvi0
#     rvictl -x <UDID>            # снять после серии
set -euo pipefail
LABEL="${1:?label}"; SECS="${2:?seconds}"; IP="${3:?relay-ip}"
IFACE="${4:-en0}"; PORT="${5:-443}"
RUN="$(date -u +%Y-%m-%dT%H-%M-%S)"
OUT="samples/${LABEL}__${RUN}.pcap"
echo ">> local capture on $IFACE host $IP tcp port $PORT for ${SECS}s -> $OUT"
echo ">> генерируй трафик класса '$LABEL' СЕЙЧАС (VEIL на устройстве / baseline_browser.py)"
sudo timeout "$SECS" tcpdump -i "$IFACE" -B 65536 -w "$OUT" "host $IP and tcp port $PORT" || true
echo ">> saved $OUT (server_port=$PORT)"
echo ">> extract: extract/pcap_to_records.py $OUT --server-port $PORT --tag $LABEL -o samples/${LABEL}__${RUN}.csv"
