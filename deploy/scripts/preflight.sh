#!/usr/bin/env bash
# preflight.sh — check a greenfield VPS is ready before bootstrap-prod.sh
# Run on the VPS from /opt/veil-front (or any dir with .env loaded).
#
# Usage:
#   set -a && source .env && set +a
#   ./scripts/preflight.sh
#
# Exit 0 = all required checks passed. Warnings go to stderr but still 0
# unless a required check fails.

set -euo pipefail

fail=0
warn() { echo "⚠ $*" >&2; }
ok()   { echo "✓ $*"; }
bad()  { echo "✗ $*" >&2; fail=1; }

echo "── VEIL-front preflight ──"

# ── env ────────────────────────────────────────────────────────────────────
: "${DOMAIN:?DOMAIN must be set}"
: "${EMAIL:?EMAIL must be set}"
: "${COVER_IMAGE:?COVER_IMAGE must be set}"
: "${ISSUER_PUBKEY:?ISSUER_PUBKEY must be set}"
BACKEND="${BACKEND:-}"
EXTRA_DOMAINS="${EXTRA_DOMAINS:-}"

ok "DOMAIN=$DOMAIN"
ok "COVER_IMAGE=$COVER_IMAGE"
ok "ISSUER_PUBKEY length=${#ISSUER_PUBKEY}"
if [ "${#ISSUER_PUBKEY}" -ne 64 ]; then
  bad "ISSUER_PUBKEY should be 64 hex chars (got ${#ISSUER_PUBKEY})"
fi
if ! [[ "$ISSUER_PUBKEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  bad "ISSUER_PUBKEY is not hex"
fi

# ── tools ──────────────────────────────────────────────────────────────────
command -v docker >/dev/null && ok "docker present" || bad "docker missing"
if docker compose version >/dev/null 2>&1; then
  ok "docker compose plugin present"
else
  bad "docker compose plugin missing"
fi
command -v curl >/dev/null && ok "curl present" || bad "curl missing"
command -v openssl >/dev/null && ok "openssl present" || bad "openssl missing"

# ── ports ──────────────────────────────────────────────────────────────────
for p in 80 443; do
  if command -v ss >/dev/null 2>&1; then
    if ss -lnt | awk '{print $4}' | grep -qE "[:.]$p\$"; then
      warn "port $p already has a listener — bootstrap may conflict"
    else
      ok "port $p free (ss)"
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
      warn "port $p already has a listener — bootstrap may conflict"
    else
      ok "port $p free (lsof)"
    fi
  else
    warn "cannot check port $p (no ss/lsof)"
  fi
done

# ── DNS ────────────────────────────────────────────────────────────────────
check_dns() {
  local name="$1"
  [ -z "$name" ] && return
  local ip=""
  if command -v dig >/dev/null 2>&1; then
    ip=$(dig +short A "$name" | head -1)
  elif command -v getent >/dev/null 2>&1; then
    ip=$(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1; exit}')
  fi
  if [ -z "$ip" ]; then
    bad "DNS A missing for $name — ACME will fail"
  else
    ok "$name → $ip"
  fi
}

check_dns "$DOMAIN"
if [ -n "$EXTRA_DOMAINS" ]; then
  IFS=',' read -ra _EXTRA <<< "$EXTRA_DOMAINS"
  for d in "${_EXTRA[@]}"; do
    d=$(echo "$d" | tr -d '[:space:]')
    check_dns "$d"
  done
fi

# ── GHCR pull for COVER_IMAGE ──────────────────────────────────────────────
if docker pull "$COVER_IMAGE" >/dev/null 2>&1; then
  ok "can pull COVER_IMAGE"
  # leave image cached — fine for bootstrap
else
  bad "cannot pull COVER_IMAGE=$COVER_IMAGE"
  echo "    → docker login ghcr.io -u <user> --password-stdin  (PAT with read:packages)" >&2
fi

# ── optional chain vars ────────────────────────────────────────────────────
if [ -n "${CHAIN_UPSTREAM_ADDR:-}" ] || [ -n "${CHAIN_UPSTREAM_SNI:-}" ] || [ -n "${CHAIN_UPSTREAM_SPKI:-}" ]; then
  echo "── chain mode env present ──"
  [ -n "${CHAIN_UPSTREAM_ADDR:-}" ] && ok "CHAIN_UPSTREAM_ADDR=$CHAIN_UPSTREAM_ADDR" || bad "CHAIN_UPSTREAM_ADDR empty"
  [ -n "${CHAIN_UPSTREAM_SNI:-}" ] && ok "CHAIN_UPSTREAM_SNI=$CHAIN_UPSTREAM_SNI" || bad "CHAIN_UPSTREAM_SNI empty"
  [ -n "${CHAIN_UPSTREAM_SPKI:-}" ] && ok "CHAIN_UPSTREAM_SPKI set (${#CHAIN_UPSTREAM_SPKI} chars)" || bad "CHAIN_UPSTREAM_SPKI empty"
  if [ -n "${CHAIN_UPSTREAM_SPKI:-}" ] && [ "${#CHAIN_UPSTREAM_SPKI}" -ne 64 ]; then
    warn "CHAIN_UPSTREAM_SPKI usually 64 hex chars"
  fi
fi

if [ -n "$BACKEND" ]; then
  ok "BACKEND=$BACKEND"
else
  warn "BACKEND unset — compose default may apply; set explicitly for clean fronts"
fi

echo "────────────────────────"
if [ "$fail" -ne 0 ]; then
  echo "preflight FAILED" >&2
  exit 1
fi
echo "preflight OK — proceed with ./scripts/bootstrap-prod.sh"
exit 0
