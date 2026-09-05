#!/usr/bin/env bash
# Bootstrap from pre-built GHCR images (no local Rust compilation).
# Run on VPS in deploy/ directory.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f docker-compose.prod.yml"

if [ ! -f .env ]; then
  echo "✗ .env missing. Copy .env.example and edit it first."
  exit 1
fi
set -a; source .env; set +a

: "${DOMAIN:?DOMAIN must be set in .env}"
: "${EMAIL:?EMAIL must be set in .env}"
: "${COVER_IMAGE:?COVER_IMAGE must be set (private cover image — see deploy/COVER.md)}"
: "${ISSUER_PUBKEY:?ISSUER_PUBKEY must be set in .env}"
CAPABILITY_DAYS="${CAPABILITY_DAYS:-${TICKET_DAYS:-60}}"
EXTRA_DOMAINS="${EXTRA_DOMAINS:-}"
export COVER_IMAGE

# Build certbot -d args
CERTBOT_DOMAINS=("-d" "$DOMAIN")
if [ -n "$EXTRA_DOMAINS" ]; then
  IFS=',' read -ra _EXTRA <<< "$EXTRA_DOMAINS"
  for d in "${_EXTRA[@]}"; do
    d=$(echo "$d" | tr -d '[:space:]')
    [ -n "$d" ] && CERTBOT_DOMAINS+=("-d" "$d")
  done
fi

echo "▸ DOMAIN      = $DOMAIN"
echo "▸ EXTRA       = ${EXTRA_DOMAINS:-(none)}"
echo "▸ EMAIL       = $EMAIL"
echo "▸ COVER_IMAGE = $COVER_IMAGE"
echo "▸ ISSUER      = ${ISSUER_PUBKEY:0:12}…"
echo

# ── Pull images ──────────────────────────────────────────────────────────
echo "▸ Pulling relay (GHCR) + cover (COVER_IMAGE)…"
$COMPOSE pull

# ── Start cover for ACME ─────────────────────────────────────────────────
echo "▸ Starting cover on :80…"
$COMPOSE up -d cover
sleep 3

for i in 1 2 3 4 5; do
  if curl -fsS --max-time 2 "http://127.0.0.1/" -o /dev/null 2>&1 \
     || curl -fsSI --max-time 2 "http://127.0.0.1/" 2>&1 | grep -q 'HTTP/.*301'; then
    echo "✓ cover responding"
    break
  fi
  sleep 1
done

# ── Issue cert ───────────────────────────────────────────────────────────
echo "▸ Requesting Let's Encrypt cert for: ${CERTBOT_DOMAINS[*]}"
$COMPOSE run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  "${CERTBOT_DOMAINS[@]}" \
  --email "$EMAIL" \
  --agree-tos --no-eff-email --reuse-key --expand -n

# ── Make certs readable by the non-root relay (uid 65532) ───────────────────
# certbot writes privkey.pem 0600 root:root and live/archive dirs 0700, so the
# relay container (USER veil, uid 65532) gets EACCES on the key. Re-applied on
# every renewal (renew-cert.sh) since certbot resets perms on each new key.
echo "▸ Fixing cert permissions for the non-root relay…"
$COMPOSE run --rm --no-TTY --entrypoint sh certbot -c '
  chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
  chmod 0755 /etc/letsencrypt/live/* /etc/letsencrypt/archive/* 2>/dev/null || true
  chmod 0644 /etc/letsencrypt/archive/*/privkey*.pem 2>/dev/null || true
'

# ── Start relay ──────────────────────────────────────────────────────────
echo "▸ Starting relay on :443…"
$COMPOSE up -d relay
sleep 3

echo
echo "── Relay banner ──"
$COMPOSE logs --no-color relay 2>&1 | grep -E 'spki|listen|tickets|backend|site' | head
echo "───────────────────"

SPKI=$($COMPOSE logs --no-color relay 2>&1 | grep -oE 'spki *[a-f0-9]{64}' | head -1 | awk '{print $2}')
if [ -n "$SPKI" ]; then
  echo
  echo "── Client manifest values ──"
  echo "  address           = $DOMAIN:443"
  echo "  tls_sni           = $DOMAIN"
  echo "  pinned_spki       = $SPKI"
  echo "  issuer_pubkey     = $ISSUER_PUBKEY"
  echo "────────────────────────────"
  echo
  echo "Issue user capabilities locally, never on this relay VPS:"
  echo "  RELAY=$DOMAIN:443 DAYS=$CAPABILITY_DAYS ./deploy/scripts/provision-link.sh <tester>"
else
  echo "⚠ Could not extract SPKI. Check logs: $COMPOSE logs relay"
fi
