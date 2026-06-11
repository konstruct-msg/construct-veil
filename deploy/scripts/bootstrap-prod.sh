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
TICKET_DAYS="${TICKET_DAYS:-60}"
EXTRA_DOMAINS="${EXTRA_DOMAINS:-}"

# Build certbot -d args
CERTBOT_DOMAINS=("-d" "$DOMAIN")
if [ -n "$EXTRA_DOMAINS" ]; then
  IFS=',' read -ra _EXTRA <<< "$EXTRA_DOMAINS"
  for d in "${_EXTRA[@]}"; do
    d=$(echo "$d" | tr -d '[:space:]')
    [ -n "$d" ] && CERTBOT_DOMAINS+=("-d" "$d")
  done
fi

echo "▸ DOMAIN = $DOMAIN"
echo "▸ EXTRA  = ${EXTRA_DOMAINS:-(none)}"
echo "▸ EMAIL  = $EMAIL"
echo

# ── Pull images ──────────────────────────────────────────────────────────
echo "▸ Pulling images from GHCR…"
$COMPOSE pull

# ── Start cover for ACME ─────────────────────────────────────────────────
echo "▸ Starting cover-site on :80…"
$COMPOSE up -d cover
sleep 3

for i in 1 2 3 4 5; do
  if curl -fsS --max-time 2 "http://127.0.0.1/" -o /dev/null 2>&1 \
     || curl -fsSI --max-time 2 "http://127.0.0.1/" 2>&1 | grep -q 'HTTP/.*301'; then
    echo "✓ cover-site responding"
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
  --agree-tos --no-eff-email --expand -n

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

# ── Issue ticket ─────────────────────────────────────────────────────────
echo "▸ Issuing initial veil-front ticket ($TICKET_DAYS days)…"
mkdir -p data/tickets
TICKET=$($COMPOSE run --rm --no-TTY \
          --entrypoint /usr/local/bin/issue-ticket relay \
          --days "$TICKET_DAYS" | tr -d '\r\n' | tr -d '[:space:]')

if [ ${#TICKET} -lt 80 ]; then
  echo "✗ issue-ticket returned suspiciously short output: '$TICKET'"
  exit 1
fi

cat > data/tickets/tickets.json <<EOF
[ "$TICKET" ]
EOF
echo "✓ ticket written"

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
  echo "  veil_front_ticket = $TICKET"
  echo "────────────────────────────"
else
  echo "⚠ Could not extract SPKI. Check logs: $COMPOSE logs relay"
fi
