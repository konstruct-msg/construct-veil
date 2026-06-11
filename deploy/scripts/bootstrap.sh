#!/usr/bin/env bash
# Bootstrap: build images, request cert, issue initial ticket, start relay.
# Run from the deploy/ directory.

set -euo pipefail

cd "$(dirname "$0")/.."

# ── .env ────────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  echo "✗ .env missing. Copy .env.example and edit it first:"
  echo "    cp .env.example .env && \$EDITOR .env"
  exit 1
fi
set -a; source .env; set +a

: "${DOMAIN:?DOMAIN must be set in .env}"
: "${EMAIL:?EMAIL must be set in .env}"
TICKET_DAYS="${TICKET_DAYS:-60}"
EXTRA_DOMAINS="${EXTRA_DOMAINS:-}"

# Build the -d arg list for certbot. Primary $DOMAIN goes first — this
# determines which directory under /etc/letsencrypt/live/ the cert lands in
# (so it must match the relay's --cert path which is parameterised on $DOMAIN).
CERTBOT_DOMAINS=("-d" "$DOMAIN")
if [ -n "$EXTRA_DOMAINS" ]; then
  IFS=',' read -ra _EXTRA <<< "$EXTRA_DOMAINS"
  for d in "${_EXTRA[@]}"; do
    d=$(echo "$d" | tr -d '[:space:]')
    [ -n "$d" ] && CERTBOT_DOMAINS+=("-d" "$d")
  done
fi

echo "▸ DOMAIN         = $DOMAIN"
echo "▸ EXTRA_DOMAINS  = ${EXTRA_DOMAINS:-(none)}"
echo "▸ EMAIL          = $EMAIL"
echo "▸ BACKEND        = ${BACKEND:-host.docker.internal:50051}"
echo

# ── Pre-flight ──────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null; then
  echo "✗ docker not installed"; exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "✗ docker compose plugin missing"; exit 1
fi

# Verify DNS resolves for every cert name (warn only — user may be running
# from elsewhere). Each SAN name needs its own A record so the http-01
# challenge can hit /.well-known/acme-challenge/<token> from the CA.
if command -v dig >/dev/null; then
  for d in "$DOMAIN" $(echo "$EXTRA_DOMAINS" | tr ',' ' '); do
    [ -z "$d" ] && continue
    resolved=$(dig +short A "$d" | head -1)
    if [ -z "$resolved" ]; then
      echo "⚠ $d has no A record — ACME will fail until DNS is set"
    else
      echo "▸ $d → $resolved"
    fi
  done
fi

# ── Build images ────────────────────────────────────────────────────────────
echo "▸ Building images…"
docker compose build

# ── Start cover (needed for ACME http-01) ──────────────────────────────────
echo "▸ Starting cover-site on :80 for ACME challenge…"
docker compose up -d cover

# Wait for cover to be ready.
for i in 1 2 3 4 5; do
  if curl -fsS --max-time 2 "http://127.0.0.1/" -o /dev/null 2>&1 \
       || curl -fsSI --max-time 2 "http://127.0.0.1/" 2>&1 | grep -q 'HTTP/.*301'; then
    echo "✓ cover-site responding on :80"
    break
  fi
  sleep 1
done

# ── Issue Let's Encrypt cert ────────────────────────────────────────────────
echo "▸ Requesting Let's Encrypt cert for: ${CERTBOT_DOMAINS[*]}"
# --expand handles the case where a cert already exists for $DOMAIN and we're
# adding SAN names this run. No-op if cert doesn't exist or names unchanged.
docker compose run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  "${CERTBOT_DOMAINS[@]}" \
  --email "$EMAIL" \
  --agree-tos --no-eff-email --expand -n

# ── Make certs readable by the non-root relay (uid 65532) ───────────────────
# certbot writes privkey.pem as 0600 root:root and the live/archive dirs as
# 0700, so the relay container (USER veil, uid 65532) gets EACCES on the key and
# crashes with InvalidData(PermissionDenied). Open traversal on live/archive and
# read on the privkeys. Must be re-applied after every renewal — see
# renew-cert.sh — because certbot resets perms on each freshly-issued key.
echo "▸ Fixing cert permissions for the non-root relay…"
docker compose run --rm --no-TTY --entrypoint sh certbot -c '
  chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
  chmod 0755 /etc/letsencrypt/live/* /etc/letsencrypt/archive/* 2>/dev/null || true
  chmod 0644 /etc/letsencrypt/archive/*/privkey*.pem 2>/dev/null || true
'

# ── Issue initial ticket ───────────────────────────────────────────────────
echo "▸ Issuing initial veil-front ticket ($TICKET_DAYS days)…"
mkdir -p data/tickets
TICKET=$(docker compose run --rm --no-TTY \
            --entrypoint /usr/local/bin/issue-ticket relay \
            --days "$TICKET_DAYS")
TICKET=$(echo "$TICKET" | tr -d '\r\n' | tr -d '[:space:]')

if [ ${#TICKET} -lt 80 ]; then
  echo "✗ issue-ticket returned suspiciously short output: '$TICKET'"
  exit 1
fi

cat > data/tickets/tickets.json <<EOF
[
  "$TICKET"
]
EOF
echo "✓ ticket written to data/tickets/tickets.json"

# ── Start relay ────────────────────────────────────────────────────────────
echo "▸ Starting relay on :443…"
docker compose up -d relay

# Wait + show the SPKI hex from the startup banner.
sleep 2
echo
echo "── Relay startup banner ──"
docker compose logs --no-color relay 2>&1 | grep -E 'spki|listen|tickets|backend|site' | head
echo "──────────────────────────"

SPKI=$(docker compose logs --no-color relay 2>&1 | grep -oE 'spki *[a-f0-9]{64}' | head -1 | awk '{print $2}')
if [ -n "$SPKI" ]; then
  echo
  echo "── Client manifest values ──"
  echo "  address           = $DOMAIN:443"
  echo "  tls_sni           = $DOMAIN"
  echo "  pinned_spki       = $SPKI"
  echo "  veil_front_ticket = $TICKET"
  echo "────────────────────────────"
  echo
  echo "Copy these into the client manifest entry for this relay."
else
  echo "⚠ Could not extract SPKI from relay logs. Check 'docker compose logs relay'."
fi
