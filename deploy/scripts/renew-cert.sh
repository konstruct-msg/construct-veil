#!/usr/bin/env bash
# Renew the Let's Encrypt cert via webroot challenge (cover-site is still up,
# serves /.well-known/acme-challenge from the shared volume). Reload the relay
# if the cert actually changed.
#
# Wire into root crontab:
#   0 3 * * 1 cd /opt/veil-front && ./scripts/renew-cert.sh >> /var/log/veil-renew.log 2>&1

set -euo pipefail
cd "$(dirname "$0")/.."

set -a; source .env; set +a
: "${DOMAIN:?DOMAIN must be set in .env}"

CERT_PATH="/var/lib/docker/volumes/$(basename "$PWD" | tr '[:upper:]' '[:lower:]')_letsencrypt/_data/live/${DOMAIN}/cert.pem"
PRE_MTIME=$(stat -c '%Y' "$CERT_PATH" 2>/dev/null || echo 0)

echo "$(date -Iseconds) ▸ renew attempt for $DOMAIN"

docker compose run --rm certbot renew --webroot -w /var/www/certbot --quiet

POST_MTIME=$(stat -c '%Y' "$CERT_PATH" 2>/dev/null || echo 0)

if [ "$POST_MTIME" -gt "$PRE_MTIME" ]; then
  echo "✓ cert renewed (mtime: $PRE_MTIME → $POST_MTIME)"

  # certbot resets perms on the freshly-issued privkey (0600 root:root) — re-open
  # them so the non-root relay (uid 65532) can read the new key after restart.
  echo "  fixing cert permissions for the non-root relay…"
  docker compose run --rm --no-TTY --entrypoint sh certbot -c '
    chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
    chmod 0755 /etc/letsencrypt/live/* /etc/letsencrypt/archive/* 2>/dev/null || true
    chmod 0644 /etc/letsencrypt/archive/*/privkey*.pem 2>/dev/null || true
  '

  echo "  restarting relay"
  docker compose restart relay

  # Republish SPKI — fish it from the new banner.
  sleep 3
  SPKI=$(docker compose logs --no-color --tail 30 relay 2>&1 \
         | grep -oE 'spki *[a-f0-9]{64}' | tail -1 | awk '{print $2}')
  if [ -n "$SPKI" ]; then
    echo "  new SPKI = $SPKI"
    echo "  ⚠ update the client manifest entry for $DOMAIN with this SPKI"
  fi
else
  echo "  cert not yet due for renewal"
fi
