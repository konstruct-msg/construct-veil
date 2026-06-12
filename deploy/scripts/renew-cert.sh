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

# SPKI pin BEFORE renewal (from the live wire cert) — used to assert the pin did
# not move. With --reuse-key it must stay constant; a change means the key was
# rotated and every issued config link just died.
PRE_SPKI=$(echo | openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null \
           | openssl x509 -pubkey -noout 2>/dev/null \
           | openssl pkey -pubin -outform DER 2>/dev/null \
           | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}')

echo "$(date -Iseconds) ▸ renew attempt for $DOMAIN (spki=$PRE_SPKI)"

# --reuse-key freezes the TLS keypair so the SPKI pin (and every issued config
# link) survives renewal. bootstrap.sh persists this into the renewal config;
# passing it here guarantees it even on certs issued before the flag existed.
docker compose run --rm certbot renew --webroot -w /var/www/certbot --reuse-key --quiet

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

  # Assert the pin did NOT move. With --reuse-key the SPKI is identical to
  # PRE_SPKI; if it changed, the key rotated and all issued config links are now
  # dead — re-issue them with provision-link.sh and re-provision testers.
  sleep 3
  POST_SPKI=$(docker compose logs --no-color --tail 30 relay 2>&1 \
         | grep -oE 'spki *[a-f0-9]{64}' | tail -1 | awk '{print $2}')
  echo "  SPKI: $PRE_SPKI → $POST_SPKI"
  if [ -n "$POST_SPKI" ] && [ "$POST_SPKI" != "$PRE_SPKI" ]; then
    echo "  ⚠⚠ SPKI CHANGED despite --reuse-key — all config links are now INVALID."
    echo "     Re-issue with: ./scripts/provision-link.sh <tester-name>"
  else
    echo "  ✓ SPKI stable — existing config links remain valid"
  fi
else
  echo "  cert not yet due for renewal"
fi
