#!/usr/bin/env bash
# Shared helpers for the veil-front deploy scripts.
# Source AFTER loading .env (so overrides apply):  . scripts/lib.sh
#
# The whole point of this file is the volume-name contract. The cert lives in a
# Docker volume; compose names project volumes `<project>_<name>`, and the
# project defaults to the directory basename — so the SAME node deployed from
# `/opt/veil-front` vs a `deploy/` checkout attaches DIFFERENT volumes, and a
# fresh empty one crashes the relay on a missing cert. We pin fixed, external
# volume names instead. Existing nodes whose cert already sits in a
# `<project>_letsencrypt` volume point these at that exact name in .env.

LETSENCRYPT_VOLUME="${LETSENCRYPT_VOLUME:-veil_letsencrypt}"
CERTBOT_WWW_VOLUME="${CERTBOT_WWW_VOLUME:-veil_certbot-www}"
export LETSENCRYPT_VOLUME CERTBOT_WWW_VOLUME

# Create the external volumes if missing. compose does NOT auto-create external
# volumes, so this must run before any `docker compose up`. Idempotent.
ensure_volumes() {
  docker volume create "$LETSENCRYPT_VOLUME" >/dev/null
  docker volume create "$CERTBOT_WWW_VOLUME" >/dev/null
  echo "▸ volumes ready: $LETSENCRYPT_VOLUME, $CERTBOT_WWW_VOLUME"
}

# Succeeds if a live cert for $1 (domain) already exists in the cert volume.
# Used to make bootstrap idempotent — a re-run skips re-issuing a working cert
# (renewal is the cron's job). Override with FORCE_CERT=1 to always re-issue.
cert_exists() {
  local domain="$1"
  docker run --rm -v "$LETSENCRYPT_VOLUME":/le alpine \
    test -f "/le/live/$domain/fullchain.pem" 2>/dev/null
}
