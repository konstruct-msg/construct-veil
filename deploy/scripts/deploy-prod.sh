#!/usr/bin/env bash
# Pull latest prod images from GHCR and restart services.
# Run on VPS in the deploy/ directory.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.prod.yml"

if [ ! -f .env ]; then
  echo "✗ .env missing. Copy .env.example and edit it first."
  exit 1
fi
set -a; source .env; set +a

# External volumes must exist before `up` (compose won't create them). No-op on
# an already-bootstrapped node; loading .env first honours any *_VOLUME override.
. scripts/lib.sh
ensure_volumes

echo "▸ Pulling latest images from GHCR…"
docker compose -f "$COMPOSE_FILE" pull

echo "▸ Recreating containers…"
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

echo "▸ Status:"
docker compose -f "$COMPOSE_FILE" ps
