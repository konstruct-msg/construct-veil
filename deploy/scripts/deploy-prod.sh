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

echo "▸ Pulling latest images from GHCR…"
docker compose -f "$COMPOSE_FILE" pull

echo "▸ Recreating containers…"
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

echo "▸ Status:"
docker compose -f "$COMPOSE_FILE" ps
