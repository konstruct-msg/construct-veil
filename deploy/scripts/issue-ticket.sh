#!/usr/bin/env bash
# Issue an additional ticket, append to data/tickets/tickets.json.
# Optionally restart the relay so it picks up the new ticket.
#
# Usage:
#   ./scripts/issue-ticket.sh                # 60 days, append, no restart
#   ./scripts/issue-ticket.sh --days 30      # 30-day ticket
#   ./scripts/issue-ticket.sh --reload-relay # also restart relay

set -euo pipefail
cd "$(dirname "$0")/.."

DAYS=60
RELOAD=false
while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="$2"; shift 2 ;;
    --reload-relay) RELOAD=true; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

TICKET=$(docker compose run --rm --no-TTY \
           --entrypoint /usr/local/bin/issue-ticket relay \
           --days "$DAYS" | tr -d '[:space:]')

if [ ${#TICKET} -lt 80 ]; then
  echo "✗ issue-ticket returned suspiciously short output"; exit 1
fi

# Append to JSON array (preserve existing tickets).
mkdir -p data/tickets
python3 - <<PY
import json, os, sys
path = "data/tickets/tickets.json"
existing = []
if os.path.exists(path):
    try: existing = json.load(open(path))
    except: existing = []
existing.append("$TICKET")
json.dump(existing, open(path, "w"), indent=2)
print(f"✓ wrote {len(existing)} tickets to {path}")
PY

echo "  new ticket = $TICKET"
echo "  validity   = $DAYS days"

if $RELOAD; then
  echo "▸ restarting relay to pick up the new ticket…"
  docker compose restart relay
fi
