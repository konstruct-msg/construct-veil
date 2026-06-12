#!/usr/bin/env bash
# provision-link.sh — issue a working veil-front config link + ticket for one tester.
#
#   ░░ RUN ON YOUR LAPTOP — NEVER ON THE RELAY ░░
#
# It needs the SECRET Ed25519 config-signing key (relayConfigSigningKey private
# seed). That key is the trust anchor for every config link the app accepts; it
# must never touch the relay VPS. This script hard-refuses to run if it can't
# find the key locally, so accidentally running it on the relay is a no-op.
#
# Why this exists: the SPKI pin used to be hand-copied from the relay banner into
# `make-config-link --spki …`. A stale copy (e.g. after a cert renewal that
# rotated the key) produced a TLS HandshakeFailure with no useful client error.
# This script removes the human step: it reads the pin straight off the live wire
# cert, so the link is correct by construction. Combined with certbot --reuse-key
# (see bootstrap.sh / renew-cert.sh) the pin no longer moves, so links stay valid.
#
# Usage:
#   ./provision-link.sh [tester-label]
#
# Env (override as needed):
#   RELAY=api.divany-kresla.uk:443     # host:port of the relay (also the SNI host)
#   DAYS=60                            # ticket + config validity
#   SIGNING_KEY_PEM=~/Code/construct-landing/scripts/signing_key.pem
#   VEIL_REPO=~/Code/construct-veil    # checkout that builds make-config-link
#
# Output:
#   • the konstruct://veil-config?d=… link (stdout) + QR (stderr)
#   • the base64 ticket to install on the relay (stderr)
# The ticket must be appended to the relay's tickets.json AND the relay reloaded
# before the link works — see the printed next-steps.

set -euo pipefail

RELAY="${RELAY:-api.divany-kresla.uk:443}"
DAYS="${DAYS:-60}"
SIGNING_KEY_PEM="${SIGNING_KEY_PEM:-$HOME/Code/construct-landing/scripts/signing_key.pem}"
VEIL_REPO="${VEIL_REPO:-$HOME/Code/construct-veil}"
LABEL="${1:-tester}"

HOST="${RELAY%:*}"

# ── Guard: secret signing key must be present locally ───────────────────────
if [ ! -f "$SIGNING_KEY_PEM" ]; then
  echo "✗ signing key not found at: $SIGNING_KEY_PEM" >&2
  echo "  This script is LOCAL-ONLY and needs the secret Ed25519 config-signing" >&2
  echo "  key. If you are on the relay VPS: stop — that key must never live here." >&2
  exit 1
fi

# ── Single source of truth: pin = SHA-256(SPKI) of the LIVE wire cert ────────
echo "▸ reading SPKI pin from live cert at $RELAY …" >&2
SPKI=$(echo | openssl s_client -connect "$RELAY" -servername "$HOST" 2>/dev/null \
       | openssl x509 -pubkey -noout 2>/dev/null \
       | openssl pkey -pubin -outform DER 2>/dev/null \
       | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}')
if [ -z "$SPKI" ] || [ "${#SPKI}" -ne 64 ]; then
  echo "✗ could not derive SPKI from $RELAY (got: '$SPKI')" >&2
  echo "  Is the relay reachable on :443 and serving its TLS cert?" >&2
  exit 1
fi
echo "  spki = $SPKI" >&2

# ── Extract the 32-byte Ed25519 seed from the PKCS8 PEM (never printed) ──────
SEED=$(openssl pkey -in "$SIGNING_KEY_PEM" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)
if [ "${#SEED}" -ne 64 ]; then
  echo "✗ could not extract 32-byte Ed25519 seed from $SIGNING_KEY_PEM" >&2
  exit 1
fi

# ── Issue the signed link + ticket ──────────────────────────────────────────
echo "▸ issuing link for '$LABEL' (relay=$RELAY, days=$DAYS) …" >&2
( cd "$VEIL_REPO" && cargo run -q -p construct-veil-relay --bin make-config-link -- \
    --signing-key "$SEED" \
    --relay "$RELAY" \
    --spki "$SPKI" \
    --days "$DAYS" )

cat >&2 <<EOF

── next steps ──────────────────────────────────────────────────────────────
1. Add the base64 ticket above to the relay's tickets.json:
     ssh <vps> 'cd /opt/veil-front && \\
       jq ". + [\"<TICKET>\"]" data/tickets/tickets.json | sponge data/tickets/tickets.json && \\
       docker compose restart relay'
   (or hand-edit the JSON array + \`docker compose restart relay\`)
2. Send the konstruct://veil-config link (or QR) to the tester out-of-band.
3. Tester opens it once — the app verifies the Ed25519 signature against the
   pinned relayConfigSigningKey and stores the ticket + pin.
EOF
