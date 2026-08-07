# Chain mode (relay_domestic → relay_clean)

Topology and mechanics: construct-docs `decisions/veil-relay-topology.md` §3.

**Production hostnames, IPs, and SPKI pins are operator inventory** — keep them in
private ops, not in this public repository. This file is the *mechanical* recipe only.

```text
  client (censored path)
       │
       ▼
  ┌─ relay_domestic ──────────────────────────────────────────────────┐
  │  cover = YOUR private domestic cover image (COVER_IMAGE)          │
  │  chain: TCP → <UPSTREAM_IP:443>                                   │
  │         TLS SNI = <clean-front-hostname>                          │
  │         SPKI pin = live cert of clean front                       │
  │         AUTH v3 ROLE_RELAY                                        │
  └───────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
  ┌─ relay_clean ─────────────────────────────────────────────────────┐
  │  cover = YOUR private clean-zone cover (different brand)          │
  │  accepts ROLE_USER + ROLE_RELAY                                   │
  │  --backend-tls → home backend                                     │
  └───────────────────────────────────────────────────────────────────┘
```

## 1. Clean front — no chain flags

Use `docker-compose.prod.yml` with your clean-zone `COVER_IMAGE`, backend TLS flags,
and `--issuer-pubkey`. Image must accept **ROLE_RELAY** on the same listener.

## 2. Domestic front — enable chain

### 2a. Keypair (once, on domestic VPS)

```bash
mkdir -p /opt/veil-front/chain && chmod 700 /opt/veil-front/chain
docker run --rm -v /opt/veil-front/chain:/data/chain \
  ghcr.io/konstruct-msg/construct-veil/relay:latest \
  --generate-relay-keypair --chain-veil-sk-file /data/chain/veil_sk.hex
# prints: veil_pk: <64 hex>
# seed only in /opt/veil-front/chain/veil_sk.hex (0600)
```

Send **only** `veil_pk` to the home-server admin.

### 2b. Issue ROLE_RELAY capability

Via home `IssueVeilCapability` with `role = 1`. Save `capability` base64 to
`/opt/veil-front/chain/capability.b64`.

### 2c. Live SPKI of clean front

```bash
echo | openssl s_client -connect <UPSTREAM_IP>:443 \
  -servername <CLEAN_SNI> 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -r | awk '{print $1}'
```

Prefer `certbot --reuse-key` on the clean front so SPKI is stable across renewals.

### 2d. `.env` on domestic VPS (example shape)

```bash
DOMAIN=<domestic-cover-domain>
EMAIL=<ops-email>
ISSUER_PUBKEY=<home issuer pubkey hex>
COVER_IMAGE=ghcr.io/<you>/<domestic-private-cover>:latest

CHAIN_UPSTREAM_ADDR=<UPSTREAM_IP>:443
CHAIN_UPSTREAM_SNI=<CLEAN_SNI>
CHAIN_UPSTREAM_SPKI=<sha256 hex of clean SPKI>
```

Use a **different** cover brand than the clean front.

### 2e. Compose

```bash
docker compose \
  -f docker-compose.prod.yml \
  -f docker-compose.chain.yml \
  up -d
```

Boot log must show chain dial success (see relay logging for chain mode).
