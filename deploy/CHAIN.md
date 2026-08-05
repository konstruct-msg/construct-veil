# Chain mode: domestic.example.com → <redacted> (IP) → backend

## Topology

```text
  client (RU / censored path)
       │
       │  primary:   front.example.com  (or 203.0.113.10 if you pin by IP later)
       │  alternate: domestic.example.com            (Selectel, ExampleWeather cover)
       ▼
  ┌─ domestic.example.com (relay_domestic) ─────────────────────────────────────┐
  │  cover = example-weather-cover                                        │
  │  chain: TCP → 203.0.113.10:443                                   │
  │         TLS SNI = front.example.com                             │
  │         SPKI pin = live <redacted> cert                                │
  │         AUTH v3 ROLE_RELAY                                         │
  └───────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
  ┌─ 203.0.113.10  example-cover (relay_clean) ─────────────────────┐
  │  cover = furniture site                                            │
  │  accepts ROLE_USER (clients) + ROLE_RELAY (domestic chain)          │
  │  --backend-tls → ams.konstruct.cc (DO)                             │
  └────────────────────────────────────────────────────────────────────┘
```

**Why IP for the chain hop:** on the Selectel box, DNS to `front.example.com`
may be poisoned or flaky; dialing `203.0.113.10:443` is stable. TLS still
presents the real hostname as **SNI** and checks **SPKI**, so a MITM on that IP
fails the pin.

**Why client failover domestic when <redacted> is “down”:** often the *client path*
to 203.0.113.10 is blocked (ISP DPI), while Selectel egress still reaches that
IP. Nearsky is the entry that still works; chain reuses the clean front.

---

## 1. Clean front (<redacted>) — no chain flags

Keep current `docker-compose.prod.yml`:

- `--backend ams.konstruct.cc:443 --backend-tls --backend-sni ams.konstruct.cc`
- `--issuer-pubkey` = home `VEIL_ISSUER` public half  
- Image **must** include the gate fix that accepts **ROLE_RELAY** (same listener).  
  Older images reject ROLE_RELAY → chain lands on the cover site and breaks.

Redeploy <redacted> relay after that image ships.

---

## 2. Domestic front (domestic) — enable chain

### 2a. Keypair (once, on domestic VPS)

```bash
mkdir -p /opt/veil-front/chain && chmod 700 /opt/veil-front/chain
# using the relay binary / one-shot container with a RW mount:
docker run --rm -v /opt/veil-front/chain:/data/chain \
  ghcr.io/konstruct-msg/construct-veil/relay:latest \
  --generate-relay-keypair --chain-veil-sk-file /data/chain/veil_sk.hex
# prints: veil_pk: <64 hex>
# seed only in /opt/veil-front/chain/veil_sk.hex (0600) — never leave the box
```

Send **only** `veil_pk` to the home-server admin.

### 2b. Issue ROLE_RELAY capability (home / veil-service)

JWT-gated `IssueVeilCapability`:

- `relay_address` = whatever address is registered for the **clean** front in
  `VEIL_RELAYS` (e.g. `front.example.com:443`) — scope/spki in the response
  describe the front the cap is for; the chain dial still uses IP+SNI+pin.
- `veil_pk` = 32-byte raw pubkey from step 2a  
- `role` = **1** (`ROLE_RELAY`)

Save response `capability` bytes as base64 in  
`/opt/veil-front/chain/capability.b64` (one line, no quotes).

TTL: prefer shorter for relays (7–14d); renew in-band later.

### 2c. Live SPKI of <redacted> (from any host that can reach the IP)

```bash
echo | openssl s_client -connect 203.0.113.10:443 \
  -servername front.example.com 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -r | awk '{print $1}'
# expect: <REDACTED_SPKI>
# (rotate when LE key rotates — prefer certbot --reuse-key)
```

### 2d. `.env` on domestic

```bash
DOMAIN=domestic.example.com                 # + EXTRA_DOMAINS if needed
EMAIL=ops@domestic.example.com
ISSUER_PUBKEY=8a0ee71cd95f86a9f6877211accefaff6bb97f3051b3b2141f1c71690b9a2dcf

CHAIN_UPSTREAM_ADDR=203.0.113.10:443
CHAIN_UPSTREAM_SNI=front.example.com
CHAIN_UPSTREAM_SPKI=<REDACTED_SPKI>
```

Cover image: **ExampleWeather** (`example-weather-cover`), not furniture.

### 2e. Compose

```bash
# mount host chain dir into the named volume or bind-mount in an override:
#   volumes: [ "/opt/veil-front/chain:/data/chain:ro" ]

docker compose \
  -f docker-compose.prod.yml \
  -f docker-compose.chain.yml \
  up -d
```

Boot log must show:  
`Chain relay mode ENABLED — upstream 203.0.113.10:443 (SNI front.example.com)`

---

## 3. Client routing (<redacted> primary → domestic alternate)

`VEILConfig.seedRelays` order = failover priority:

1. `front.example.com:443` + SPKI `5621e47a…` (direct clean; best latency when reachable)
2. `domestic.example.com:443` + SPKI of **domestic** LE cert (after bootstrap)

Home `VEIL_RELAYS` must list **both** so `IssueVeilCapability` can hand out
capabilities (and alternates) for each.  
Signed manifest must include both `{addr, spki}`.

When <redacted> is blocked on the client path, the selector moves to domestic; tunnel
still exits via <redacted> IP from Selectel egress.

---

## 4. Smoke

```bash
# From domestic VPS — IP path + SNI works
echo | openssl s_client -connect 203.0.113.10:443 \
  -servername front.example.com 2>&1 | head -20

# Relay logs on domestic after a client connects via domestic:
#   Chain relay mode … / chain tunnel …
# On <redacted>: capability (v3) valid … role=relay
```

---

## 5. What is *not* required

- DNS on domestic for `front.example.com` (IP dial)
- Cloudflare in front of veil-front data path
- Client ever dialing DigitalOcean

## 6. Known limits

- Chain hop ClientHello is bare rustls (no uTLS yet) — if Selectel egress DPI
  fingerprints it, that is a follow-up.
- ROLE_RELAY shares the client-facing listener on clean (no separate port yet).
- Client→upstream chain direction is DATA-only chaff for now (see chain.rs).
