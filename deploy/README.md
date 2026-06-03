# `construct-veil-relay` Docker deployment

One-VPS deployment of the veil-front relay + cover application via
`docker compose`. Implements the operational checklist from
`construct-docs/raw/02_Core_Crypto/protocols/M0_COVER_APP_DEPLOYMENT.md`.

## Services

| Container | What | Host port |
|---|---|---|
| `cover` | Node.js cover-site (Диваны и Кресла — custom-furniture workshop landing + live production tracker via SSE). Serves the public site on internal `:8080`, ACME http-01 challenges + `https://` redirect on host `:80`. | `80` |
| `relay` | `construct-veil-relay` Rust binary. Terminates TLS, runs the constant-shape gate, routes valid AUTH to gRPC backend / everything else to `cover:8080`. | `443` |
| `certbot` | Let's Encrypt cert issuance + renewal via webroot challenge. Invoked manually (bootstrap) and from `cron` (renewal). | — |

## Prerequisites

- A VPS with Docker + `docker compose` plugin (Docker 20.10+).
- DNS A/AAAA record for `$DOMAIN` (and every name in `$EXTRA_DOMAINS`) pointing at the VPS — required so ACME http-01 challenge passes for each SAN name.
- Ports `80` and `443` free on the VPS host.
- A reachable Construct gRPC backend (host:port) — the relay's tunnel target.

### Single-name vs SAN (multi-name) cert

The cert is a single Let's Encrypt cert issued for `$DOMAIN` plus every comma-separated entry in `$EXTRA_DOMAINS`. Typical layout for our case:

| Env var | Value | What it does |
|---|---|---|
| `DOMAIN` | `api.divany-kresla.uk` | Primary name — this is the cert directory key (`/etc/letsencrypt/live/api.divany-kresla.uk/`), the relay's `--cert` path, the client manifest's `address`/`tls_sni`. |
| `EXTRA_DOMAINS` | `divany-kresla.uk` | Additional SAN entries on the same cert. The cover-site's host-aware routing serves the marketing landing on the root domain and a minimal JSON identity on the `api.*` subdomain. |

Adding/removing names after first bootstrap: re-run `./scripts/bootstrap.sh` — certbot is invoked with `--expand`, which transparently grows the existing cert to cover new SANs (or shrinks it if you remove entries).

If you're reusing one of the existing `ice.*.konstruct.cc` hosts that
was running `construct-relay`, stop the old service first:

```bash
ssh <vps>
sudo systemctl stop construct-relay   # or whichever unit name
sudo systemctl disable construct-relay
sudo docker stop <old-container>      # if container-based
```

## Bootstrap (first deploy)

```bash
cd construct-veil/deploy
cp .env.example .env
$EDITOR .env                                # fill DOMAIN, EMAIL, BACKEND
./scripts/bootstrap.sh
```

`bootstrap.sh` runs the orchestrated sequence:

1. `docker compose up -d cover` — cover-site listening on `:80` for ACME.
2. `docker compose run --rm certbot ...` — issues the cert via webroot
   challenge into the `letsencrypt` named volume.
3. Generates one veil-front ticket (60-day validity) into
   `data/tickets/tickets.json`.
4. `docker compose up -d relay` — relay starts on `:443`.
5. Prints the SPKI hex from relay logs — copy this into the client
   manifest as `pinned_spki`.
6. Prints the issued ticket base64 — copy this into the client manifest
   as `veil_front_ticket`.

After bootstrap the relay is live. Verify:

```bash
curl -sI https://$DOMAIN/                   # 200, served by cover-site
curl -sI https://$DOMAIN/api/feed | head    # 200, content-type: text/event-stream
```

## Issue more tickets

```bash
./scripts/issue-ticket.sh --days 60         # appends to tickets.json
./scripts/issue-ticket.sh --days 60 --reload-relay   # also restarts relay
```

The relay reads `tickets.json` once at startup. Restart the relay
container after appending new tickets if you want the running process
to pick them up.

## Cert renewal (host cron)

Let's Encrypt issues 90-day leaf certs; renew at 60 days. Add to root
crontab:

```cron
0 3 * * 1 cd /opt/veil-front && ./scripts/renew-cert.sh >> /var/log/veil-renew.log 2>&1
```

The renew script:
1. `docker compose run --rm certbot renew --webroot -w /var/www/certbot`
2. If cert was renewed (cert mtime changed): `docker compose restart relay`
3. Re-derives + republishes the SPKI to wherever the manifest lives.

## Stop / inspect / debug

```bash
docker compose logs -f relay        # follow relay logs
docker compose logs -f cover        # follow cover logs
docker compose ps                   # state of services
docker compose down                 # stop everything (preserves volumes)
docker compose down -v              # stop + delete volumes (FORCE re-bootstrap)
```

## File layout

```
deploy/
├── README.md
├── .env.example
├── docker-compose.yml
├── Dockerfile.relay              # multi-stage Rust build
├── Dockerfile.cover              # node:22-alpine
├── cover-site/
│   ├── package.json
│   ├── server.js
│   └── public/
│       ├── index.html
│       ├── about.html
│       ├── app.js
│       ├── styles.css
│       ├── robots.txt
│       ├── favicon.ico         # supply your own
│       └── .well-known/security.txt
├── scripts/
│   ├── bootstrap.sh            # first-deploy orchestration
│   ├── issue-ticket.sh         # add tickets
│   └── renew-cert.sh           # cron-driven renewal
└── data/
    └── tickets/                # generated; tickets.json lives here
```

## Security notes

- `SSLKEYLOGFILE` is **not enabled** in this compose file. Only enable
  it manually for classifier-capture runs, then re-deploy without it.
- `tickets.json` is bind-mounted **read-only** into the relay; never
  edit while the container is running (atomic replacement is fine).
- The `letsencrypt` and `certbot-www` volumes are docker-managed named
  volumes; back them up with `docker run --rm -v letsencrypt:/x alpine
  tar c -C /x .` if you want offsite copies.
