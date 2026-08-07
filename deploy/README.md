# `construct-veil-relay` Docker deployment

One-VPS deployment of the veil-front **relay** plus a **pluggable cover** image via
`docker compose`.

Cover applications are **not** in this repository. See:

- [`COVER.md`](./COVER.md) — wire-up and contract summary
- construct-docs `decisions/veil-example-cover-modularity.md`
- construct-docs `manuals&Instructions/veil-example-cover-operator-checklist.md`

## Services

| Container | What | Host port |
|---|---|---|
| `cover` | **Your** private cover image (`COVER_IMAGE`). Serves ACME on host `:80` and the app on internal `:8080`. | `80` |
| `relay` | `construct-veil-relay` Rust binary. Terminates TLS, constant-shape gate, valid AUTH → gRPC backend / else → `cover:8080`. | `443` |
| `certbot` | Let's Encrypt cert issuance + renewal via webroot. Invoked manually (bootstrap) and from `cron` (renewal). | — |

## Prerequisites

- A VPS with Docker + `docker compose` plugin (Docker 20.10+).
- DNS A/AAAA for `$DOMAIN` (and every name in `$EXTRA_DOMAINS`) → VPS (ACME http-01).
- Ports `80` and `443` free on the host.
- A reachable Construct gRPC backend (host:port).
- A **private cover image** that meets `COVER.md` (long-lived H2/SSE, no protocol branding).

```bash
export COVER_IMAGE=ghcr.io/<you>/<private-cover>:latest
# VPS must be able to pull it (docker login to the private registry if needed)
```

### Single-name vs SAN (multi-name) cert

The cert is a single Let's Encrypt cert for `$DOMAIN` plus every comma-separated entry
in `$EXTRA_DOMAINS`. Typical pattern:

| Env var | Role |
|---|---|
| `DOMAIN` | Primary name — cert directory key, relay `--cert` path, client manifest `address` / `tls_sni`. |
| `EXTRA_DOMAINS` | Additional SANs on the same cert (e.g. apex + `api.*`). Host-aware routing is a **cover** concern. |

Adding/removing names after first bootstrap: re-run `./scripts/bootstrap.sh` — certbot
`--expand` grows/shrinks the cert.

If you're reusing a host that previously ran another service, stop it first:

```bash
ssh <vps>
sudo systemctl stop construct-relay   # or whichever unit name
sudo docker stop <old-container>      # if container-based
```

## Bootstrap (first deploy)

```bash
cd construct-veil/deploy
cp .env.example .env
$EDITOR .env                                # DOMAIN, EMAIL, BACKEND, ISSUER_PUBKEY, …
export COVER_IMAGE=ghcr.io/<you>/<private-cover>:latest
./scripts/bootstrap.sh
```

`bootstrap.sh` roughly:

1. `docker compose up -d cover` — cover listening on `:80` for ACME.
2. `docker compose run --rm certbot ...` — issues the cert into the `letsencrypt` volume.
3. Capability / ticket provisioning as configured for your environment.
4. `docker compose up -d relay` — relay on `:443`.
5. Prints SPKI from relay logs — pin this in the client manifest.

After bootstrap:

```bash
curl -sI "https://$DOMAIN/" | head -5
# long-lived path depends on YOUR cover (example SSE):
# curl -sN -m 5 "https://$DOMAIN/api/feed" | head -5
```

## Issue more tickets / capabilities

Use the scripts under `scripts/` and your home-server tooling. The relay reads
issuer material / tickets as documented for your deployment mode; restart the
relay container after changing mounted credential files when required.

## Cert renewal (host cron)

Let's Encrypt issues 90-day leaf certs; renew at ~60 days. Example root crontab:

```cron
0 3 * * 1 cd /opt/veil-front && ./scripts/renew-cert.sh >> /var/log/veil-renew.log 2>&1
```

The renew script:

1. `docker compose run --rm certbot renew --webroot -w /var/www/certbot`
2. If cert mtime changed: `docker compose restart relay`
3. Re-derive SPKI if your leaf key rotated (prefer `certbot --reuse-key`)

## Stop / inspect / debug

```bash
docker compose logs -f relay
docker compose logs -f cover
docker compose ps
docker compose down                 # preserves volumes
docker compose down -v              # FORCE re-bootstrap
```

## File layout

```
deploy/
├── README.md
├── COVER.md                    # pluggable cover contract
├── .env.example
├── docker-compose.yml          # local relay build + COVER_IMAGE
├── docker-compose.prod.yml     # GHCR relay + COVER_IMAGE
├── docker-compose.chain.yml    # optional chain overlay (ops)
├── Dockerfile.relay
├── scripts/
│   ├── bootstrap.sh
│   ├── issue-ticket.sh
│   └── renew-cert.sh
└── data/
    └── tickets/                # local/dev credential material if used
```

Production cover source trees live in **private** repositories, not here.

## Security notes

- `SSLKEYLOGFILE` is **not enabled** here. Only enable for classifier-capture runs.
- Do not commit production domains, SPKI pins, or chain graphs to the public tree.
- Prefer private registry paths for cover images — not `…/construct-veil/cover`.
- `letsencrypt` / `certbot-www` are named volumes; back them up if you need offsite copies.
