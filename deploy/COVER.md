# Cover site (pluggable)

Production cover applications are **not** shipped in this repository.

The relay only needs a cleartext upstream after TLS termination:

```bash
construct-veil-relay ... --site cover:8080
```

Compose expects an external image:

```bash
export COVER_IMAGE=ghcr.io/<you>/<your-private-cover>:latest
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

## Contract

See construct-docs:

- `decisions/veil-example-cover-modularity.md` — why covers stay out of the public tree
- `manuals&Instructions/veil-example-cover-operator-checklist.md` — ports, long-lived H2/SSE, branding, smoke tests

### Minimum requirements

| Item | Requirement |
|------|-------------|
| Upstream | HTTP on `host:port` (default compose: `cover:8080`) |
| ACME | `:80` serves http-01 (or you terminate certs another way) |
| Shape | Long-lived streams (SSE / WS / long-poll) — not static-only |
| Identity | No Construct/VEIL branding; unique brand per public front |
| Source | Private repo / private image path (not `…/construct-veil/cover`) |

### Dev without a real cover

```bash
cargo run -p construct-veil-relay -- --dev
```

Uses the built-in minimal site in `site.rs` — **not** for production.

### Local compose with your cover checkout

```bash
# build any private cover that meets the contract
docker build -t my-cover:dev /path/to/your-private-cover
export COVER_IMAGE=my-cover:dev
docker compose up -d
```
