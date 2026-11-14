# V3 Rinjani CTI — Deployment Guide

By [RinjaniAnalytics](https://rinjanianalytics.com). Pairs with the [cti-platform-dashboard](https://github.com/rinjanianalytics/cti-platform-dashboard).

## Prerequisites

- **Node.js** 20+ — Tailwind 4 / `@tailwindcss/oxide` native binding for the embedded Workbench UI build won't resolve on Node 18
- **PostgreSQL** 16+ — canonical store
- **Redis** 7+ — both queues (port 6380 in dev) and cache (port 6381 in dev); one instance works, but separating them lets BullMQ tune AOF independently from the cache's LRU eviction
- **OpenSearch** 2.x — full-text + vector search; required for `/v2/search`, similar-entity lookup, and the OpenSearch event-stream consumer group
- **Neo4j** 5.x — actor/IOC/vuln/technique relationship graph; required by `/graph` and the `neo4j-sync` event-stream consumer
- **Docker** & **Docker Compose** — all four datastores bundled in `docker-compose.yml`

---

## Quick Start (Development)

### 1. Clone and Install

```bash
cd cti-platform-api
pnpm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database credentials and API keys
```

### 3. Start the data plane in Docker

```bash
docker compose up -d
```

This starts the **6-service data plane** the app talks to:

| Service | Port(s) | Role |
|---|---|---|
| `v3-postgres` | 5432 | Primary store (Drizzle) |
| `v3-pgbouncer` | 6432 | Transaction pooler in front of pg |
| `v3-redis-cache` | 6381 | LRU cache + rate-limit counters |
| `v3-redis-queue` | 6380 | BullMQ persistent queue (AOF) |
| `v3-opensearch` | 9200 | Search + vector |
| `v3-neo4j` | 7474 / 7687 | Graph (actors / IOCs / techniques) |

Everything else (the API as a container, Keycloak, Vault, Traefik,
prometheus stack) is gated behind opt-in compose profiles — see
`docker-compose.yml` and the **Docker compose profiles** section in
[README.md](README.md). The default `up -d` does **not** start `v3-api`, so it
won't collide with a host `pnpm dev` on `:3001`.

### 4. Run Database Migrations

```bash
# Push schema to database
pnpm --filter @rinjani/db push
```

### 5. Start Development Servers

```bash
# Start the API. Workers and the scheduler run inside it.
pnpm dev
```

**Services:**
- API: http://localhost:3001
- GraphQL Playground: http://localhost:3001/graphql
- Dashboard: http://localhost:3001 (static files in apps/dashboard)

---

## Production Deployment

### Option 1: Docker Compose

```bash
# Build the API image and start it alongside the data plane.
# The `apps` profile contains v3-api; without it the data services come up
# but no app process runs. Workers and the scheduler run inside v3-api.
# There is no separate worker container.
docker compose --profile apps up -d --build

# Add the gateway/telemetry/platform profiles as needed:
docker compose --profile apps --profile gateway --profile telemetry up -d
```

> **Note:** `docker-compose.yml` covers dev and prod through profiles. The
> command above is all a production host needs.
>
> `docker-compose.prod.yml` is an optional override. It adds resource
> limits to `v3-api` and puts Traefik with TLS in front of it, so the API
> publishes no port of its own. It still needs the `apps` profile, because
> `v3-api` lives in that profile:
>
> ```bash
> docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile apps up -d --build
> ```

#### Updating environment variables

⚠️ **`docker compose restart` does NOT re-read `.env`.** It restarts the
container process but keeps the existing environment. So a change to
`.env` — adding a new API key, rotating `JWT_SECRET`, updating
`CORS_ORIGINS`, etc. — won't take effect until you recreate the
container:

```bash
# After editing .env, do ONE of these — NOT `restart`:

# Just the API:
docker compose --profile apps up -d --force-recreate v3-api

# Or rebuild + recreate everything in the apps profile:
docker compose --profile apps up -d --force-recreate
```

This caught us during the 2026-06-01 production deploy: CORS headers
were missing for 20 minutes because the container had stale
`CORS_ORIGINS`. The `.env` had the right value the whole time.

### Option 2: Kubernetes (Helm)

```bash
# Add Helm dependencies
helm dependency update ./helm/v3-threat-intel

# Install chart
helm install v3-ti ./helm/v3-threat-intel \
  --set api.image.tag=latest \
  --set worker.enabled=false \
  --set cronjobs.enabled=false \
  --set postgresql.auth.password=YOUR_PASSWORD \
  --set redis.auth.password=YOUR_PASSWORD
```

> **Turn off `worker` and `cronjobs`.** The chart still defines a worker
> deployment and three feed-sync CronJobs, and both default to on. They
> use the image `rinjani/v3-worker`, which is no longer built: workers and
> the scheduler now run inside the API pod. Left on, those pods fail to
> pull their image.

**Helm Values:**
- `api.replicaCount` - Number of API pods (default: 2)
- `worker.enabled` - Legacy worker deployment. Set to `false`.
- `cronjobs.enabled` - Legacy feed-sync CronJobs. Set to `false`.
- `ingress.enabled` - Enable ingress (default: true)
- `ingress.tls.enabled` - Enable TLS (default: true)

### Option 3: Manual Deployment

```bash
# Build applications
pnpm build

# Start the API server. Workers and the scheduler run inside it.
cd apps/api
NODE_ENV=production node dist/index.js
```

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/db` |
| `JWT_SECRET` | Secret for JWT tokens | Generate with `openssl rand -hex 32` |
| `PORT` | API server port | `3001` |

### Optional (Intel Feeds)

| Variable | Description |
|----------|-------------|
| `ALIENVAULT_API_KEY` | AlienVault OTX API key |
| `CVE_API_KEY` | NIST NVD API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `RISKIQ_API_KEY` | RiskIQ PassiveTotal key |

See `.env.example` for full list.

---

## Database Migrations

### Production: auto-migrate on container boot (recommended)

Set `ENABLE_AUTO_MIGRATE=true` in `.env` and the API container will apply
any pending migrations on every boot before serving traffic. Idempotent
and cross-references both tracking tables (`__drizzle_migrations` +
`__sql_migrations`) so a previously-run CLI script doesn't cause
double-apply attempts.

```bash
# In .env on the droplet:
ENABLE_AUTO_MIGRATE=true
```

⚠️ **This is now the recommended default.** Without it, a deploy that
ships a new migration silently leaves the database on the old schema —
which manifests as 500 errors on whatever new route touches the new
table. We hit this on 2026-06-09 with `0048_ticket_links.sql`: the
ticketing scaffold PR shipped clean code + a fresh table, the table
never ran, and `POST /v1/cases/:id/tickets` returned 500 after
silently creating an orphan GitHub issue.

### Manual CLI fallback (emergency / first-time setup)

```bash
# Apply all pending migrations (idempotent, tracks in __sql_migrations)
docker exec v3-api sh -c 'cd /app && pnpm --filter @rinjani/db db:apply'

# Or hand-apply a single file (least preferred — no tracking record):
docker exec -i v3-postgres psql -U postgres -d rinjani_v3 \
  < packages/db/drizzle/0048_ticket_links.sql
```

### Development

```bash
# Push schema directly without versioned migrations (dev only)
pnpm --filter @rinjani/db push

# Generate a new migration after editing schema files
pnpm --filter @rinjani/db generate
pnpm --filter @rinjani/db migrate
```

---

## Worker startup grace (avoid post-restart thundering herd)

On the 8 GB droplet we saw a 15-minute post-restart lockout when
docker-compose recreated v3-api: feed-sync, IOC enrichment, embedding
warm-up, and several `*/15` cron jobs all fired simultaneously as the
event loop was still booting, pegging one core and timing out the
Postgres pool until the queue drained.

Set `WORKER_STARTUP_GRACE_MS=60000` to defer worker processing for the
first 60 s after boot. Jobs queue normally; processing waits. The data
plane gets room to finish its own warm-up first.

```bash
# In .env on the droplet:
WORKER_STARTUP_GRACE_MS=60000
```

Default is `0` (no grace) to preserve existing behaviour. Anything
larger than `0` opts the workers into the paused-on-boot path.

---

## Footgun: `environment:` lists vs `.env` (docker-compose.override.yml)

The production override on the droplet uses explicit `environment:`
lists (one `KEY=${VAR}` line per env var passed in), not `env_file:`.
That means **every new env var has to be added to the override** —
forgetting it silently leaves the container missing the value.

We hit this twice on 2026-06-09:

1. `GITHUB_TICKETING_TOKEN` + `GITHUB_WEBHOOK_SECRET` were added to
   `.env` but not to the override → the API returned
   `"GITHUB_TICKETING_TOKEN not configured"` despite the host having
   the right values.
2. The `-` separator was typed as `:` instead of `=` (`KEY:VALUE`
   instead of `KEY=VALUE`) — docker compose silently parses it as a
   key with empty value, no error.

**Fix when you hit it:** add the missing keys to v3-api's
`environment:` block using `KEY=${KEY:-}` interpolation, then
recreate:

```bash
docker compose -p rinjani-api up -d --no-deps --force-recreate v3-api
sleep 8
docker exec v3-api env | grep YOUR_NEW_VAR
```

A future cleanup will switch the override to `env_file: .env` so new
vars flow through automatically.

---

## Feed Sync

### Manual Sync

```bash
# Sync all feeds once
pnpm --filter @rinjani/worker sync:feeds

# Sync specific feed
pnpm --filter @rinjani/worker sync:cisa
pnpm --filter @rinjani/worker sync:alienvault
```

### Daemon Mode

```bash
# Workers, the scheduler and feed sync all run inside the API process.
# A single `pnpm dev` at the repo root boots everything.
pnpm dev
```

There is no standalone daemon. The BullMQ scheduler inside the API is the
only thing that dispatches feed syncs. Change a feed's schedule at
`/admin/feeds` in the dashboard or in Workbench.

### Kubernetes CronJobs

Do not use them. The Helm chart still ships CronJobs for CISA KEV,
AlienVault OTX and MITRE ATT&CK, but they run the retired worker image and
would duplicate the scheduler. Install the chart with
`--set cronjobs.enabled=false`.

---

## Monitoring

### Health Checks

```bash
curl http://localhost:3001/health
```

### Workbench — pipeline + queue dashboard

Browse to **`http://${DASHBOARD_URL}/admin/workbench`** while signed in as an
admin. The dashboard's Next.js rewrite proxies `/admin/workbench/*` same-origin
to the API, so the `rinjani_token` session cookie auto-authenticates Workbench
without a second login.

What's exposed:

| Tab | What it shows | When to use |
|-----|---------------|-------------|
| Overview | counts across all queues | health at a glance |
| Queues | per-queue depth + workers | spot a worker outage |
| Jobs | search + filter by status, tags (`source`, `feedId`, `iocId`, `cveId`) | post-mortem a specific run |
| Flows | parent/child DAG per feed-sync batch | confirm enrichment fan-out fired |
| Schedulers | the 13 cron-driven jobs + their next-fire times | adjust cadence (Edit / Run now / Disable per row) |

Schedule edits delegate to our own control plane (`scheduledJobOverrides` +
`reconcileScheduledJob`), so they survive the API boot reconcile loop. Both the
Workbench Schedulers tab and the native `/admin/schedules` dashboard page write
through the same backend.

Set `WORKBENCH_READONLY=true` in `.env` to hide retry / remove / promote
actions for low-trust admins.

### Service-health probe (one round-trip)

```bash
curl http://localhost:3001/admin/services -H "Authorization: Bearer ${JWT}"
```

Aggregates Postgres / OpenSearch / Neo4j / Redis (queue+cache) connectivity,
BullMQ queue depths, worker liveness, bootlock state, recent feed-sync
results, LLM provider configuration, and OSV/NVD enrichment-source status.
The dashboard's `/admin/services` page renders all of it on one screen.

### Metrics (OpenTelemetry + Prometheus)

Set `OTEL_ENABLED=true` and configure `OTEL_ENDPOINT`:

```bash
OTEL_ENABLED=true
OTEL_ENDPOINT=http://localhost:4318
```

The local observability stack lives behind the `telemetry` compose profile
(prometheus, grafana, loki, tempo, promtail, plus the redis/postgres/opensearch
exporters). Before starting it, configure the prometheus scrape key:

```bash
# 1. Mint a dedicated scrape key
KEY="prom-scrape-$(openssl rand -hex 16)"

# 2. Add the key to API_KEYS (read-only "viewer" role is sufficient)
#    and mirror it into PROMETHEUS_SCRAPE_API_KEY:
echo "PROMETHEUS_SCRAPE_API_KEY=$KEY" >> .env
# append ",$KEY:viewer" to the existing API_KEYS line in .env

# 3. Bring up prometheus — it sed-substitutes the env var into
#    config/prometheus/prometheus.template.yml at startup. Compose
#    fails fast if PROMETHEUS_SCRAPE_API_KEY is unset.
docker compose --profile telemetry up -d v3-prometheus
```

Without this, prometheus scrapes `/v1/ops/metrics/prometheus` with an empty
key every 15s and the API logs a steady stream of 401s.

### Logs

```bash
# Docker logs. Worker and scheduler output is in the API's log.
docker logs v3-api

# Kubernetes logs
kubectl logs -f deployment/v3-ti-api
```

---

## Security

### API Authentication

**JWT Tokens:**
```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "your-api-key"}'
```

**API Keys:**
```bash
curl http://localhost:3001/v1/vulnerabilities \
  -H "X-API-Key: your-api-key"
```

### TLS/HTTPS

For production, enable TLS in Kubernetes ingress or use a reverse proxy (nginx, Traefik).

---

## Troubleshooting

### Database Connection Errors

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql postgresql://postgres:postgres@localhost:5432/rinjani_v3
```

### Feeds Not Syncing

```bash
# Workers run inside the API, so check the API's log
docker logs v3-api

# Verify DATABASE_URL is set
echo $DATABASE_URL
```

### Port Already in Use

```bash
# Kill process on port 3001
lsof -ti:3001 | xargs kill -9
```

---

## Backup \u0026 Restore

### Database Backup

```bash
pg_dump -U postgres rinjani_v3 \u003e backup.sql
```

### Database Restore

```bash
psql -U postgres rinjani_v3 \u003c backup.sql
```

---

## Scaling

### Horizontal Scaling (Kubernetes)

```bash
# Scale API pods. A Redis boot lock keeps several pods from
# scheduling the same feed sync twice.
kubectl scale deployment v3-ti-api --replicas=5
```

### Vertical Scaling

Update resource limits in `helm/v3-threat-intel/values.yaml`:

```yaml
api:
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "2Gi"
      cpu: "2000m"
```

---

## OAuth Sign-in (Google + GitHub)

Operators and analysts sign in via Google or GitHub OAuth. The `api_key` paste
flow remains for service-to-service automation but is **not** the human path.

### 1. Register the OAuth apps

**Google** — https://console.cloud.google.com/apis/credentials
- Application type: Web application
- Authorised redirect URI: `${API_PUBLIC_URL}/auth/oauth/google/callback`
  (e.g. `http://localhost:3001/auth/oauth/google/callback` in dev)
- Copy Client ID + Client secret to env

**GitHub** — https://github.com/settings/developers → New OAuth App
- Homepage URL: your dashboard URL (e.g. `http://localhost:3000`)
- Authorisation callback URL: `${API_PUBLIC_URL}/auth/oauth/github/callback`
- Copy Client ID + Client secret to env

### 2. Set env vars (api side, `.env`)

```bash
# Where the dashboard lives (used for post-OAuth redirect)
DASHBOARD_URL=http://localhost:3000

# Public-facing API URL — must match the redirect URI registered with each provider
API_PUBLIC_URL=http://localhost:3001

GOOGLE_OAUTH_CLIENT_ID=…
GOOGLE_OAUTH_CLIENT_SECRET=…
GITHUB_OAUTH_CLIENT_ID=…
GITHUB_OAUTH_CLIENT_SECRET=…

# Comma-separated emails that get role=admin on first OAuth sign-in.
# Everyone else lands as 'viewer' and must be elevated manually.
ADMIN_EMAILS=ops@yourcompany.com,security-lead@yourcompany.com
```

### 3. First sign-in

Restart the API. The dashboard `/login` will discover available providers via
`GET /auth/oauth/providers` and render the matching buttons.

The `oauth_identities` table is created idempotently on first sign-in — no
manual migration step required.

### Operational notes

- **State + PKCE** are cookie-backed (HttpOnly, SameSite=Lax, 10 min TTL).
- **Token transport back to dashboard** is a one-time `?token=…` query param
  that the dashboard consumes and strips from the URL on load.
- **Existing users**: if an OAuth email matches an existing `users.email`,
  the new identity is linked to that user rather than creating a duplicate.
- **Role promotion**: changing `ADMIN_EMAILS` later only affects *new* users
  on their *first* sign-in. To elevate an existing user, update their
  `roles` via `/admin/rbac` (UI shipping in a follow-up) or in the DB.

---

## Support

- **Website**: [rinjanianalytics.com](https://rinjanianalytics.com)
- **Email**: [rinjanianalytics@gmail.com](mailto:rinjanianalytics@gmail.com)
- **Documentation**: See [README.md](README.md) (features + architecture) and [SECURITY_AUDIT.md](SECURITY_AUDIT.md) (latest dependency review)
- **Issues**: [GitHub Issues](https://github.com/rinjanianalytics/cti-platform-api/issues)
- **Dashboard repo**: [cti-platform-dashboard](https://github.com/rinjanianalytics/cti-platform-dashboard)
