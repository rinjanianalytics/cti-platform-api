# V3 Rinjani CTI — Backend

**Modern, standalone threat intelligence backend with direct feed integration, embedded BullMQ pipeline monitoring, and a multi-tenant federation layer.**

By [RinjaniAnalytics](https://rinjanianalytics.com) — paired with the [v304 dashboard](https://github.com/rinjanianalytics/v304-dashboard-rinjani).

[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)
[![Hono](https://img.shields.io/badge/Hono-4.x-orange)](https://hono.dev/)
[![Drizzle](https://img.shields.io/badge/Drizzle-ORM-c5f74f?labelColor=000)](https://orm.drizzle.team/)
[![BullMQ](https://img.shields.io/badge/BullMQ-5.x-red)](https://bullmq.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🚀 Features

- **Direct feed sync, no middlemen** — CISA KEV · NVD · CVE.org cvelistV5 · MITRE ATT&CK · MISP Galaxy · AlienVault OTX · abuse.ch SSL/ThreatFox/URLhaus/MalwareBazaar · OpenPhish
- **Polyglot storage** — Postgres (Drizzle ORM) for the canonical store, OpenSearch for full-text + vector search, Neo4j for the threat-relationship graph, Redis for queues + cache
- **Pipeline orchestration** — BullMQ workers with `FlowProducer` parent/child graphs, scheduled jobs, work-driven enrichment via Postgres `NOTIFY`
- **Embedded Workbench BullMQ dashboard** — vendored fork at `/admin/workbench` with custom scheduler edit/run-now/disable actions delegating to our control plane (see [packages/workbench-core/](packages/workbench-core/))
- **TAXII 2.1 server** for downstream STIX consumers, alongside REST v1, REST v2, GraphQL (Pothos), and WebSocket subscriptions
- **Multi-tenant federation** — tenant schemas, peer connections, trust-level scoring
- **Type-safe end-to-end** — full TypeScript, Drizzle inferred schemas, zod validation at edges
- **Production-ready** — Docker, Kubernetes Helm chart, OpenTelemetry instrumentation, cross-process bootlock for safe HA

---

## 📊 Data Sources

| Source | Records | Update Frequency |
|--------|---------|------------------|
| **CISA KEV** | 1,501 vulnerabilities | Every 6 hours |
| **AlienVault OTX** | 50,000+ IOCs | Every 4 hours |
| **MITRE ATT&CK** | 835 techniques, 91 tools | Daily |
| **Threat Actors** | 187 APT groups | Daily |
| **Malware** | 696 families | Daily |

---

## 🏗️ Architecture

```
                         ┌───────────────────────────┐
                         │      Dashboard (3000)     │
                         │   Next.js + shadcn/ui     │
                         └──────────────┬────────────┘
                                        │  (same-origin proxy)
                  ┌─────────────────────┼─────────────────────┐
                  ▼                     ▼                     ▼
        ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
        │  Gateway (4000) │   │   API (3001)    │   │ /admin/workbench│
        │  GraphQL Mesh   │   │   Hono + REST   │   │  BullMQ ops UI  │
        │  Stitched APIs  │   │   GraphQL + WS  │   │  (vendored fork)│
        └─────────────────┘   └────────┬────────┘   └─────────────────┘
                                       │
                            BullMQ workers + scheduler
                            + feed-sync daemon + work
                            listener — in-process (one
                            Node runtime, bootlock-gated)
                                       │
   ┌───────────────────────────────────┼───────────────────────────────────┐
   ▼               ▼                   ▼                   ▼               ▼
┌──────┐   ┌──────────────┐   ┌────────────────┐   ┌──────────────┐   ┌────────┐
│ PG   │   │  OpenSearch  │   │     Neo4j      │   │    Redis     │   │ TAXII  │
│ canon│   │   FTS+vector │   │   relationship │   │ queue + cache│   │  2.1   │
└──────┘   └──────────────┘   └────────────────┘   └──────────────┘   └────────┘
                                       ▲
                                       │
                            ┌──────────┴───────────┐
                            │  Direct Threat Feeds │
                            │  CISA · NVD · CVE.org│
                            │  MITRE · OTX · MISP  │
                            │  abuse.ch × 4 · etc. │
                            └──────────────────────┘
```

Workers used to run as a separate `apps/worker` process; they're now folded into the API process (single `pnpm dev` runtime) with a Redis advisory bootlock so concurrent api+gateway processes don't double-schedule. `apps/worker` is kept as a build target for the `dev:standalone` daemon + one-off `sync:*` CLIs.

---

## 🚦 Quick Start

### Prerequisites

- Node.js 20+ or Bun 1.0+
- PostgreSQL 16+
- Redis 7+
- Docker & Docker Compose (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/rinjanianalytics/v3-backend-api-rinjani.git
cd v3-backend-api-rinjani

# Install dependencies
pnpm install

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Start Docker services
docker compose up -d

# Push database schema
pnpm --filter @rinjani/db push

# Start development servers
pnpm dev
```

**Services:**
- API: http://localhost:3001
- GraphQL: http://localhost:3001/graphql
- Health: http://localhost:3001/health

---

## 📁 Project Structure

```
v3-backend-api-rinjani/
├── apps/
│   ├── api/                 # Hono REST + GraphQL + WS + workers (port 3001)
│   │   └── src/
│   │       ├── routes/      # REST endpoints (v1, v2, /admin/*, /auth/*, /taxii/*)
│   │       ├── graphql/     # Pothos schema + resolvers
│   │       ├── middleware/  # Auth (JWT + cookie), CORS, rate limiting
│   │       ├── websocket/   # Real-time subscriptions
│   │       ├── queues/      # BullMQ workers + scheduler + FlowProducer wiring
│   │       └── services/    # Feed sync, enrichment, federation, neo4j, OTel
│   ├── gateway/             # GraphQL Mesh stitched-API gateway (port 4000)
│   ├── worker/              # CLI helpers + emergency standalone daemon
│   └── dashboard-static/    # Tiny static landing page (real UI lives in v304-dashboard)
├── packages/
│   ├── core/                # Shared services & types
│   ├── db/                  # Drizzle ORM schemas + migrations
│   └── workbench-core/      # Vendored fork of @getworkbench/core
│                            # (BullMQ ops UI mounted at /admin/workbench)
├── helm/v3-threat-intel/    # Kubernetes Helm chart
├── docker-compose.yml       # Development stack (PG + OpenSearch + Redis × 2 + Neo4j)
└── .env.example             # Environment template
```

---

## 🔌 API Endpoints

### REST API (v1)

| Endpoint | Description |
|----------|-------------|
| `GET /v1/vulnerabilities` | CVE/KEV data with filters |
| `GET /v1/iocs` | IOCs (IP, domain, hash, URL) |
| `GET /v1/tactics` | MITRE ATT&CK tactics |
| `GET /v1/techniques` | MITRE techniques |
| `GET /v1/threat-actors` | APT groups |
| `GET /v1/malware` | Malware families |
| `GET /v1/tools` | Adversary tools |
| `GET /v1/stats` | Dashboard statistics |

### Authentication

```bash
# Login with API key
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "your-api-key"}'

# Use JWT token
curl http://localhost:3001/v1/vulnerabilities \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### GraphQL

```graphql
query {
  vulnerabilities(limit: 10, severity: CRITICAL) {
    cveId
    description
    severity
    dateAdded
  }
}
```

---

## 🔄 Feed Sync

### Manual Sync

```bash
# Sync all feeds
pnpm --filter @rinjani/worker sync:feeds

# Sync specific feed
pnpm --filter @rinjani/worker sync:cisa
pnpm --filter @rinjani/worker sync:alienvault
```

### Daemon Mode

```bash
# Workers + scheduler + feed-sync daemon now run inside the API process.
# `pnpm dev` at the repo root starts everything as a single Node runtime.
pnpm dev

# Legacy standalone feed-only daemon (kept for emergency use, no BullMQ):
pnpm --filter @rinjani/worker dev:standalone
```

---

## 🐳 Docker Deployment

```bash
# Start all services
docker compose up -d

# View logs
docker logs v3-api
docker logs v3-worker

# Stop services
docker compose down
```

---

## ☸️ Kubernetes Deployment

```bash
# Install with Helm
helm install v3-ti ./helm/v3-threat-intel

# Scale API pods
kubectl scale deployment v3-ti-api --replicas=5

# View logs
kubectl logs -f deployment/v3-ti-api
```

See [DEPLOY.md](DEPLOY.md) for detailed deployment instructions.

---

## 🧪 Testing

```bash
# Run all tests
pnpm test

# Run specific package tests
pnpm --filter @rinjani/api test
pnpm --filter @rinjani/worker test
```

---

## 📊 Monitoring

### Health Check

```bash
curl http://localhost:3001/health
```

### Workbench — embedded pipeline dashboard

Mounted at **`/admin/workbench`** (proxied same-origin through the dashboard's
Next.js rewrite, so a logged-in admin session authenticates it automatically —
no second login).

Vendored fork of [`@getworkbench/core`](https://github.com/pontusab/workbench)
under [`packages/workbench-core/`](packages/workbench-core/) — we added
scheduler edit / disable / run-now actions that delegate to our own
`reconcileScheduledJob` control plane (raw BullMQ writes would be clobbered
by our boot-time reconcile loop).

What you see:
- **Overview / Queues / Jobs** — depth, throughput, failures across the
  `feed-sync`, `ioc-enrichment`, `feed-batch`, `cve-enrichment`, `alerts`,
  `notifications`, `neo4j-sync`, `ai-analysis`, `maintenance` queues
- **Flows** — `FlowProducer` parent/child graphs (each feed-sync builds one
  parent `batch-<runId>` in `feed-batch` plus N enrichment children — see
  [`apps/api/src/queues/workers/feedSyncWorker.ts`](apps/api/src/queues/workers/feedSyncWorker.ts))
- **Schedulers** — 13 cron entries from [`apps/api/src/queues/scheduler.ts`](apps/api/src/queues/scheduler.ts)
  with our kebab-menu actions (Edit interval / Run now / Disable). The native
  [`/admin/schedules`](https://github.com/rinjanianalytics/v304-dashboard-rinjani/blob/main/src/app/(app)/admin/schedules/page.tsx)
  page in the dashboard shares the same backend so edits stay consistent
  between both UIs

### Service-health probe

`GET /admin/services` returns a single JSON envelope with Postgres /
OpenSearch / Neo4j / Redis (queue+cache) connectivity, BullMQ queue depths,
worker liveness, bootlock state, feed-sync status, LLM provider
configuration, and enrichment-source health. The dashboard's
`/admin/services` page renders all of it in one pane.

### OpenTelemetry

```bash
# Enable telemetry
export OTEL_ENABLED=true
export OTEL_ENDPOINT=http://localhost:4318

# View traces in Jaeger
docker compose --profile telemetry up -d
open http://localhost:16686
```

---

## 🛠️ Development

### Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start dev servers |
| `pnpm build` | Build all packages |
| `pnpm test` | Run tests |
| `pnpm lint` | Lint code |
| `pnpm db:push` | Push schema to database |
| `pnpm db:studio` | Open Drizzle Studio |

### Adding a Custom Feed

1. Create plugin in `apps/worker/plugins/my-feed/`
2. Implement `FeedPlugin` interface
3. Add manifest.json
4. Plugin auto-discovered on startup

See `apps/worker/plugins/example-rss-feed/` for reference.

---

## 📚 Documentation

- [Deployment Guide](DEPLOY.md)
- [API Documentation](http://localhost:3001/docs) (when running)
- [GraphQL Playground](http://localhost:3001/graphql)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pnpm test`
5. Submit a pull request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **CISA** - Known Exploited Vulnerabilities Catalog
- **AlienVault** - Open Threat Exchange
- **MITRE** - ATT&CK Framework
- **RinjaniAnalytics** - Platform development

---

## 📞 Support

- **Website**: [rinjanianalytics.com](https://rinjanianalytics.com)
- **Email**: [rinjanianalytics@gmail.com](mailto:rinjanianalytics@gmail.com)
- **Dashboard repo**: [v304-dashboard-rinjani](https://github.com/rinjanianalytics/v304-dashboard-rinjani)
- **Issues**: [GitHub Issues](https://github.com/rinjanianalytics/v3-backend-api-rinjani/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rinjanianalytics/v3-backend-api-rinjani/discussions)
