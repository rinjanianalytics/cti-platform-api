# V3 Threat Intelligence Platform

**Modern, standalone threat intelligence backend with direct feed integration.**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🚀 Features

- **100% Independent** - Standalone threat intelligence platform
- **Direct Feed Sync** - CISA KEV, AlienVault OTX, MITRE ATT&CK
- **Modern Stack** - Hono, Drizzle ORM, PostgreSQL, OpenSearch
- **Type-Safe** - Full TypeScript with tRPC
- **Production Ready** - Docker, Kubernetes, CI/CD
- **Real-time** - WebSocket subscriptions
- **Monitored** - OpenTelemetry integration

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
┌─────────────────────────────────────────┐
│         V3 Backend (Standalone)         │
├─────────────────────────────────────────┤
│  API Server (3001)    Worker (Daemon)  │
│         │                    │          │
│         └────────┬───────────┘          │
│                  │                      │
│         ┌────────▼────────┐             │
│         │  PostgreSQL DB  │             │
│         │   (rinjani_v3)  │             │
│         └─────────────────┘             │
└─────────────────────────────────────────┘
                   ▲
                   │
      ┌────────────┴────────────┐
      │  Public Threat Feeds    │
      ├─────────────────────────┤
      │  • CISA KEV             │
      │  • AlienVault OTX       │
      │  • MITRE ATT&CK         │
      └─────────────────────────┘
```

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
│   ├── api/                 # Hono API server
│   │   ├── src/
│   │   │   ├── routes/      # REST endpoints
│   │   │   ├── graphql/     # GraphQL schema
│   │   │   ├── middleware/  # Auth, CORS, rate limiting
│   │   │   └── websocket/   # Real-time subscriptions
│   │   └── Dockerfile
│   ├── worker/              # Feed sync worker
│   │   ├── src/
│   │   │   ├── feeds/       # CISA, AlienVault, MITRE
│   │   │   ├── core/        # Plugin system
│   │   │   └── plugins/     # Custom feed plugins
│   │   └── Dockerfile
│   └── dashboard/           # Static HTML dashboard
├── packages/
│   ├── db/                  # Drizzle ORM schemas
│   │   └── src/schema/      # Database tables
│   └── core/                # Shared services & types
├── helm/                    # Kubernetes Helm chart
│   └── v3-threat-intel/
├── .github/workflows/       # CI/CD pipeline
├── docker-compose.yml       # Development stack
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

- **Issues**: [GitHub Issues](https://github.com/rinjanianalytics/v3-backend-api-rinjani/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rinjanianalytics/v3-backend-api-rinjani/discussions)
