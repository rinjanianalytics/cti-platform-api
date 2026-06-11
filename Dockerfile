# =============================================================================
# V3 Dockerfile — API container
# =============================================================================
# Single image, one app: the API server. BullMQ scheduler + workers + the
# feed-sync code path all run inside this process — see
# apps/api/src/queues/scheduler.ts for the job registry.
#
# Uses tsx runtime (noEmit:true monorepo — no tsc build step needed).
# Debian-slim (not Alpine) because onnxruntime requires glibc.

FROM node:20-slim

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8 --activate

# Security: non-root user
RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs -s /bin/sh -m nodejs

# Install wget for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Package manifests (layer cache) ──
COPY --chown=nodejs:nodejs pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY --chown=nodejs:nodejs apps/api/package.json ./apps/api/
COPY --chown=nodejs:nodejs apps/worker/package.json ./apps/worker/
COPY --chown=nodejs:nodejs packages/db/package.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/package.json ./packages/core/
# workbench-core's manifest joins the install layer so its devDeps
# (tsup + vite + tailwind) are present when we build it below.
COPY --chown=nodejs:nodejs packages/workbench-core/package.json ./packages/workbench-core/

# Install all dependencies (tsx needed at runtime; tsup/vite needed to build workbench-core)
RUN pnpm install --frozen-lockfile

# ── Source code (api + worker + shared packages) ──
COPY --chown=nodejs:nodejs tsconfig.base.json ./
COPY --chown=nodejs:nodejs apps/api/tsconfig.json ./apps/api/
COPY --chown=nodejs:nodejs apps/api/src ./apps/api/src
COPY --chown=nodejs:nodejs apps/worker/tsconfig.json ./apps/worker/
COPY --chown=nodejs:nodejs apps/worker/src ./apps/worker/src
COPY --chown=nodejs:nodejs packages/db/src ./packages/db/src
COPY --chown=nodejs:nodejs packages/db/tsconfig.json ./packages/db/
# Drizzle SQL migrations are loaded at runtime by `packages/db/src/scripts/
# apply-migrations.ts` (invoked at API boot). Previously omitted, so every
# fresh deploy ran the API against an empty schema until someone bind-mounted
# the directory back into the container by hand.
COPY --chown=nodejs:nodejs packages/db/drizzle ./packages/db/drizzle
COPY --chown=nodejs:nodejs packages/core/src ./packages/core/src
COPY --chown=nodejs:nodejs packages/core/tsconfig.json ./packages/core/

# workbench-core: API imports `@rinjani/workbench-core` from
# apps/api/src/routes/admin/workbench.ts. The package's main is
# `./dist/index.js`, so the build has to run inside the image (otherwise
# the API crashes at import time with a `Cannot find module` error on
# the first request to /admin/workbench). The build needs the src + the
# tsup/vite/tailwind configs; the resulting `dist/` is what the API
# actually loads at runtime.
COPY --chown=nodejs:nodejs packages/workbench-core/tsconfig.json ./packages/workbench-core/
COPY --chown=nodejs:nodejs packages/workbench-core/tsup.config.ts ./packages/workbench-core/
COPY --chown=nodejs:nodejs packages/workbench-core/vite.config.ts ./packages/workbench-core/
COPY --chown=nodejs:nodejs packages/workbench-core/postcss.config.js ./packages/workbench-core/
COPY --chown=nodejs:nodejs packages/workbench-core/components.json ./packages/workbench-core/
COPY --chown=nodejs:nodejs packages/workbench-core/src ./packages/workbench-core/src
RUN pnpm --filter @rinjani/workbench-core build

# Create plugins directory for worker
RUN mkdir -p /app/plugins && chown nodejs:nodejs /app/plugins

# Environment
ENV NODE_ENV=production
ENV PORT=3001
ENV PLUGINS_DIR=/app/plugins
ENV NODE_PATH=/app/apps/api/node_modules

# Switch to non-root user
USER nodejs

# Expose API port (only used when running as API)
EXPOSE 3001

# Note: HEALTHCHECK is NOT defined here because this image serves both
# API (has /health endpoint) and Worker (no HTTP server). Each service
# defines its own healthcheck in docker-compose.yml.

# Default: run API server
CMD ["./apps/api/node_modules/.bin/tsx", "apps/api/src/index.ts"]
