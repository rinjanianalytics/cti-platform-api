# =============================================================================
# V3 API Dockerfile
# =============================================================================
# Single-stage build with tsx runtime.
# The monorepo uses noEmit:true so tsc only type-checks, tsx runs TS at runtime.
# Uses Debian-slim (not Alpine) because onnxruntime requires glibc.

FROM node:22-slim

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8 --activate

# Security: non-root user (created early, used later)
RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs -s /bin/sh -m nodejs

# Install wget for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first for better layer caching
COPY --chown=nodejs:nodejs pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY --chown=nodejs:nodejs apps/api/package.json ./apps/api/
COPY --chown=nodejs:nodejs packages/db/package.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/package.json ./packages/core/

# Install all dependencies (tsx is needed at runtime)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY --chown=nodejs:nodejs tsconfig.base.json ./
COPY --chown=nodejs:nodejs apps/api/tsconfig.json ./apps/api/
COPY --chown=nodejs:nodejs apps/api/src ./apps/api/src
COPY --chown=nodejs:nodejs packages/db/src ./packages/db/src
COPY --chown=nodejs:nodejs packages/db/tsconfig.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/src ./packages/core/src
COPY --chown=nodejs:nodejs packages/core/tsconfig.json ./packages/core/

# Environment
ENV NODE_ENV=production
ENV PORT=3001

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

# Start the application using tsx (esbuild-backed TS runtime)
CMD ["./apps/api/node_modules/.bin/tsx", "apps/api/src/index.ts"]
