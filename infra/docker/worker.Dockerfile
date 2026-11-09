# PR-analysis worker image: the BullMQ worker plus every engine it shells out
# to, so no pass is silently skipped in production.
#   - codegate-scan (native Rust taint engine, services/taint-engine), release build
#   - Semgrep, with the p/ci ruleset baked in (no registry fetch per analysis)
#
# Build from the repository root:
#   docker build -f infra/docker/worker.Dockerfile -t codegate-worker .
# Run (DATABASE_URL, REDIS_URL, JWT_SECRET, ENCRYPTION_KEY, GITHUB_APP_* …):
#   docker run --env-file .env codegate-worker

# ── 1. Rust scan engine ──────────────────────────────────────────────────
FROM rust:1.86-bookworm AS taint-engine
WORKDIR /src
COPY services/taint-engine/ ./
RUN cargo build --release --locked && strip target/release/codegate-scan

# ── 2. TypeScript build (workspace: shared → db → api) ──────────────────
FROM node:22-bookworm AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.1.1 --activate
# Manifests first so the dependency layer is cached across code changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/db/package.json packages/db/
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter @codegate/api...
COPY packages/ packages/
COPY apps/api/ apps/api/
RUN pnpm --filter @codegate/db exec prisma generate \
 && pnpm --filter @codegate/shared build \
 && pnpm --filter @codegate/db build \
 && pnpm --filter @codegate/api build

# ── 3. Runtime ──────────────────────────────────────────────────────────
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates curl openssl \
 && rm -rf /var/lib/apt/lists/*
# Semgrep in its own venv, pinned; ruleset fetched once at build time.
RUN python3 -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.178.0 \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && curl -fsSL https://semgrep.dev/c/p/ci -o /opt/semgrep/ci.yml \
 && semgrep --validate --config /opt/semgrep/ci.yml --metrics off >/dev/null
COPY --from=taint-engine /src/target/release/codegate-scan /usr/local/bin/codegate-scan

WORKDIR /app
COPY --from=build /app /app

ENV NODE_ENV=production \
    CODEGATE_SCAN_BIN=/usr/local/bin/codegate-scan \
    CODEGATE_SEMGREP_CONFIG=/opt/semgrep/ci.yml \
    SEMGREP_SEND_METRICS=off

USER node
CMD ["node", "apps/api/dist/worker.js"]
