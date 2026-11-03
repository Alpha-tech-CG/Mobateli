import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeConfig } from "./config-rules.js";

const ids = (file: string, lines: string[]) =>
  analyzeConfig(
    lines.map((content, i) => ({ file, line: i + 1, content })),
    [file],
  ).map((f) => f.ruleId);

test("workflows: real risks are flagged", () => {
  const wf = ".github/workflows/ci.yml";
  assert.deepEqual(ids(wf, ["          ref: ${{ github.event.pull_request.head.sha }}"]), ["GHA_PR_TARGET_CHECKOUT"]);
  assert.deepEqual(ids(wf, ["permissions: write-all"]), ["GHA_WRITE_ALL"]);
  assert.deepEqual(ids(wf, ['        run: echo "${{ github.event.pull_request.title }}"']), ["GHA_SCRIPT_INJECTION"]);
  assert.deepEqual(ids(wf, ["        run: echo ${{ secrets.NPM_TOKEN }}"]), ["GHA_SECRET_ECHO"]);
  assert.deepEqual(ids(wf, ["      - uses: someone/deploy-action@main"]), ["GHA_UNPINNED_ACTION"]);
  assert.deepEqual(ids(wf, ["        run: curl -fsSL https://x.sh | bash"]), ["REMOTE_SCRIPT_PIPE"]);
});

test("workflows: safe patterns produce no finding", () => {
  const wf = ".github/workflows/ci.yml";
  assert.deepEqual(
    ids(wf, [
      "permissions:",
      "  contents: read",
      "      - uses: actions/checkout@v4",
      "      - uses: pnpm/action-setup@v4",
      "        env:",
      "          TITLE: ${{ github.event.pull_request.title }}",
      '        run: echo "$TITLE"',
      "        run: pnpm --filter @codegate/api test",
      "      DATABASE_URL: postgresql://codegate:codegate@127.0.0.1:5434/codegate_test",
    ]),
    [],
  );
});

test("docker-compose: privileged, docker socket, exposed database, host network", () => {
  const dc = "infra/docker/docker-compose.yml";
  assert.deepEqual(ids(dc, ["    privileged: true"]), ["COMPOSE_PRIVILEGED"]);
  assert.deepEqual(ids(dc, ["      - /var/run/docker.sock:/var/run/docker.sock"]), ["COMPOSE_DOCKER_SOCKET"]);
  assert.deepEqual(ids(dc, ['      - "5434:5432"']), ["COMPOSE_DB_EXPOSED"]);
  assert.deepEqual(ids(dc, ['      - "127.0.0.1:5434:5432"', '      - "3000:3000"']), [], "loopback or non-db ports are fine");
  assert.deepEqual(ids(dc, ["    network_mode: host"]), ["COMPOSE_HOST_NETWORK"]);
});

test("Dockerfile, vercel.json and committed .env", () => {
  assert.deepEqual(ids("Dockerfile", ["FROM node:latest", "FROM node:22-slim AS build"]), ["DOCKER_LATEST_TAG"]);
  assert.deepEqual(ids("apps/web/vercel.json", ['  "framework": "nextjs",', '  "regions": ["fra1"]']), []);
  assert.deepEqual(ids("vercel.json", ['{ "key": "Access-Control-Allow-Origin", "value": "*" }']), ["VERCEL_CORS_WILDCARD"]);
  assert.deepEqual(ids(".env", ["DATABASE_URL=x"]), ["ENV_FILE_COMMITTED"]);
  assert.deepEqual(ids(".env.example", ["DATABASE_URL="]), []);
});
