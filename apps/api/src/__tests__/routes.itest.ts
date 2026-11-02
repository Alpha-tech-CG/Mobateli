/**
 * End-to-end integration tests. Boots the real Fastify app and drives it with
 * app.inject() (no network) against a dedicated test database.
 *
 * Prereq: `node scripts/setup-test-db.mjs` (recreates codegate_test), Postgres
 * and Redis running. Run with `pnpm --filter @codegate/api test:integration`.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

// Env must be set before the app/db modules load their config.
process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL ??
  "postgresql://codegate:codegate@127.0.0.1:5434/codegate_test";
process.env.REDIS_URL = process.env.REDIS_URL ?? "redis://127.0.0.1:6380";
process.env.JWT_SECRET = "integration_test_jwt_secret_0123456789abcd";
process.env.ENCRYPTION_KEY = Buffer.from("0123456789abcdef0123456789abcdef").toString("base64");
process.env.GITHUB_WEBHOOK_SECRET = "it_gh_secret";
process.env.VERCEL_WEBHOOK_SECRET = "it_vercel_secret";

const { buildApp } = await import("../app.js");
const { loadConfig } = await import("../config.js");
const { prisma } = await import("@codegate/db");
const { getRedis } = await import("../lib/redis.js");

type App = Awaited<ReturnType<typeof buildApp>>;
let app: App;
let token = "";
let repoId = "";

const auth = () => ({ authorization: `Bearer ${token}` });
const ghSig = (body: string) =>
  "sha256=" + createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET!).update(body).digest("hex");
const vercelSig = (body: string) =>
  createHmac("sha1", process.env.VERCEL_WEBHOOK_SECRET!).update(body).digest("hex");

before(async () => {
  app = await buildApp(loadConfig());
  await app.ready();
  // Fresh state (idempotent across reruns).
  await prisma.$executeRawUnsafe(
    `TRUNCATE TABLE organizations RESTART IDENTITY CASCADE;`,
  );
});

after(async () => {
  await app.close();
  getRedis(process.env.REDIS_URL!).disconnect();
});

test("signup bootstraps org + owner and returns a token", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: {
      email: "owner@acme.test",
      password: "supersecret-password",
      name: "Owner",
      organizationName: "Acme",
    },
  });
  assert.equal(res.statusCode, 201);
  token = res.json().token;
  assert.ok(token.length > 20);
});

test("protected route needs auth", async () => {
  assert.equal((await app.inject({ method: "GET", url: "/api/v1/organization" })).statusCode, 401);
  const ok = await app.inject({ method: "GET", url: "/api/v1/organization", headers: auth() });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().name, "Acme");
});

test("login enforces credentials", async () => {
  const bad = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "owner@acme.test", password: "wrong" },
  });
  assert.equal(bad.statusCode, 401);
  const good = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "owner@acme.test", password: "supersecret-password" },
  });
  assert.equal(good.statusCode, 200);
});

test("validation errors are 400 with field info", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: { email: "x@y.test", password: "short", name: "X", organizationName: "Y" },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, "validation_error");
});

test("policies: create + list (RBAC owner allowed)", async () => {
  const create = await app.inject({
    method: "POST",
    url: "/api/v1/policies",
    headers: auth(),
    payload: { rule: "Bloquer les secrets", action: "block", severityThreshold: "high" },
  });
  assert.equal(create.statusCode, 201);
  const list = await app.inject({ method: "GET", url: "/api/v1/policies", headers: auth() });
  assert.equal(list.json().policies.length, 1);
});

test("linear integration: connect, status hides the key", async () => {
  const con = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/linear",
    headers: auth(),
    payload: { apiKey: "lin_api_secret_key_value", teamId: "TEAM-X" },
  });
  assert.equal(con.statusCode, 201);
  const status = await app.inject({
    method: "GET",
    url: "/api/v1/integrations/linear",
    headers: auth(),
  });
  const body = status.json();
  assert.equal(body.connected, true);
  assert.equal(body.teamId, "TEAM-X");
  assert.ok(!("apiKey" in body));
});

test("github webhook: bad signature 401, signed PR 202 and persisted", async () => {
  const org = await prisma.organization.findFirstOrThrow();
  await prisma.githubInstallation.create({
    data: { organizationId: org.id, installationId: 999n, accountLogin: "acme" },
  });

  const payload = JSON.stringify({
    action: "opened",
    installation: { id: 999 },
    repository: { id: 555, full_name: "acme/app", default_branch: "main" },
    pull_request: {
      id: 5001,
      number: 3,
      title: "Add feature via Copilot",
      user: { login: "copilot[bot]" },
      body: "Generated with Copilot",
      head: { sha: "deadbeef" },
    },
  });

  const bad = await app.inject({
    method: "POST",
    url: "/webhooks/github",
    headers: { "content-type": "application/json", "x-github-event": "pull_request", "x-github-delivery": "d1", "x-hub-signature-256": "sha256=bad" },
    payload,
  });
  assert.equal(bad.statusCode, 401);

  const ok = await app.inject({
    method: "POST",
    url: "/webhooks/github",
    headers: { "content-type": "application/json", "x-github-event": "pull_request", "x-github-delivery": "d2", "x-hub-signature-256": ghSig(payload) },
    payload,
  });
  assert.equal(ok.statusCode, 202);

  const prs = await app.inject({ method: "GET", url: "/api/v1/pull-requests", headers: auth() });
  const list = prs.json().pullRequests;
  assert.equal(list.length, 1);
  assert.equal(list[0].repository, "acme/app");
  assert.equal(list[0].aiGenerated, true);

  const repos = await app.inject({ method: "GET", url: "/api/v1/repositories", headers: auth() });
  repoId = repos.json().repositories[0].id;
  assert.ok(repoId);
});

test("agent guard: secrets locked, allowlist governs network", async () => {
  const secret = await app.inject({
    method: "POST",
    url: "/api/v1/agent/guard",
    headers: auth(),
    payload: { repositoryId: repoId, permission: "modify_secrets", target: "DATABASE_URL" },
  });
  assert.equal(secret.json().decision, "deny");

  await app.inject({
    method: "PUT",
    url: `/api/v1/repositories/${repoId}/agent-policies`,
    headers: auth(),
    payload: { permission: "network_access", decision: "deny", allowlist: ["api.github.com"] },
  });
  const allowed = await app.inject({
    method: "POST",
    url: "/api/v1/agent/guard",
    headers: auth(),
    payload: { repositoryId: repoId, permission: "network_access", target: "api.github.com" },
  });
  assert.equal(allowed.json().decision, "allow");
  const denied = await app.inject({
    method: "POST",
    url: "/api/v1/agent/guard",
    headers: auth(),
    payload: { repositoryId: repoId, permission: "network_access", target: "evil.com" },
  });
  assert.equal(denied.json().decision, "deny");
});

test("vercel deploy gate: signed deployment 202 and recorded", async () => {
  const payload = JSON.stringify({
    type: "deployment.created",
    payload: {
      deployment: {
        id: "dpl_it_1",
        target: "production",
        meta: { githubCommitOrg: "acme", githubCommitRepo: "app", githubCommitRef: "main", githubCommitSha: "c0ffee" },
      },
    },
  });
  const res = await app.inject({
    method: "POST",
    url: "/webhooks/vercel",
    headers: { "content-type": "application/json", "x-vercel-signature": vercelSig(payload), "x-vercel-id": "v1" },
    payload,
  });
  assert.equal(res.statusCode, 202);

  const checks = await app.inject({ method: "GET", url: "/api/v1/deploy-checks", headers: auth() });
  const list = checks.json().deployChecks;
  assert.equal(list.length, 1);
  assert.ok(["authorized", "warning", "blocked", "requires_approval"].includes(list[0].decision));
});

test("audit export returns a JSON evidence pack", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/audit/export",
    headers: auth(),
    payload: { format: "json" },
  });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers["content-type"] as string, /application\/json/);
  const pack = res.json();
  assert.equal(pack.organization.name, "Acme");
  assert.ok(pack.summary.auditEvents > 0);
});
