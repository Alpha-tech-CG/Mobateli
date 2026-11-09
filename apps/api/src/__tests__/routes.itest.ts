/**
 * End-to-end integration tests. Boots the real Fastify app and drives it with
 * app.inject() (no network) against a dedicated test database.
 *
 * Prereq: `node scripts/setup-test-db.mjs` (recreates codegate_test), Postgres
 * and Redis running. Run with `pnpm --filter @codegate/api test:integration`.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomUUID } from "node:crypto";

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
// The suite drives admin routes with a fresh owner; MFA enforcement is unit-tested.
process.env.MFA_REQUIRED_FOR_ADMINS = "false";
process.env.CRON_SECRET = "it_cron_secret_0123456789abcdef";
// The whole suite runs from 127.0.0.1 in a few seconds on CI.
process.env.RATE_LIMIT_PER_MINUTE = "100000";
process.env.GITHUB_APP_SLUG = "codegate-it";
process.env.GITHUB_CLIENT_ID = "Iv1.it_client";
process.env.GITHUB_CLIENT_SECRET = "it_client_secret";
process.env.WEB_ORIGIN = "http://localhost:3000";

const { buildApp } = await import("../app.js");
const { loadConfig } = await import("../config.js");
const { prisma, startDbKeepAlive } = await import("@codegate/db");
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

let stopKeepAlive: (() => void) | undefined;

before(async () => {
  app = await buildApp(loadConfig());
  await app.ready();
  // Keep the DB connection warm so the suite doesn't thrash on reconnects.
  stopKeepAlive = startDbKeepAlive(10_000);
  // Fresh state (idempotent across reruns).
  await prisma.$executeRawUnsafe(
    `TRUNCATE TABLE organizations RESTART IDENTITY CASCADE;`,
  );
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE auth_throttles, webhook_deliveries;`);
});

after(async () => {
  stopKeepAlive?.();
  await app.close();
  getRedis(process.env.REDIS_URL!).disconnect();
  // An open Prisma pool can keep the runner alive after the last test.
  await prisma.$disconnect();
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
      acceptTerms: true,
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
    payload: { email: "x@y.test", password: "short", name: "X", organizationName: "Y", acceptTerms: true },
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
    payload: { apiKey: ["lin_api", "secret_key_value"].join("_"), teamId: "TEAM-X" },
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
    headers: { "content-type": "application/json", "x-github-event": "pull_request", "x-github-delivery": randomUUID(), "x-hub-signature-256": ghSig(payload) },
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

test("finding feedback: mark false positive, propagate by fingerprint, metrics, clear", async () => {
  const mkPr = (n: number) =>
    prisma.pullRequest.create({
      data: { repositoryId: repoId, externalId: `fb-${n}`, number: 900 + n, title: "t", author: "a" },
    });
  const [pr1, pr2] = [await mkPr(1), await mkPr(2)];
  const base = { type: "sast" as const, severity: "medium" as const, title: "Hash", description: "d", ruleId: "WEAK_HASH" };
  const f1 = await prisma.finding.create({ data: { ...base, pullRequestId: pr1.id, filePath: "a.ts", line: 3, fingerprint: "fp-hash" } });
  const f2 = await prisma.finding.create({ data: { ...base, pullRequestId: pr2.id, filePath: "a.ts", line: 9, fingerprint: "fp-hash" } });
  const legacy = await prisma.finding.create({ data: { ...base, pullRequestId: pr1.id, fingerprint: null } });

  const bad = await app.inject({ method: "PUT", url: `/api/v1/findings/${f1.id}/feedback`, headers: auth(), payload: { verdict: "maybe" } });
  assert.equal(bad.statusCode, 400);
  const noFp = await app.inject({ method: "PUT", url: `/api/v1/findings/${legacy.id}/feedback`, headers: auth(), payload: { verdict: "false_positive" } });
  assert.equal(noFp.statusCode, 409);
  const unknown = await app.inject({ method: "PUT", url: `/api/v1/findings/${randomUUID()}/feedback`, headers: auth(), payload: { verdict: "false_positive" } });
  assert.equal(unknown.statusCode, 404);

  const ok = await app.inject({
    method: "PUT",
    url: `/api/v1/findings/${f1.id}/feedback`,
    headers: auth(),
    payload: { verdict: "false_positive", note: "checksum, not a password" },
  });
  assert.equal(ok.statusCode, 200);
  // Same fingerprint in another PR of the repo gets the verdict too.
  assert.equal((await prisma.finding.findUnique({ where: { id: f2.id } }))!.status, "false_positive");
  const stored = await prisma.findingFeedback.findMany({ where: { repositoryId: repoId } });
  assert.equal(stored.length, 1);
  assert.equal(stored[0]!.note, "checksum, not a password");

  const metrics = await app.inject({ method: "GET", url: "/api/v1/metrics/rule-quality?days=30", headers: auth() });
  assert.equal(metrics.statusCode, 200);
  const weak = metrics.json().rules.find((r: { ruleId: string }) => r.ruleId === "WEAK_HASH");
  assert.equal(weak.falsePositives, 2);
  assert.equal(weak.falsePositiveRate, 1);

  const audit = await prisma.auditEvent.findFirst({ where: { action: "finding.feedback" } });
  assert.ok(audit, "verdict audited");

  const cleared = await app.inject({ method: "DELETE", url: `/api/v1/findings/${f1.id}/feedback`, headers: auth() });
  assert.equal(cleared.statusCode, 204);
  assert.equal((await prisma.finding.findUnique({ where: { id: f2.id } }))!.status, "open");
  assert.equal(await prisma.findingFeedback.count({ where: { repositoryId: repoId } }), 0);
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
    headers: { "content-type": "application/json", "x-vercel-signature": vercelSig(payload), "x-vercel-id": randomUUID() },
    payload,
  });
  assert.equal(res.statusCode, 202);

  const checks = await app.inject({ method: "GET", url: "/api/v1/deploy-checks", headers: auth() });
  const list = checks.json().deployChecks;
  assert.equal(list.length, 1);
  assert.ok(["authorized", "warning", "blocked", "requires_approval"].includes(list[0].decision));
});

test("gitlab: connect token governs the MR webhook", async () => {
  const con = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/gitlab",
    headers: auth(),
  });
  assert.equal(con.statusCode, 201);
  const gitlabToken: string = con.json().webhookToken;
  assert.ok(gitlabToken.length > 10);

  const payload = JSON.stringify({
    object_kind: "merge_request",
    user: { username: "cursor-bot" },
    project: { id: 42, path_with_namespace: "acme/infra", default_branch: "main" },
    object_attributes: {
      iid: 9,
      title: "Harden config",
      description: "Generated with Cursor",
      action: "open",
      last_commit: { id: "abcdef1" },
    },
  });

  // Wrong token → 401.
  const bad = await app.inject({
    method: "POST",
    url: "/webhooks/gitlab",
    headers: { "content-type": "application/json", "x-gitlab-token": "nope", "x-gitlab-event": "Merge Request Hook" },
    payload,
  });
  assert.equal(bad.statusCode, 401);

  // Valid token → 202 and the MR is persisted as a PR.
  const ok = await app.inject({
    method: "POST",
    url: "/webhooks/gitlab",
    headers: { "content-type": "application/json", "x-gitlab-token": gitlabToken, "x-gitlab-event": "Merge Request Hook" },
    payload,
  });
  assert.equal(ok.statusCode, 202);

  const prs = await app.inject({ method: "GET", url: "/api/v1/pull-requests", headers: auth() });
  const gl = prs.json().pullRequests.find((p: { repository: string }) => p.repository === "acme/infra");
  assert.ok(gl, "GitLab MR should appear as a pull request");
  assert.equal(gl.number, 9);
  assert.equal(gl.aiGenerated, true);

  // Another org's GitLab token can't inject MRs into acme's project.
  const other = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: {
      email: "intruder@other.test",
      password: "intruder-password-123",
      name: "Intruder",
      organizationName: "Other",
      acceptTerms: true,
    },
  });
  const otherCon = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/gitlab",
    headers: { authorization: `Bearer ${other.json().token}` },
  });
  const hijack = await app.inject({
    method: "POST",
    url: "/webhooks/gitlab",
    headers: {
      "content-type": "application/json",
      "x-gitlab-token": otherCon.json().webhookToken,
      "x-gitlab-event": "Merge Request Hook",
    },
    payload: payload.replace('"iid":9', '"iid":10'),
  });
  assert.equal(hijack.statusCode, 403);
});

test("members: an admin cannot mint an owner", async () => {
  const invite = await app.inject({
    method: "POST",
    url: "/api/v1/organization/members",
    headers: auth(),
    payload: { email: "admin2@acme.test", role: "admin" },
  });
  assert.equal(invite.statusCode, 201);
  const login = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "admin2@acme.test", password: invite.json().tempPassword },
  });
  const adminAuth = { authorization: `Bearer ${login.json().token}` };
  const escalate = await app.inject({
    method: "POST",
    url: "/api/v1/organization/members",
    headers: adminAuth,
    payload: { email: "owner2@acme.test", role: "owner" },
  });
  assert.equal(escalate.statusCode, 403);
});

test("login: email is case- and space-insensitive", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "  Owner@ACME.test ", password: "supersecret-password" },
  });
  assert.equal(res.statusCode, 200);
});

test("session tokens expire after 12h, and an expired token is refused", async () => {
  const claims = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
  assert.equal(claims.exp - claims.iat, 12 * 3600);

  const expired = app.jwt.sign(
    { userId: claims.userId, organizationId: claims.organizationId, role: claims.role },
    { expiresIn: -10 },
  );
  const res = await app.inject({
    method: "GET",
    url: "/api/v1/organization",
    headers: { authorization: `Bearer ${expired}` },
  });
  assert.equal(res.statusCode, 401);
});

test("client errors from Fastify stay 4xx (not 500)", async () => {
  // A JSON content-type with an empty body is a client mistake.
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/policies",
    headers: { ...auth(), "content-type": "application/json" },
  });
  assert.equal(res.statusCode, 400);
});

test("passwords: self-service change, admin reset, owner protected", async () => {
  // An admin member (created by the owner) with a known temp password.
  const invite = await app.inject({
    method: "POST",
    url: "/api/v1/organization/members",
    headers: auth(),
    payload: { email: "pw-admin@acme.test", role: "admin" },
  });
  const adminId: string = invite.json().user.id;
  let adminPw: string = invite.json().tempPassword;
  const loginAs = (email: string, password: string) =>
    app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { email, password } });
  const adminAuth = { authorization: `Bearer ${(await loginAs("pw-admin@acme.test", adminPw)).json().token}` };

  // Wrong current password → 401; right one → changed, old one stops working.
  const wrong = await app.inject({
    method: "POST",
    url: "/api/v1/auth/password",
    headers: adminAuth,
    payload: { currentPassword: "not-it-at-all", newPassword: "brand-new-password-42" },
  });
  assert.equal(wrong.statusCode, 401);
  const ok = await app.inject({
    method: "POST",
    url: "/api/v1/auth/password",
    headers: adminAuth,
    payload: { currentPassword: adminPw, newPassword: "brand-new-password-42" },
  });
  assert.equal(ok.statusCode, 200);
  assert.equal((await loginAs("pw-admin@acme.test", adminPw)).statusCode, 401);
  adminPw = "brand-new-password-42";
  assert.equal((await loginAs("pw-admin@acme.test", adminPw)).statusCode, 200);

  // Owner resets the admin → temp password works.
  const reset = await app.inject({
    method: "POST",
    url: `/api/v1/organization/members/${adminId}/reset-password`,
    headers: auth(),
  });
  assert.equal(reset.statusCode, 200);
  assert.equal((await loginAs("pw-admin@acme.test", reset.json().tempPassword)).statusCode, 200);

  // An admin cannot reset the owner.
  const members = await app.inject({ method: "GET", url: "/api/v1/organization/members", headers: auth() });
  const ownerId = members.json().members.find((m: { role: string }) => m.role === "owner").id;
  const freshAdmin = {
    authorization: `Bearer ${(await loginAs("pw-admin@acme.test", reset.json().tempPassword)).json().token}`,
  };
  const denied = await app.inject({
    method: "POST",
    url: `/api/v1/organization/members/${ownerId}/reset-password`,
    headers: freshAdmin,
  });
  assert.equal(denied.statusCode, 403);
});

test("github link: only a GitHub user with access to the installation can link it", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { writePlatformSetting } = await import("../lib/platform.js");
  const { GITHUB_APP_SETTING, resetGithubAppCache } = await import("../lib/github.js");

  // A test App with OAuth credentials, as the one-click flow stores it.
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const owner = await prisma.user.findFirstOrThrow({ where: { email: "owner@acme.test" } });
  await writePlatformSetting(
    GITHUB_APP_SETTING,
    { appId: "123", slug: "codegate-test", privateKey, webhookSecret: "whsec", clientId: "Iv1.test", clientSecret: "s", owner: null },
    process.env.ENCRYPTION_KEY!,
    owner.id,
  );
  resetGithubAppCache();

  // Fake GitHub: OAuth code → user token → installations that user can see;
  // the App can read installation 5001; repository import is not needed here.
  const users: Record<string, { token: string; installations: number[] }> = {
    "code-alice": { token: "tok-alice", installations: [5001] },
    "code-mallory": { token: "tok-mallory", installations: [9999] },
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const u = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (u === "https://github.com/login/oauth/access_token") {
      const { code } = JSON.parse(String(init?.body));
      const user = users[code];
      return new Response(JSON.stringify(user ? { access_token: user.token } : { error: "bad_verification_code" }));
    }
    if (u.startsWith("https://api.github.com/user/installations")) {
      const headers = new Headers(init?.headers);
      const tok = (headers.get("authorization") ?? "").replace("Bearer ", "");
      const user = Object.values(users).find((x) => x.token === tok);
      return new Response(
        JSON.stringify({ installations: (user?.installations ?? []).map((id) => ({ id, account: { login: "acme-gh" } })) }),
      );
    }
    if (u.startsWith("https://api.github.com/app/installations/5001")) {
      if (u.endsWith("/access_tokens")) return new Response("{}", { status: 403 });
      return new Response(JSON.stringify({ id: 5001, account: { login: "acme-gh" } }), {
        headers: { "content-type": "application/json" },
      });
    }
    return realFetch(input, init);
  }) as typeof fetch;

  try {
    const installUrl = await app.inject({ method: "GET", url: "/api/v1/github/install-url", headers: auth() });
    assert.equal(installUrl.statusCode, 200);
    const state = new URL(installUrl.json().url).searchParams.get("state")!;
    const link = (payload: Record<string, unknown>, headers = auth()) =>
      app.inject({ method: "POST", url: "/api/v1/github/link", headers, payload });

    // OAuth configured: the code is mandatory.
    assert.equal((await link({ installationId: 5001, state })).json().error, "oauth_code_required");
    // A valid state is not enough: this GitHub user cannot see installation 5001.
    const refused = await link({ installationId: 5001, state, code: "code-mallory" });
    assert.equal(refused.statusCode, 403);
    assert.equal(refused.json().error, "installation_not_authorized");
    assert.equal(await prisma.githubInstallation.count({ where: { installationId: 5001n } }), 0);

    // GitHub confirms access → linked.
    const ok = await link({ installationId: 5001, state, code: "code-alice" });
    assert.ok(ok.statusCode === 200 || ok.statusCode === 201, ok.body);
    assert.equal((await prisma.githubInstallation.findUniqueOrThrow({ where: { installationId: 5001n } })).accountLogin, "acme-gh");

    // The same return link replayed (spent code): still fine for its org.
    assert.ok((await link({ installationId: 5001, state, code: "code-spent" })).statusCode < 300);

    // Another organization can't take it over, even with a GitHub user who sees it.
    const other = await app.inject({
      method: "POST",
      url: "/api/v1/auth/signup",
      payload: { email: "gh-link-other@other.test", password: "other-password-1234", name: "O", organizationName: "Other GH", acceptTerms: true },
    });
    const otherAuth = { authorization: `Bearer ${other.json().token}` };
    const otherState = new URL(
      (await app.inject({ method: "GET", url: "/api/v1/github/install-url", headers: otherAuth })).json().url,
    ).searchParams.get("state")!;
    const takeover = await link({ installationId: 5001, state: otherState, code: "code-alice" }, otherAuth);
    assert.equal(takeover.statusCode, 409);
  } finally {
    globalThis.fetch = realFetch;
    await prisma.githubInstallation.deleteMany({ where: { installationId: 5001n } });
    await prisma.platformSetting.deleteMany({});
    resetGithubAppCache();
  }
});

test("analysis settings: org defaults, repo overrides, protection level", async () => {
  // Defaults + engine catalog.
  const get0 = await app.inject({ method: "GET", url: "/api/v1/settings/analysis", headers: auth() });
  assert.equal(get0.statusCode, 200);
  assert.equal(get0.json().effective.engines.semgrep, true);
  assert.ok(get0.json().engines.some((e: { id: string }) => e.id === "rust"));

  // Invalid parameters are rejected with the failing field.
  const bad = await app.inject({
    method: "PUT",
    url: "/api/v1/settings/analysis",
    headers: auth(),
    payload: { engines: { notAnEngine: true } },
  });
  assert.equal(bad.statusCode, 400);

  const put = await app.inject({
    method: "PUT",
    url: "/api/v1/settings/analysis",
    headers: auth(),
    payload: { engines: { semgrep: false }, ignorePaths: ["vendor/**"], minSeverity: "low" },
  });
  assert.equal(put.statusCode, 200);

  // Repository: block mode + an override re-enabling Semgrep for this repo.
  const repoPut = await app.inject({
    method: "PUT",
    url: `/api/v1/repositories/${repoId}/settings`,
    headers: auth(),
    payload: { protectionLevel: "block", analysisSettings: { engines: { semgrep: true }, ignorePaths: ["**/*.snap"] } },
  });
  assert.equal(repoPut.statusCode, 200);
  assert.equal(repoPut.json().protectionLevel, "block");
  const eff = repoPut.json().effective;
  assert.equal(eff.engines.semgrep, true); // repo override wins
  assert.deepEqual(eff.ignorePaths, ["vendor/**", "**/*.snap"]); // exclusions accumulate
  assert.equal(eff.minSeverity, "low"); // inherited from the org

  // Clearing the overrides returns to the organization settings.
  const cleared = await app.inject({
    method: "PUT",
    url: `/api/v1/repositories/${repoId}/settings`,
    headers: auth(),
    payload: { analysisSettings: null },
  });
  assert.equal(cleared.json().effective.engines.semgrep, false);
  assert.equal(cleared.json().protectionLevel, "block"); // untouched

  // A developer can read but not change the settings.
  const dev = await app.inject({
    method: "POST",
    url: "/api/v1/organization/members",
    headers: auth(),
    payload: { email: "settings-dev@acme.test", role: "developer" },
  });
  const devToken = (
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "settings-dev@acme.test", password: dev.json().tempPassword },
    })
  ).json().token;
  const devPut = await app.inject({
    method: "PUT",
    url: `/api/v1/repositories/${repoId}/settings`,
    headers: { authorization: `Bearer ${devToken}` },
    payload: { protectionLevel: "observe" },
  });
  assert.equal(devPut.statusCode, 403);

  // Another organization cannot see or change this repository.
  const other = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: { email: "settings-other@other.test", password: "other-password-1234", name: "O", organizationName: "Other S", acceptTerms: true },
  });
  const foreign = await app.inject({
    method: "PUT",
    url: `/api/v1/repositories/${repoId}/settings`,
    headers: { authorization: `Bearer ${other.json().token}` },
    payload: { protectionLevel: "observe" },
  });
  assert.equal(foreign.statusCode, 404);
});

test("integrations: Slack webhook URL must point at Slack (no SSRF)", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/slack",
    headers: auth(),
    payload: { webhookUrl: "http://169.254.169.254/latest/meta-data/" },
  });
  assert.equal(res.statusCode, 400);
});

test("jira integration: connect, status hides the token", async () => {
  const con = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/jira",
    headers: auth(),
    payload: {
      baseUrl: "https://acme.atlassian.net",
      email: "sec@acme.test",
      apiToken: "jira_api_token_secret_value",
      projectKey: "SEC",
    },
  });
  assert.equal(con.statusCode, 201);
  const status = await app.inject({
    method: "GET",
    url: "/api/v1/integrations/jira",
    headers: auth(),
  });
  const body = status.json();
  assert.equal(body.connected, true);
  assert.equal(body.projectKey, "SEC");
  assert.ok(!("apiToken" in body));
});

test("scim: provision, list, deactivate; deactivated user can't log in", async () => {
  // Generate a SCIM bearer token (as owner).
  const gen = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/scim",
    headers: auth(),
  });
  assert.equal(gen.statusCode, 201);
  const scimToken: string = gen.json().token;
  const scim = () => ({ authorization: `Bearer ${scimToken}` });

  // Wrong token → 401.
  const unauth = await app.inject({
    method: "GET",
    url: "/scim/v2/Users",
    headers: { authorization: "Bearer nope" },
  });
  assert.equal(unauth.statusCode, 401);

  // Provision a user.
  const create = await app.inject({
    method: "POST",
    url: "/scim/v2/Users",
    headers: scim(),
    payload: { userName: "dev@acme.test", displayName: "Dev One", active: true },
  });
  assert.equal(create.statusCode, 201);
  const scimId: string = create.json().id;
  assert.equal(create.json().userName, "dev@acme.test");
  assert.equal(create.json().active, true);

  // List with filter.
  const list = await app.inject({
    method: "GET",
    url: `/scim/v2/Users?filter=${encodeURIComponent('userName eq "dev@acme.test"')}`,
    headers: scim(),
  });
  assert.equal(list.json().totalResults, 1);
  assert.equal(list.json().Resources[0].id, scimId);

  // Deactivate the provisioned user via PATCH.
  const patch = await app.inject({
    method: "PATCH",
    url: `/scim/v2/Users/${scimId}`,
    headers: scim(),
    payload: { Operations: [{ op: "replace", path: "active", value: false }] },
  });
  assert.equal(patch.json().active, false);

  // Deprovision→login-block path, with a known password: deactivate the owner
  // via SCIM, confirm login is refused (403), then reactivate.
  const ownerList = await app.inject({
    method: "GET",
    url: `/scim/v2/Users?filter=${encodeURIComponent('userName eq "owner@acme.test"')}`,
    headers: scim(),
  });
  const ownerId: string = ownerList.json().Resources[0].id;

  await app.inject({
    method: "PATCH",
    url: `/scim/v2/Users/${ownerId}`,
    headers: scim(),
    payload: { Operations: [{ op: "replace", path: "active", value: false }] },
  });
  const blocked = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "owner@acme.test", password: "supersecret-password" },
  });
  assert.equal(blocked.statusCode, 403);
  assert.equal(blocked.json().error, "account_disabled");

  // A token issued before deprovisioning stops working immediately.
  const stale = await app.inject({ method: "GET", url: "/api/v1/organization", headers: auth() });
  assert.equal(stale.statusCode, 401);

  // Reactivate so later tests / the session keep working.
  await app.inject({
    method: "PATCH",
    url: `/scim/v2/Users/${ownerId}`,
    headers: scim(),
    payload: { Operations: [{ op: "replace", path: "active", value: true }] },
  });
});

test("saml: configure, metadata endpoint, ACS rejects invalid assertions", async () => {
  const org = await app.inject({ method: "GET", url: "/api/v1/organization", headers: auth() });
  const orgId: string = org.json().id;

  // A placeholder IdP cert (metadata generation doesn't validate it).
  const dummyCert =
    "MIIByDummyCertBodyForTestingPurposesOnly0123456789abcdefABCDEF0123456789==";

  const con = await app.inject({
    method: "POST",
    url: "/api/v1/integrations/saml",
    headers: auth(),
    payload: {
      idpEntityId: "https://idp.acme.test/entity",
      idpSsoUrl: "https://idp.acme.test/sso",
      idpCert: dummyCert,
    },
  });
  assert.equal(con.statusCode, 201);

  const status = await app.inject({
    method: "GET",
    url: "/api/v1/integrations/saml",
    headers: auth(),
  });
  assert.equal(status.json().connected, true);
  assert.match(status.json().metadataUrl, /\/saml\/.+\/metadata$/);

  // SP metadata is public XML containing our ACS endpoint.
  const meta = await app.inject({ method: "GET", url: `/saml/${orgId}/metadata` });
  assert.equal(meta.statusCode, 200);
  assert.match(meta.headers["content-type"] as string, /xml/);
  assert.match(meta.body, /EntityDescriptor/);
  assert.match(meta.body, new RegExp(`/saml/${orgId}/acs`));

  // ACS input validation.
  const noResp = await app.inject({
    method: "POST",
    url: `/saml/${orgId}/acs`,
    payload: {},
  });
  assert.equal(noResp.statusCode, 400);

  const garbage = await app.inject({
    method: "POST",
    url: `/saml/${orgId}/acs`,
    payload: { SAMLResponse: Buffer.from("not-a-saml-response").toString("base64") },
  });
  assert.equal(garbage.statusCode, 401);

  // Real IdPs use the HTTP-POST binding (form-encoded), not JSON.
  const form = await app.inject({
    method: "POST",
    url: `/saml/${orgId}/acs`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      SAMLResponse: Buffer.from("not-a-saml-response").toString("base64"),
    }).toString(),
  });
  assert.equal(form.statusCode, 401);
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

test("signed PDF report is registered and verifiable publicly", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/audit/export",
    headers: auth(),
    payload: { format: "pdf" },
  });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers["content-type"] as string, /application\/pdf/);
  const reportId = res.headers["x-report-id"] as string;
  assert.ok(reportId);
  const sha = createHash("sha256").update(res.rawPayload).digest("hex");

  // No account needed to verify, and the stored fingerprint matches the file.
  const ok = await app.inject({ method: "GET", url: `/api/v1/reports/${reportId}/verify?sha256=${sha}` });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().matches, true);
  assert.equal(ok.json().report.organization, "Acme");
  const bad = await app.inject({ method: "GET", url: `/api/v1/reports/${reportId}/verify?sha256=${"0".repeat(64)}` });
  assert.equal(bad.json().matches, false);
  const unknown = await app.inject({ method: "GET", url: "/api/v1/reports/00000000-0000-4000-8000-000000000000/verify" });
  assert.equal(unknown.statusCode, 404);

  const list = await app.inject({ method: "GET", url: "/api/v1/reports", headers: auth() });
  assert.ok(list.json().reports.some((r: { id: string }) => r.id === reportId));
});

test("every feature has its own signed report, scoped to the org", async () => {
  const pr = await prisma.pullRequest.findFirst({ where: { repository: { organization: { name: "Acme" } } } });
  assert.ok(pr, "a pull request exists from earlier tests");
  const res = await app.inject({ method: "POST", url: `/api/v1/reports/pull-request/${pr.id}`, headers: auth() });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers["content-type"] as string, /application\/pdf/);
  const reportId = res.headers["x-report-id"] as string;
  const v = await app.inject({ method: "GET", url: `/api/v1/reports/${reportId}/verify` });
  assert.equal(v.json().report.kind, "pull_request");
  assert.match(v.json().report.subject, new RegExp(`#${pr.number}$`));
  const forPr = await app.inject({ method: "GET", url: `/api/v1/reports?subjectId=${pr.id}`, headers: auth() });
  assert.deepEqual(forPr.json().reports.map((r: { id: string }) => r.id), [reportId]);

  // Unknown type or a subject from nowhere: 404, nothing issued.
  const bad = await app.inject({ method: "POST", url: `/api/v1/reports/nope/${pr.id}`, headers: auth() });
  assert.equal(bad.statusCode, 404);
  const missing = await app.inject({ method: "POST", url: `/api/v1/reports/server/${randomUUID()}`, headers: auth() });
  assert.equal(missing.statusCode, 404);
});

test("infra shield: connect server, agent report scored, token required", async () => {
  const con = await app.inject({
    method: "POST",
    url: "/api/v1/servers/connect",
    headers: auth(),
    payload: { name: "vps-prod", environment: "production" },
  });
  assert.equal(con.statusCode, 201);
  const { server, agentToken } = con.json();
  assert.ok(agentToken.startsWith("cg_srv_"));

  const report = {
    agentVersion: "1.0.0",
    hostname: "vps-prod",
    os: "Ubuntu 24.04",
    listening: [
      { proto: "tcp", address: "0.0.0.0", port: 22, process: "sshd" },
      { proto: "tcp", address: "0.0.0.0", port: 6379, process: "redis-server" },
    ],
    ssh: { permitRootLogin: "yes", passwordAuthentication: true, pubkeyAuthentication: true, maxAuthTries: 3 },
    firewall: { ufw: "active", nftablesRules: null, iptablesRules: null },
    bruteforce: { fail2ban: true, crowdsec: false },
    docker: null,
    updates: { manager: "apt", pendingSecurity: 0, autoUpdates: true },
  };

  const denied = await app.inject({
    method: "POST",
    url: "/api/v1/agent/report",
    headers: { authorization: "Bearer cg_srv_wrong" },
    payload: report,
  });
  assert.equal(denied.statusCode, 401);

  const ok = await app.inject({
    method: "POST",
    url: "/api/v1/agent/report",
    headers: { authorization: `Bearer ${agentToken}` },
    payload: report,
  });
  assert.equal(ok.statusCode, 202);
  // Redis public (critical 25) + root login (10) + password auth (10): 100 × 60 / (60 + 45)
  assert.equal(ok.json().score, 57);

  const detail = await app.inject({ method: "GET", url: `/api/v1/servers/${server.id}`, headers: auth() });
  assert.equal(detail.statusCode, 200);
  const s = detail.json().server;
  assert.equal(s.securityScore, 57);
  assert.equal(s.findings[0].checkId, "port.public.6379");
  assert.equal(JSON.stringify(detail.json()).includes("agentTokenHash"), false);

  const rotated = await app.inject({
    method: "POST",
    url: `/api/v1/servers/${server.id}/rotate-token`,
    headers: auth(),
  });
  const stale = await app.inject({
    method: "POST",
    url: "/api/v1/agent/report",
    headers: { authorization: `Bearer ${agentToken}` },
    payload: report,
  });
  assert.equal(stale.statusCode, 401, "old token is revoked after rotation");
  assert.ok(rotated.json().agentToken.startsWith("cg_srv_"));
});

test("infra shield v2: delta, accepted risk, re-audit on demand", async () => {
  const con = await app.inject({
    method: "POST",
    url: "/api/v1/servers/connect",
    headers: auth(),
    payload: { name: "vps-v2", environment: "production" },
  });
  const { server, agentToken } = con.json();
  const agent = { authorization: `Bearer ${agentToken}` };
  const report = {
    agentVersion: "2.0.0",
    hostname: "vps-v2",
    os: "Ubuntu 24.04",
    listening: [{ proto: "tcp", address: "0.0.0.0", port: 22, process: "sshd" }],
    ssh: { permitRootLogin: "no", passwordAuthentication: true, pubkeyAuthentication: true, maxAuthTries: 3 },
    firewall: { ufw: "inactive", ufwAllowed: [], nftablesRules: 0, iptablesRules: 0 },
    bruteforce: { fail2ban: true, crowdsec: false },
    docker: null,
    updates: { manager: "apt", pendingSecurity: 0, autoUpdates: true },
  };

  // Never audited: the agent's frequent cron is told to run.
  const due = await app.inject({ method: "GET", url: "/api/v1/agent/pending", headers: agent });
  assert.equal(due.json().run, true);

  const first = await app.inject({ method: "POST", url: "/api/v1/agent/report", headers: agent, payload: report });
  assert.equal(first.statusCode, 202);
  const before = first.json().score as number;

  // Fresh report: nothing pending until a re-audit is requested from the dashboard.
  assert.equal((await app.inject({ method: "GET", url: "/api/v1/agent/pending", headers: agent })).json().run, false);
  assert.equal((await app.inject({ method: "POST", url: `/api/v1/servers/${server.id}/rescan`, headers: auth() })).statusCode, 202);
  const asked = await app.inject({ method: "GET", url: "/api/v1/agent/pending", headers: agent });
  assert.deepEqual(asked.json(), { run: true, reason: "requested" });

  // The firewall is accepted as a known risk: it leaves the score at once, stays listed.
  const short = await app.inject({
    method: "PUT",
    url: `/api/v1/servers/${server.id}/acceptances/firewall.inactive`,
    headers: auth(),
    payload: { kind: "accepted", justification: "court" },
  });
  assert.equal(short.statusCode, 400, "a justification is required");
  const acc = await app.inject({
    method: "PUT",
    url: `/api/v1/servers/${server.id}/acceptances/firewall.inactive`,
    headers: auth(),
    payload: { kind: "mitigated", justification: "Filtrage assuré par le pare-feu de l'hébergeur (security group)." },
  });
  assert.equal(acc.statusCode, 200);
  assert.ok(acc.json().score > before);

  // Fixing SSH password auth is confirmed by the next report, with the delta.
  const fixed = await app.inject({
    method: "POST",
    url: "/api/v1/agent/report",
    headers: agent,
    payload: { ...report, ssh: { ...report.ssh, passwordAuthentication: false } },
  });
  assert.equal(fixed.json().resolved, 1);
  assert.equal(fixed.json().previousScore, acc.json().score);
  assert.ok(fixed.json().score > fixed.json().previousScore);

  const detail = (await app.inject({ method: "GET", url: `/api/v1/servers/${server.id}`, headers: auth() })).json().server;
  const fw = detail.findings.find((f: { checkId: string }) => f.checkId === "firewall.inactive");
  assert.equal(fw.acceptance.kind, "mitigated");
  assert.ok(fw.verifyCommand, "findings carry a verification command");
  assert.equal(detail.scans.length, 2);
  assert.deepEqual(detail.scans[0].resolved, ["ssh.password_auth"]);

  const events = await prisma.auditEvent.findMany({ where: { resourceId: server.id, action: "server.risk_mitigated" } });
  assert.equal(events.length, 1);

  // Reopening counts it again.
  const reopened = await app.inject({ method: "DELETE", url: `/api/v1/servers/${server.id}/acceptances/firewall.inactive`, headers: auth() });
  assert.ok(reopened.json().score < fixed.json().score);
});

test("bruteforce shield: CodeGate login locks an account after 5 failures", async () => {
  const attempt = () =>
    app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "ghost@acme.test", password: ["wrong", "password", "123"].join("-") },
    });
  for (let i = 1; i <= 5; i++) {
    const r = await attempt();
    assert.equal(r.statusCode, 401);
    assert.equal(r.json().error, "invalid_credentials");
  }
  const locked = await attempt();
  assert.equal(locked.statusCode, 429);
  assert.equal(locked.json().error, "too_many_attempts");
  assert.ok(Number(locked.headers["retry-after"]) > 0);
  // Another account from the same IP is not locked (per-account counter).
  const other = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email: "owner@acme.test", password: "supersecret-password" },
  });
  assert.equal(other.statusCode, 200);
});

test("bruteforce shield: policies, target ownership and test guard rails", async () => {
  const pol = await app.inject({
    method: "POST",
    url: "/api/v1/bruteforce/policies",
    headers: auth(),
    payload: { endpoint: "/api/auth/login", maxAttempts: 5, windowSeconds: 600, lockoutSeconds: 300 },
  });
  assert.equal(pol.statusCode, 201);
  const list = await app.inject({ method: "GET", url: "/api/v1/bruteforce/policies", headers: auth() });
  assert.equal(list.json().policies.length, 1);

  const httpTarget = await app.inject({
    method: "POST",
    url: "/api/v1/bruteforce/targets",
    headers: auth(),
    payload: { name: "insecure", origin: "http://example.com" },
  });
  assert.equal(httpTarget.statusCode, 400, "HTTPS is mandatory");

  const tgt = await app.inject({
    method: "POST",
    url: "/api/v1/bruteforce/targets",
    headers: auth(),
    payload: { name: "staging", origin: "https://staging.example.com/some/path" },
  });
  assert.equal(tgt.statusCode, 201);
  const target = tgt.json().target;
  assert.equal(target.origin, "https://staging.example.com");
  assert.ok(target.verificationToken.startsWith("cg-verify-"));

  const run = await app.inject({
    method: "POST",
    url: "/api/v1/bruteforce/tests",
    headers: auth(),
    payload: { targetId: target.id, testType: "login_lockout", endpoint: "/api/auth/login", testAccount: "qa@example.com" },
  });
  assert.equal(run.statusCode, 409);
  assert.equal(run.json().error, "target_not_verified");

  const local = await app.inject({
    method: "POST",
    url: "/api/v1/bruteforce/targets",
    headers: auth(),
    payload: { name: "local", origin: "https://localhost" },
  });
  const verify = await app.inject({
    method: "POST",
    url: `/api/v1/bruteforce/targets/${local.json().target.id}/verify`,
    headers: auth(),
  });
  assert.equal(verify.statusCode, 400);
  assert.equal(verify.json().error, "private_address");
});

test("backup shield: job, run report, integrity, restore test, token required", async () => {
  const create = await app.inject({
    method: "POST",
    url: "/api/v1/backups",
    headers: auth(),
    payload: { name: "pg-daily", type: "postgres", frequencyHours: 24 },
  });
  assert.equal(create.statusCode, 201);
  const { backup, reportToken } = create.json();
  assert.ok(reportToken.startsWith("cg_bkp_"));
  const agent = { authorization: `Bearer ${reportToken}` };
  const sha = "b".repeat(64);

  const denied = await app.inject({
    method: "POST",
    url: "/api/v1/backups/agent/run",
    headers: { authorization: "Bearer cg_bkp_nope" },
    payload: {},
  });
  assert.equal(denied.statusCode, 401);

  const run = await app.inject({
    method: "POST",
    url: "/api/v1/backups/agent/run",
    headers: agent,
    payload: {
      finishedAt: new Date().toISOString(),
      status: "success",
      sha256: sha,
      sizeBytes: 5_000_000_000,
      encrypted: true,
      encryptionAlgorithm: "AES-256-GCM",
      inTransit: "tls1.3",
      keyLocation: "external_kms",
      storageLocation: "offsite",
      immutable: true,
      versioning: true,
      separateAccount: true,
      retentionDays: 90,
    },
  });
  assert.equal(run.statusCode, 202);
  assert.equal(run.json().status, "attention", "no integrity re-check nor restore test yet");

  const ok = await app.inject({ method: "POST", url: "/api/v1/backups/agent/verify", headers: agent, payload: { sha256: sha } });
  assert.equal(ok.json().integrityOk, true);

  const now = new Date();
  const restore = await app.inject({
    method: "POST",
    url: "/api/v1/backups/agent/restore-test",
    headers: agent,
    payload: {
      engine: "postgres",
      startedAt: new Date(now.getTime() - 252_000).toISOString(),
      completedAt: now.toISOString(),
      durationSeconds: 252,
      result: "success",
      restoredTables: 30,
      restoredRecords: 1200,
    },
  });
  assert.equal(restore.statusCode, 201);

  const detail = await app.inject({ method: "GET", url: `/api/v1/backups/${backup.id}`, headers: auth() });
  const body = detail.json();
  assert.equal(body.evaluation.score, 100);
  assert.equal(body.evaluation.status, "healthy");
  assert.equal(body.evaluation.ransomwareReady, true);
  assert.equal(body.backup.runs[0].sizeBytes, 5_000_000_000);
  assert.equal(JSON.stringify(body).includes("tokenHash"), false);

  const tampered = await app.inject({
    method: "POST",
    url: "/api/v1/backups/agent/verify",
    headers: agent,
    payload: { sha256: "c".repeat(64) },
  });
  assert.equal(tampered.json().integrityOk, false);
  const report = await app.inject({ method: "GET", url: "/api/v1/reports/backup", headers: auth() });
  assert.equal(report.json().backups[0].status, "critical");
});

test("findings: a verdict is kept per alert, survives re-analysis and rescores", async () => {
  const pr = await prisma.pullRequest.findFirstOrThrow({ where: { repository: { provider: "github" } } });
  const { findingFingerprint } = await import("../analysis/fingerprint.js");
  const code = "const r = eval('1+1');";
  const fingerprint = findingFingerprint({ ruleId: "DANGEROUS_EVAL", title: "", filePath: "src/sandbox.ts" }, code);
  const finding = await prisma.finding.create({
    data: {
      pullRequestId: pr.id,
      type: "sast",
      severity: "high",
      title: "Utilisation de eval / Function dynamique",
      description: "test",
      filePath: "src/sandbox.ts",
      line: 4,
      ruleId: "DANGEROUS_EVAL",
      fingerprint,
    },
  });
  const list = await app.inject({ method: "GET", url: "/api/v1/findings?status=open", headers: auth() });
  assert.ok(list.json().findings.some((f: { id: string }) => f.id === finding.id));

  const fp = await app.inject({
    method: "PATCH",
    url: `/api/v1/findings/${finding.id}`,
    headers: auth(),
    payload: { status: "false_positive", reason: "eval sur une constante de test" },
  });
  assert.equal(fp.statusCode, 200);
  assert.equal(fp.json().pullRequest.riskScore, 0, "a false positive no longer counts");
  const verdict = await prisma.findingFeedback.findFirst({ where: { repositoryId: pr.repositoryId, fingerprint } });
  assert.equal(verdict?.verdict, "false_positive");
  assert.equal(verdict?.note, "eval sur une constante de test");

  const { analyzeDiff } = await import("../analysis/analyzer.js");
  const diffWith = (lines: string[]) =>
    [
      "diff --git a/src/sandbox.ts b/src/sandbox.ts",
      "--- a/src/sandbox.ts",
      "+++ b/src/sandbox.ts",
      `@@ -1,0 +10,${lines.length} @@`,
      ...lines.map((l) => `+${l}`),
    ].join("\n");
  const again = analyzeDiff(diffWith([code]), new Set([fingerprint]));
  assert.equal(again.findings.filter((f) => f.ruleId === "DANGEROUS_EVAL").length, 0, "suppressed even if the line moved");
  assert.equal(again.suppressed.length, 1);
  // A new eval elsewhere in the same file is a different alert: not hidden.
  const other = analyzeDiff(diffWith([code, "const s = eval(userInput);"]), new Set([fingerprint]));
  assert.equal(other.findings.filter((f) => f.ruleId === "DANGEROUS_EVAL").length, 1);

  // Confirmed as real, then the verdict is cleared.
  const confirm = await app.inject({
    method: "PUT",
    url: `/api/v1/findings/${finding.id}/feedback`,
    headers: auth(),
    payload: { verdict: "confirmed" },
  });
  assert.equal(confirm.statusCode, 200);
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } })).status, "acknowledged");

  const reopen = await app.inject({
    method: "PATCH",
    url: `/api/v1/findings/${finding.id}`,
    headers: auth(),
    payload: { status: "open" },
  });
  assert.equal(reopen.statusCode, 200);
  const cleared = await app.inject({ method: "DELETE", url: `/api/v1/findings/${finding.id}/feedback`, headers: auth() });
  assert.equal(cleared.statusCode, 204);
  assert.equal(await prisma.findingFeedback.count({ where: { repositoryId: pr.repositoryId, fingerprint } }), 0);

  const quality = await app.inject({ method: "GET", url: "/api/v1/metrics/rule-quality", headers: auth() });
  assert.equal(quality.statusCode, 200);
});

test("linear webhook: signed 'completed' resolves the PR findings", async () => {
  const cfg = await app.inject({ method: "POST", url: "/api/v1/integrations/linear/webhook", headers: auth() });
  assert.equal(cfg.statusCode, 200);
  const { url, secret } = cfg.json();
  const path = new URL(url).pathname;
  const pr = await prisma.pullRequest.findFirstOrThrow({ where: { repository: { provider: "github" } } });
  await prisma.remediationIssue.deleteMany({ where: { pullRequestId: pr.id } });
  await prisma.remediationIssue.create({
    data: { pullRequestId: pr.id, provider: "linear", externalId: "lin-issue-1", identifier: "SEC-1" },
  });
  const open = await prisma.finding.create({
    data: { pullRequestId: pr.id, type: "sast", severity: "medium", title: "x", description: "x", ruleId: "XSS_INNERHTML" },
  });
  const body = JSON.stringify({
    type: "Issue",
    action: "update",
    webhookTimestamp: Date.now(),
    data: { id: "lin-issue-1", state: { type: "completed" } },
  });
  const { createHmac } = await import("node:crypto");
  const sign = (b: string) => createHmac("sha256", secret).update(b).digest("hex");

  const forged = await app.inject({
    method: "POST", url: path, payload: body,
    headers: { "content-type": "application/json", "linear-signature": "0".repeat(64) },
  });
  assert.equal(forged.statusCode, 401);

  const ok = await app.inject({
    method: "POST", url: path, payload: body,
    headers: { "content-type": "application/json", "linear-signature": sign(body) },
  });
  assert.equal(ok.statusCode, 202);
  assert.equal(ok.json().status, "done");
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: open.id } })).status, "resolved");
});

test("maintenance: cron auth, missing backup + silent agent alert once", async () => {
  assert.equal((await app.inject({ method: "GET", url: "/api/v1/cron/maintenance" })).statusCode, 401);
  const ok = await app.inject({
    method: "GET",
    url: "/api/v1/cron/maintenance",
    headers: { authorization: `Bearer ${process.env.CRON_SECRET}` },
  });
  assert.equal(ok.statusCode, 200);

  const { runMaintenance } = await import("../lib/maintenance.js");
  const later = new Date(Date.now() + 3 * 24 * 3600_000);
  const first = await runMaintenance(loadConfig(), later);
  assert.ok(first.alerts.missingBackups >= 1, "backup reported 'now' is late 3 days later");
  assert.ok(first.alerts.silentAgents >= 1, "agent reported 'now' is silent 3 days later");
  const second = await runMaintenance(loadConfig(), later);
  assert.equal(second.alerts.missingBackups + second.alerts.silentAgents, 0, "alerts fire once");
  assert.ok(await prisma.auditEvent.count({ where: { action: "backup.missing" } }));
});

test("approvals: agent action waits for a human, then is allowed", async () => {
  const repo = await prisma.repository.findFirstOrThrow({ where: { provider: "github" } });
  const ask = () =>
    app.inject({
      method: "POST",
      url: "/api/v1/agent/guard",
      headers: auth(),
      payload: { repositoryId: repo.id, permission: "run_shell", target: "rm -rf build", agentId: "cursor" },
    });
  const first = await ask();
  assert.equal(first.json().decision, "require_approval");
  const approvalId = first.json().approvalId;
  assert.ok(approvalId);
  assert.equal((await ask()).json().approvalId, approvalId, "a retry reuses the same request");

  const poll = await app.inject({ method: "GET", url: `/api/v1/agent/approvals/${approvalId}`, headers: auth() });
  assert.equal(poll.json().status, "pending");
  const pending = await app.inject({ method: "GET", url: "/api/v1/approvals?status=pending", headers: auth() });
  assert.ok(pending.json().approvals.some((a: { id: string }) => a.id === approvalId));

  const ok = await app.inject({
    method: "POST",
    url: `/api/v1/approvals/${approvalId}/decision`,
    headers: auth(),
    payload: { decision: "approve" },
  });
  assert.equal(ok.json().status, "approved");
  assert.equal((await ask()).json().decision, "allow");
  const again = await app.inject({
    method: "POST",
    url: `/api/v1/approvals/${approvalId}/decision`,
    headers: auth(),
    payload: { decision: "deny" },
  });
  assert.equal(again.statusCode, 409);
});

test("members: role change, deactivation, last-owner and self guards", async () => {
  const inv = await app.inject({
    method: "POST",
    url: "/api/v1/organization/members",
    headers: auth(),
    payload: { email: "dev2@acme.test", role: "developer" },
  });
  assert.equal(inv.statusCode, 201);
  const devId = inv.json().user.id;
  const promote = await app.inject({
    method: "PATCH", url: `/api/v1/organization/members/${devId}`, headers: auth(), payload: { role: "security_manager" },
  });
  assert.equal(promote.json().member.role, "security_manager");
  const off = await app.inject({
    method: "PATCH", url: `/api/v1/organization/members/${devId}`, headers: auth(), payload: { active: false },
  });
  assert.equal(off.json().member.active, false);
  const login = await app.inject({
    method: "POST", url: "/api/v1/auth/login", payload: { email: "dev2@acme.test", password: inv.json().tempPassword },
  });
  assert.equal(login.statusCode, 403, "deactivated member cannot sign in");

  const owner = await prisma.user.findFirstOrThrow({ where: { email: "owner@acme.test" } });
  const self = await app.inject({
    method: "PATCH", url: `/api/v1/organization/members/${owner.id}`, headers: auth(), payload: { role: "viewer" },
  });
  assert.equal(self.statusCode, 409);
});

test("secrets: guided revocation and proof of remediation", async () => {
  const pr = await prisma.pullRequest.findFirstOrThrow({ where: { repository: { provider: "github" } } });
  const secret = await prisma.secretFinding.create({
    data: { pullRequestId: pr.id, secretType: "aws_access_key_id", location: "src/x.ts:3", maskedPreview: "AKIA…WXYZ", severity: "critical" },
  });
  const guide = await app.inject({ method: "GET", url: `/api/v1/secrets/${secret.id}/revocation`, headers: auth() });
  assert.equal(guide.json().guide.provider, "AWS");
  assert.ok(guide.json().guide.steps.length >= 4);
  const revoked = await app.inject({ method: "POST", url: `/api/v1/secrets/${secret.id}/revoked`, headers: auth() });
  assert.equal(revoked.statusCode, 200);
  const row = await prisma.secretFinding.findUniqueOrThrow({ where: { id: secret.id } });
  assert.ok(row.revokedAt);
  assert.notEqual(revoked.json().pullRequest.status, "blocked", "a revoked secret no longer blocks");
});

test("gitlab api: private instance refused", async () => {
  const res = await app.inject({
    method: "PUT",
    url: "/api/v1/integrations/gitlab/api",
    headers: auth(),
    payload: { baseUrl: "https://localhost", accessToken: "glpat-0123456789abcdef" },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, "private_address");
});

test("platform: GitHub App manifest flow is operator-only and stores credentials", async () => {
  const status = await app.inject({ method: "GET", url: "/api/v1/platform/github-app", headers: auth() });
  assert.equal(status.json().configured, false);
  assert.equal(status.json().canConfigure, true, "owner of the first organization operates the platform");

  const start = await app.inject({
    method: "POST",
    url: "/api/v1/platform/github-app/manifest",
    headers: auth(),
    payload: { name: "CodeGate Test App" },
  });
  assert.equal(start.statusCode, 200);
  assert.match(start.json().action, /^https:\/\/github\.com\/settings\/apps\/new\?state=/);
  const manifest = JSON.parse(start.json().manifest);
  assert.match(manifest.hook_attributes.url, /\/webhooks\/github$/);
  assert.deepEqual(manifest.default_permissions, {
    contents: "read", metadata: "read", pull_requests: "write", checks: "write",
  });

  // Another organization's owner is not the operator.
  const other = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: { email: "other-owner@beta.test", password: "supersecret-password", name: "O", organizationName: "Beta", acceptTerms: true },
  });
  const otherAuth = { authorization: `Bearer ${other.json().token}` };
  const denied = await app.inject({
    method: "POST", url: "/api/v1/platform/github-app/manifest", headers: otherAuth, payload: { name: "Hijack" },
  });
  assert.equal(denied.statusCode, 403);

  const forged = await app.inject({
    method: "POST", url: "/api/v1/platform/github-app/complete", headers: auth(),
    payload: { code: "0123456789abcdef", state: "not-a-valid-state-token-at-all" },
  });
  assert.equal(forged.statusCode, 400);

  // Credentials saved by the flow are read back, encrypted at rest.
  const { writePlatformSetting } = await import("../lib/platform.js");
  const { GITHUB_APP_SETTING, getGithubSettings, resetGithubAppCache } = await import("../lib/github.js");
  await writePlatformSetting(
    GITHUB_APP_SETTING,
    { appId: "123", slug: "codegate-test", privateKey: ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" "), webhookSecret: "whsec", clientId: "c", clientSecret: "s", owner: null },
    process.env.ENCRYPTION_KEY!,
    (await prisma.user.findFirstOrThrow({ where: { email: "owner@acme.test" } })).id,
  );
  resetGithubAppCache();
  const row = await prisma.platformSetting.findUniqueOrThrow({ where: { key: GITHUB_APP_SETTING } });
  assert.equal(row.valueEncrypted.includes("whsec"), false, "stored encrypted");
  const settings = await getGithubSettings(loadConfig());
  assert.equal(settings?.slug, "codegate-test");
  await prisma.platformSetting.deleteMany({});
  resetGithubAppCache();
});

test("repository scans: pick a repo, guard rails, auto-scan toggle", async () => {
  const repo = await prisma.repository.findFirstOrThrow({ where: { provider: "github" } });
  await prisma.repository.update({ where: { id: repo.id }, data: { installationId: null } });
  const blocked = await app.inject({ method: "POST", url: `/api/v1/repositories/${repo.id}/scans`, headers: auth() });
  assert.equal(blocked.statusCode, 409);
  assert.equal(blocked.json().error, "github_not_installed");

  const list = await app.inject({ method: "GET", url: "/api/v1/repositories", headers: auth() });
  const row = list.json().repositories.find((r: { id: string }) => r.id === repo.id);
  assert.equal(row.scannable, false);
  assert.equal(row.autoScan, true);

  const off = await app.inject({
    method: "PATCH", url: `/api/v1/repositories/${repo.id}`, headers: auth(), payload: { autoScan: false },
  });
  assert.equal(off.json().autoScan, false);

  const { createScan } = await import("../lib/repo-scan.js");
  const a = await createScan({ repositoryId: repo.id, organizationId: repo.organizationId, trigger: "manual" });
  const b = await createScan({ repositoryId: repo.id, organizationId: repo.organizationId, trigger: "manual" });
  assert.equal(b.id, a.id, "a scan already queued is reused");
  const scans = await app.inject({ method: "GET", url: "/api/v1/scans", headers: auth() });
  assert.equal(scans.json().scans[0].id, a.id);
  const detail = await app.inject({ method: "GET", url: `/api/v1/scans/${a.id}`, headers: auth() });
  assert.equal(detail.json().scan.status, "queued");
});

test("pull requests: problems counted apart from analysed deps, project filter, open PRs guard", async () => {
  const pr = await prisma.pullRequest.findFirstOrThrow({ where: { repository: { provider: "github" } } });
  await prisma.dependency.createMany({
    data: [
      { pullRequestId: pr.id, ecosystem: "npm", name: "zod", version: "^4.6.7", trustScore: 80, riskLevel: "low" },
      { pullRequestId: pr.id, ecosystem: "npm", name: "fastify", version: "^5.12.8", trustScore: 80, riskLevel: "low" },
    ],
  });
  const list = await app.inject({ method: "GET", url: `/api/v1/pull-requests?repositoryId=${pr.repositoryId}`, headers: auth() });
  const row = list.json().pullRequests.find((p: { id: string }) => p.id === pr.id);
  assert.equal(row.counts.dependencies, 0, "safe dependencies are not problems");
  assert.ok(row.counts.dependenciesAnalyzed >= 2);
  assert.ok(list.json().pullRequests.every((p: { repositoryId: string }) => p.repositoryId === pr.repositoryId));

  const other = await app.inject({ method: "GET", url: "/api/v1/pull-requests?repositoryId=00000000-0000-0000-0000-000000000000", headers: auth() });
  assert.equal(other.json().pullRequests.length, 0);

  await prisma.repository.update({ where: { id: pr.repositoryId }, data: { installationId: null } });
  const open = await app.inject({ method: "GET", url: `/api/v1/repositories/${pr.repositoryId}/open-pull-requests`, headers: auth() });
  assert.equal(open.statusCode, 409);
  assert.equal(open.json().error, "github_not_installed");
});

test("rgpd: export without secrets, then erase the organization", async () => {
  const exp = await app.inject({ method: "GET", url: "/api/v1/organization/export", headers: auth() });
  assert.equal(exp.statusCode, 200);
  const text = exp.body;
  for (const forbidden of ["passwordHash", "mfaSecret", "agentTokenHash", "tokenHash", "apiKeyEncrypted", "webhookSecretEncrypted"]) {
    assert.equal(text.includes(forbidden), false, `${forbidden} must not be exported`);
  }
  assert.ok(exp.json().users.length >= 1);

  const wrong = await app.inject({
    method: "DELETE", url: "/api/v1/organization", headers: auth(), payload: { confirmName: "acme" },
  });
  assert.equal(wrong.statusCode, 400);
  const erased = await app.inject({
    method: "DELETE", url: "/api/v1/organization", headers: auth(), payload: { confirmName: "Acme" },
  });
  assert.equal(erased.statusCode, 204);
  assert.equal(await prisma.organization.count({ where: { name: "Acme" } }), 0);
  assert.equal(await prisma.user.count({ where: { email: "owner@acme.test" } }), 0);
});

test("email: verification, forgotten password (sessions revoked), invitation", async () => {
  const { setMailTransport } = await import("../lib/mailer.js");
  const outbox: { to: string; tag: string; text: string }[] = [];
  setMailTransport(async (m) => {
    outbox.push({ to: m.to, tag: m.tag, text: m.text });
    return { sent: true, id: `it-${outbox.length}` };
  });
  const linkToken = (tag: string, to: string) => {
    const mail = [...outbox].reverse().find((m) => m.tag === tag && m.to === to);
    assert.ok(mail, `a ${tag} email went to ${to}`);
    const m = /#token=([A-Za-z0-9_-]+)/.exec(mail.text);
    assert.ok(m, "the link carries the token in the URL fragment");
    return m[1]!;
  };
  try {
    // 1. Signup sends a verification link; the account starts unverified.
    const signup = await app.inject({
      method: "POST",
      url: "/api/v1/auth/signup",
      payload: { email: "mail@acme-mail.test", password: "first-password-123", name: "Mia", organizationName: "MailCo", acceptTerms: true },
    });
    assert.equal(signup.statusCode, 201);
    assert.equal(signup.json().verificationSent, true);
    const session = signup.json().token as string;
    const me = () => app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${session}` } });
    assert.equal((await me()).json().user.emailVerified, false);

    const verifyToken = linkToken("verify_email", "mail@acme-mail.test");
    const bad = await app.inject({ method: "POST", url: "/api/v1/auth/verify-email", payload: { token: "x".repeat(43) } });
    assert.equal(bad.statusCode, 400);
    const ok = await app.inject({ method: "POST", url: "/api/v1/auth/verify-email", payload: { token: verifyToken } });
    assert.equal(ok.statusCode, 200);
    assert.equal((await me()).json().user.emailVerified, true);
    const reused = await app.inject({ method: "POST", url: "/api/v1/auth/verify-email", payload: { token: verifyToken } });
    assert.equal(reused.statusCode, 400, "single use");
    // Only the hash is stored.
    const stored = await prisma.authToken.findMany({ select: { tokenHash: true } });
    assert.ok(stored.every((t) => t.tokenHash !== verifyToken && /^[0-9a-f]{64}$/.test(t.tokenHash)));

    // 2. Forgot password: same answer for unknown addresses, no email sent.
    const before = outbox.length;
    const unknown = await app.inject({ method: "POST", url: "/api/v1/auth/forgot-password", payload: { email: "nobody@acme-mail.test" } });
    assert.equal(unknown.statusCode, 202);
    assert.equal(outbox.length, before, "no email for an unknown address");
    const known = await app.inject({ method: "POST", url: "/api/v1/auth/forgot-password", payload: { email: "MAIL@acme-mail.test " } });
    assert.equal(known.statusCode, 202);
    assert.deepEqual(known.json(), unknown.json(), "indistinguishable answers");
    const resetToken = linkToken("reset_password", "mail@acme-mail.test");

    // Sessions are second-precision: let the current one become "older".
    await new Promise((r) => setTimeout(r, 1100));
    const reset = await app.inject({
      method: "POST",
      url: "/api/v1/auth/reset-password",
      payload: { token: resetToken, password: "second-password-456" },
    });
    assert.equal(reset.statusCode, 200);
    assert.equal((await me()).statusCode, 401, "existing sessions are logged out");
    assert.ok(outbox.some((m) => m.tag === "password_changed" && m.to === "mail@acme-mail.test"));
    const again = await app.inject({
      method: "POST",
      url: "/api/v1/auth/reset-password",
      payload: { token: resetToken, password: "third-password-789" },
    });
    assert.equal(again.statusCode, 400, "reset link is single use");
    const oldLogin = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "mail@acme-mail.test", password: "first-password-123" },
    });
    assert.equal(oldLogin.statusCode, 401);
    const login = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "mail@acme-mail.test", password: "second-password-456" },
    });
    assert.equal(login.statusCode, 200);
    const owner = login.json().token as string;
    const meNew = await app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${owner}` } });
    assert.equal(meNew.statusCode, 200, "a session opened after the reset works");

    // 3. Invitation: an activation link instead of a temporary password.
    const invite = await app.inject({
      method: "POST",
      url: "/api/v1/organization/members",
      headers: { authorization: `Bearer ${owner}` },
      payload: { email: "newdev@acme-mail.test", role: "developer" },
    });
    assert.equal(invite.statusCode, 201);
    assert.equal(invite.json().inviteSent, true);
    assert.equal(invite.json().tempPassword, undefined, "no password travels through the inviter");
    const inviteToken = linkToken("invite", "newdev@acme-mail.test");
    const accept = await app.inject({
      method: "POST",
      url: "/api/v1/auth/accept-invite",
      payload: { token: inviteToken, password: "invitee-password-1", name: "New Dev" },
    });
    assert.equal(accept.statusCode, 200);
    const invitee = await app.inject({
      method: "GET",
      url: "/api/v1/me",
      headers: { authorization: `Bearer ${accept.json().token}` },
    });
    assert.equal(invitee.json().user.name, "New Dev");
    assert.equal(invitee.json().user.emailVerified, true);
    assert.equal(invitee.json().user.role, "developer");
    const replay = await app.inject({
      method: "POST",
      url: "/api/v1/auth/accept-invite",
      payload: { token: inviteToken, password: "attacker-password-1" },
    });
    assert.equal(replay.statusCode, 400, "invite link is single use");
  } finally {
    setMailTransport(null);
  }
});

test("signup requires accepting the terms, and records which version", async () => {
  const base = { email: "terms@acme-terms.test", password: "terms-password-1234", name: "T", organizationName: "Terms Co" };
  const refused = await app.inject({ method: "POST", url: "/api/v1/auth/signup", payload: base });
  assert.equal(refused.statusCode, 400);
  const ok = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    payload: { ...base, acceptTerms: true, termsVersion: "2026-11-05" },
  });
  assert.equal(ok.statusCode, 201);
  const user = await prisma.user.findUniqueOrThrow({ where: { email: base.email } });
  assert.equal(user.termsVersion, "2026-11-05");
  assert.ok(user.termsAcceptedAt);
});
