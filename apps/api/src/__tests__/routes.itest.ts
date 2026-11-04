/**
 * End-to-end integration tests. Boots the real Fastify app and drives it with
 * app.inject() (no network) against a dedicated test database.
 *
 * Prereq: `node scripts/setup-test-db.mjs` (recreates codegate_test), Postgres
 * and Redis running. Run with `pnpm --filter @codegate/api test:integration`.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";

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
