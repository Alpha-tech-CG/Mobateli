import { test } from "node:test";
import assert from "node:assert/strict";
import Fastify from "fastify";
import authPlugin from "./auth.js";

async function appWith(mfaRequiredForAdmins: boolean) {
  const app = Fastify();
  await app.register(authPlugin, {
    jwtSecret: "unit_test_secret_0123456789abcdefghij",
    mfaRequiredForAdmins,
  });
  app.get("/admin", { preHandler: [app.authenticate, app.requireRole("owner", "admin", "developer")] }, async () => ({
    ok: true,
  }));
  await app.ready();
  return app;
}

const call = (app: Awaited<ReturnType<typeof appWith>>, claims: object) =>
  app.inject({
    method: "GET",
    url: "/admin",
    headers: { authorization: `Bearer ${app.jwt.sign({ userId: "u", organizationId: "o", ...claims } as never)}` },
  });

test("§10.2: owner/admin without MFA are refused admin actions", async () => {
  const app = await appWith(true);
  const res = await call(app, { role: "owner", mfa: false });
  assert.equal(res.statusCode, 403);
  assert.equal(res.json().error, "mfa_enrollment_required");
  assert.equal((await call(app, { role: "admin" })).statusCode, 403, "missing claim counts as no MFA");
  assert.equal((await call(app, { role: "owner", mfa: true })).statusCode, 200);
  assert.equal((await call(app, { role: "developer", mfa: false })).statusCode, 200, "only admins are forced");
});

test("§10.2: enforcement can be disabled (tests / staged rollout)", async () => {
  const app = await appWith(false);
  assert.equal((await call(app, { role: "owner", mfa: false })).statusCode, 200);
});

test("§10.2: sessions expire", async () => {
  const app = await appWith(true);
  const token = app.jwt.sign({ userId: "u", organizationId: "o", role: "owner", mfa: true });
  const { exp, iat } = app.jwt.decode<{ exp: number; iat: number }>(token)!;
  assert.equal(exp - iat, 12 * 3600);
});
