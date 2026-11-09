import type { FastifyInstance } from "fastify";
import { prisma, type Prisma } from "@codegate/db";
import {
  bruteForcePolicySchema,
  createBruteForceTargetSchema,
  runBruteForceTestSchema,
} from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { notifySlack } from "../lib/notify.js";
import {
  firstBlocked,
  gradeEnumeration,
  gradeLockout,
  isBlocked,
  type Observation,
} from "../analysis/bruteforce.js";
import {
  TargetRejected,
  assertPublicOrigin,
  attemptLogin,
  newVerificationToken,
  nonExistentAccount,
  runLockoutProbe,
  verifyOwnership,
} from "../lib/bruteforce-runner.js";

const MANAGE = ["owner", "admin", "security_manager"] as const;
const TESTS_PER_HOUR = 10;

/** j***@example.com — the test account is evidence, but never shown in full. */
function maskAccount(account: string): string {
  const [local, domain] = account.split("@");
  if (!domain) return `${account.slice(0, 1)}***`;
  return `${local!.slice(0, 1)}***@${domain}`;
}

const slim = (o: Observation) => ({
  attempt: o.attempt,
  status: o.status,
  ms: o.ms,
  blocked: isBlocked(o),
});

/**
 * BruteForce Shield (extension §4, §8): org policies, verified targets and
 * authorized low-volume tests of the customer's own login endpoint.
 */
export async function bruteForceRoutes(app: FastifyInstance, config: AppConfig) {
  // ── Policies ──
  app.get("/api/v1/bruteforce/policies", { preHandler: [app.authenticate] }, async (req) => {
    const policies = await prisma.bruteForcePolicy.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { endpoint: "asc" },
    });
    return { policies };
  });

  app.post(
    "/api/v1/bruteforce/policies",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = bruteForcePolicySchema.parse(req.body);
      const data = {
        maxAttempts: body.maxAttempts,
        windowSeconds: body.windowSeconds,
        lockoutSeconds: body.lockoutSeconds,
        strategy: body.strategy,
        applyTo: body.applyTo,
        captchaAfter: body.captchaAfter ?? null,
        alertAfter: body.alertAfter ?? null,
      };
      const policy = await prisma.bruteForcePolicy.upsert({
        where: {
          organizationId_endpoint: {
            organizationId: req.principal.organizationId,
            endpoint: body.endpoint,
          },
        },
        create: { organizationId: req.principal.organizationId, endpoint: body.endpoint, ...data },
        update: data,
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "bruteforce.policy_saved",
        resourceType: "bruteforce_policy",
        resourceId: policy.id,
        metadata: { endpoint: body.endpoint, maxAttempts: body.maxAttempts },
      });
      return reply.code(201).send({ policy });
    },
  );

  app.delete(
    "/api/v1/bruteforce/policies/:id",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = await prisma.bruteForcePolicy.deleteMany({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      return reply.code(204).send();
    },
  );

  // ── Targets (ownership proof) ──
  app.get("/api/v1/bruteforce/targets", { preHandler: [app.authenticate] }, async (req) => {
    const targets = await prisma.bruteForceTarget.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
    });
    return { targets };
  });

  app.post(
    "/api/v1/bruteforce/targets",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = createBruteForceTargetSchema.parse(req.body);
      const origin = new URL(body.origin).origin;
      const target = await prisma.bruteForceTarget.upsert({
        where: {
          organizationId_origin: { organizationId: req.principal.organizationId, origin },
        },
        create: {
          organizationId: req.principal.organizationId,
          name: body.name,
          origin,
          environment: body.environment,
          verificationToken: newVerificationToken(),
        },
        update: { name: body.name, environment: body.environment },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "bruteforce.target_added",
        resourceType: "bruteforce_target",
        resourceId: target.id,
        metadata: { origin, environment: body.environment },
      });
      return reply.code(201).send({ target });
    },
  );

  app.post(
    "/api/v1/bruteforce/targets/:id/verify",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const target = await prisma.bruteForceTarget.findFirst({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!target) return reply.code(404).send({ error: "not_found" });
      try {
        const { verified, method } = await verifyOwnership(target.origin, target.verificationToken);
        if (!verified) return reply.code(422).send({ error: "verification_not_found" });
        const updated = await prisma.bruteForceTarget.update({
          where: { id },
          data: { verifiedAt: new Date() },
        });
        await recordAudit({
          organizationId: req.principal.organizationId,
          actorType: "user",
          actorId: req.principal.userId,
          action: "bruteforce.target_verified",
          resourceType: "bruteforce_target",
          resourceId: id,
          metadata: { method },
        });
        return { target: updated, method };
      } catch (err) {
        if (err instanceof TargetRejected) return reply.code(400).send({ error: err.message });
        throw err;
      }
    },
  );

  app.delete(
    "/api/v1/bruteforce/targets/:id",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = await prisma.bruteForceTarget.deleteMany({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      return reply.code(204).send();
    },
  );

  // ── Tests ──
  app.get("/api/v1/bruteforce/tests", { preHandler: [app.authenticate] }, async (req) => {
    const tests = await prisma.bruteForceTest.findMany({
      where: { target: { organizationId: req.principal.organizationId } },
      orderBy: { createdAt: "desc" },
      take: 50,
      include: { target: { select: { name: true, origin: true, environment: true } } },
    });
    return { tests };
  });

  app.get("/api/v1/bruteforce/tests/:id", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const test = await prisma.bruteForceTest.findFirst({
      where: { id, target: { organizationId: req.principal.organizationId } },
      include: { target: { select: { name: true, origin: true, environment: true } } },
    });
    if (!test) return reply.code(404).send({ error: "not_found" });
    return { test };
  });

  app.post(
    "/api/v1/bruteforce/tests",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = runBruteForceTestSchema.parse(req.body);
      const orgId = req.principal.organizationId;
      const target = await prisma.bruteForceTarget.findFirst({
        where: { id: body.targetId, organizationId: orgId },
      });
      if (!target) return reply.code(404).send({ error: "target_not_found" });
      if (!target.verifiedAt) return reply.code(409).send({ error: "target_not_verified" });
      if (target.environment === "production" && !body.confirmProduction) {
        return reply.code(400).send({ error: "production_confirmation_required" });
      }
      const recent = await prisma.bruteForceTest.count({
        where: { target: { organizationId: orgId }, createdAt: { gt: new Date(Date.now() - 3600_000) } },
      });
      if (recent >= TESTS_PER_HOUR) return reply.code(429).send({ error: "test_quota_exceeded" });

      try {
        await assertPublicOrigin(target.origin);
      } catch (err) {
        if (err instanceof TargetRejected) return reply.code(400).send({ error: err.message });
        throw err;
      }

      const probe = {
        origin: target.origin,
        endpoint: body.endpoint,
        emailField: body.emailField,
        passwordField: body.passwordField,
      };
      const policy = await prisma.bruteForcePolicy.findUnique({
        where: { organizationId_endpoint: { organizationId: orgId, endpoint: body.endpoint } },
      });

      let attempts: number;
      let blockedAfter: number | null = null;
      let scope: "account" | "ip" | null = null;
      let graded: { result: "pass" | "warn" | "fail"; summary: string };
      let evidence: Record<string, unknown>;

      if (body.testType === "login_lockout") {
        const observations = await runLockoutProbe(probe, body.testAccount, body.maxAttempts, isBlocked);
        attempts = observations.length;
        blockedAfter = firstBlocked(observations);
        let scopeProbe: Observation | null = null;
        if (blockedAfter !== null) {
          // Same IP, another (non-existent) account: still blocked ⇒ IP-based.
          scopeProbe = await attemptLogin(probe, nonExistentAccount(), attempts + 1);
          scope = isBlocked(scopeProbe) ? "ip" : "account";
          attempts += 1;
        }
        graded = gradeLockout(blockedAfter, observations.length, policy?.maxAttempts ?? null, scope);
        evidence = {
          observations: observations.map(slim),
          scopeProbe: scopeProbe ? slim(scopeProbe) : null,
          retryAfter: observations.at(-1)?.retryAfter ?? null,
        };
      } else {
        const existing: Observation[] = [];
        const missing: Observation[] = [];
        for (let i = 0; i < 3; i++) {
          existing.push(await attemptLogin(probe, body.testAccount, i * 2 + 1));
          missing.push(await attemptLogin(probe, nonExistentAccount(), i * 2 + 2));
        }
        attempts = 6;
        const enumeration = gradeEnumeration(existing, missing);
        graded = enumeration;
        evidence = {
          existing: existing.map(slim),
          missing: missing.map(slim),
          signals: enumeration.signals,
        };
      }

      const test = await prisma.bruteForceTest.create({
        data: {
          targetId: target.id,
          testType: body.testType,
          endpoint: body.endpoint,
          attempts,
          blockedAfter,
          scope,
          result: graded.result,
          summary: graded.summary,
          evidence: {
            ...evidence,
            testAccount: maskAccount(body.testAccount),
            policy: policy
              ? { maxAttempts: policy.maxAttempts, windowSeconds: policy.windowSeconds }
              : null,
          } as Prisma.InputJsonValue,
          createdById: req.principal.userId,
        },
      });

      await recordAudit({
        organizationId: orgId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "bruteforce.test_run",
        resourceType: "bruteforce_target",
        resourceId: target.id,
        metadata: {
          testType: body.testType,
          endpoint: body.endpoint,
          environment: target.environment,
          attempts,
          result: graded.result,
        },
      });

      if (graded.result === "fail") {
        await notifySlack(orgId, config.ENCRYPTION_KEY, {
          title: "Endpoint vulnérable au brute force",
          severity: "critical",
          repository: `${target.name} ${body.endpoint}`,
          detail: graded.summary,
        });
      }

      return reply.code(201).send({ test });
    },
  );
}
