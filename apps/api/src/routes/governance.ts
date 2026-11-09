import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma, Prisma } from "@codegate/db";
import {
  contestBlockSchema,
  createExceptionSchema,
  resolveContestSchema,
  ruleFeedbackSchema,
  ruleSettingSchema,
} from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { rescorePullRequest } from "../lib/rescore.js";
import { matchFinding, noisyRules, observedRules, type ExceptionRow } from "../lib/exceptions.js";
import { storedFinding } from "../lib/finding-rows.js";
import { ruleQuality } from "../analysis/feedback.js";

/**
 * Anti-noise governance: controlled exceptions, feedback on rules, rule
 * observation, contesting a block, and the metrics that show which rules
 * help and which ones only make noise. Every decision is audited.
 */

const MEMBERS = ["owner", "admin", "security_manager", "developer"] as const;
const REVIEWERS = ["owner", "admin", "security_manager"] as const;
const IS_REVIEWER = new Set<string>(REVIEWERS);
/** Only a Security Manager (or the owner) may approve a permanent exception. */
const MAY_APPROVE_PERMANENT = new Set(["security_manager", "owner"]);
const DAY = 86_400_000;

type ExceptionRecord = Awaited<ReturnType<typeof prisma.findingException.findFirstOrThrow>>;

/**
 * Re-evaluate the open PRs an exception touches: findings it covers become
 * `suppressed` (approval) or `open` again (revocation/expiry), then each
 * affected PR is rescored.
 */
async function reapplyException(e: ExceptionRecord, covering: boolean) {
  const prs = new Set<string>();
  if (covering) {
    const rows = await prisma.finding.findMany({
      where: {
        status: "open",
        pullRequest: {
          status: { in: ["blocked", "warning", "passed"] },
          repository: e.orgWide ? { organizationId: e.organizationId } : { id: e.repositoryId! },
        },
      },
      include: { pullRequest: { select: { id: true, baseBranch: true } } },
    });
    for (const r of rows) {
      if (r.type === "secret") continue;
      if (!matchFinding([e as ExceptionRow], storedFinding(r), r.pullRequest.baseBranch)) continue;
      await prisma.finding.update({ where: { id: r.id }, data: { status: "suppressed", exceptionId: e.id } });
      prs.add(r.pullRequestId);
    }
    if (e.dependency) {
      const deps = await prisma.dependency.findMany({
        where: {
          name: e.dependency,
          exceptionId: null,
          ...(e.dependencyVersion ? { version: e.dependencyVersion } : {}),
          pullRequest: { repository: e.orgWide ? { organizationId: e.organizationId } : { id: e.repositoryId! } },
        },
        select: { id: true, pullRequestId: true },
      });
      for (const d of deps) {
        await prisma.dependency.update({ where: { id: d.id }, data: { exceptionId: e.id } });
        prs.add(d.pullRequestId);
      }
    }
  } else {
    const [findings, deps] = await Promise.all([
      prisma.finding.findMany({ where: { exceptionId: e.id }, select: { id: true, pullRequestId: true } }),
      prisma.dependency.findMany({ where: { exceptionId: e.id }, select: { id: true, pullRequestId: true } }),
    ]);
    await prisma.finding.updateMany({ where: { exceptionId: e.id }, data: { status: "open", exceptionId: null } });
    await prisma.dependency.updateMany({ where: { exceptionId: e.id }, data: { exceptionId: null } });
    for (const x of [...findings, ...deps]) prs.add(x.pullRequestId);
  }
  for (const id of prs) await rescorePullRequest(id);
  return prs.size;
}

export async function governanceRoutes(app: FastifyInstance) {
  // ── Exceptions ────────────────────────────────────────────────────────────

  app.get("/api/v1/exceptions", { preHandler: [app.authenticate] }, async (req) => {
    const now = new Date();
    const rows = await prisma.findingException.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
      take: 200,
      include: { repository: { select: { name: true } } },
    });
    return {
      exceptions: rows.map((e) => ({
        ...e,
        state: e.revokedAt
          ? "revoked"
          : !e.approvedAt
            ? "pending"
            : e.expiresAt && e.expiresAt <= now
              ? "expired"
              : e.expiresAt && e.expiresAt.getTime() - now.getTime() < 7 * DAY
                ? "expiring"
                : "active",
      })),
    };
  });

  // Anyone in the team may ask for an exception; it applies once a reviewer
  // approves it (a reviewer's own request is approved by them, on the record).
  app.post("/api/v1/exceptions", { preHandler: [app.authenticate, app.requireRole(...MEMBERS)] }, async (req, reply) => {
    const body = createExceptionSchema.parse(req.body);
    if (body.repositoryId) {
      const repo = await prisma.repository.findFirst({
        where: { id: body.repositoryId, organizationId: req.principal.organizationId },
        select: { id: true },
      });
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });
    }
    if (body.orgWide && !IS_REVIEWER.has(req.principal.role)) {
      return reply.code(403).send({ error: "org_wide_requires_reviewer" });
    }
    const selfApproved =
      IS_REVIEWER.has(req.principal.role) && (!body.permanent || MAY_APPROVE_PERMANENT.has(req.principal.role));
    const now = new Date();
    const e = await prisma.findingException.create({
      data: {
        organizationId: req.principal.organizationId,
        repositoryId: body.repositoryId ?? null,
        orgWide: body.orgWide,
        ruleId: body.ruleId ?? null,
        pathGlob: body.pathGlob ?? null,
        riskType: body.riskType ?? null,
        dependency: body.dependency ?? null,
        dependencyVersion: body.dependencyVersion ?? null,
        branch: body.branch ?? null,
        environment: body.environment ?? null,
        reason: body.reason,
        ticketUrl: body.ticketUrl ?? null,
        requestedById: req.principal.userId,
        expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
        ...(selfApproved ? { approvedById: req.principal.userId, approvedAt: now } : {}),
      },
    });
    await recordAudit({
      organizationId: req.principal.organizationId,
      actorType: "user",
      actorId: req.principal.userId,
      action: selfApproved ? "exception.approved" : "exception.requested",
      resourceType: "finding_exception",
      resourceId: e.id,
      metadata: { ...body, approvedBy: selfApproved ? req.principal.userId : null },
    });
    const reevaluated = selfApproved ? await reapplyException(e, true) : 0;
    return reply.code(201).send({ exception: e, reevaluatedPullRequests: reevaluated });
  });

  app.post(
    "/api/v1/exceptions/:id/approve",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const e = await prisma.findingException.findFirst({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!e) return reply.code(404).send({ error: "not_found" });
      if (e.approvedAt || e.revokedAt) return reply.code(409).send({ error: "not_pending" });
      if (!e.expiresAt && !MAY_APPROVE_PERMANENT.has(req.principal.role)) {
        return reply.code(403).send({ error: "permanent_requires_security_manager" });
      }
      const approved = await prisma.findingException.update({
        where: { id },
        data: { approvedById: req.principal.userId, approvedAt: new Date() },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "exception.approved",
        resourceType: "finding_exception",
        resourceId: id,
        metadata: { requestedBy: e.requestedById },
      });
      return { exception: approved, reevaluatedPullRequests: await reapplyException(approved, true) };
    },
  );

  app.post(
    "/api/v1/exceptions/:id/revoke",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { reason } = z.object({ reason: z.string().trim().min(5).max(500) }).parse(req.body);
      const e = await prisma.findingException.findFirst({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!e) return reply.code(404).send({ error: "not_found" });
      if (e.revokedAt) return reply.code(409).send({ error: "already_revoked" });
      const revoked = await prisma.findingException.update({
        where: { id },
        data: { revokedAt: new Date(), revokedById: req.principal.userId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "exception.revoked",
        resourceType: "finding_exception",
        resourceId: id,
        metadata: { reason },
      });
      return { exception: revoked, reevaluatedPullRequests: await reapplyException(revoked, false) };
    },
  );

  // ── Rules: feedback, observation, evolution ───────────────────────────────

  app.post(
    "/api/v1/rules/:ruleId/feedback",
    { preHandler: [app.authenticate, app.requireRole(...MEMBERS)] },
    async (req, reply) => {
      const { ruleId } = req.params as { ruleId: string };
      const body = ruleFeedbackSchema.parse(req.body);
      let context: { pullRequestId: string; repositoryId: string; filePath: string | null } | null = null;
      if (body.findingId) {
        const f = await prisma.finding.findFirst({
          where: { id: body.findingId, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
          select: { filePath: true, ruleId: true, pullRequestId: true, pullRequest: { select: { repositoryId: true } } },
        });
        if (!f || f.ruleId !== ruleId) return reply.code(404).send({ error: "finding_not_found" });
        context = { pullRequestId: f.pullRequestId, repositoryId: f.pullRequest.repositoryId, filePath: f.filePath };
      }
      const ext = context?.filePath?.match(/\.([a-z0-9]+)$/i)?.[1]?.toLowerCase() ?? null;
      const LANG: Record<string, string> = { ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript", py: "python", go: "go", rb: "ruby", php: "php", java: "java", yml: "yaml", yaml: "yaml" };
      const row = await prisma.ruleFeedback.create({
        data: {
          organizationId: req.principal.organizationId,
          ruleId,
          kind: body.kind,
          note: body.note ?? null,
          findingId: body.findingId ?? null,
          pullRequestId: context?.pullRequestId ?? null,
          repositoryId: context?.repositoryId ?? null,
          filePath: context?.filePath ?? null,
          fileType: ext,
          language: ext ? (LANG[ext] ?? ext) : null,
          userId: req.principal.userId,
        },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "rule.feedback",
        resourceType: "rule",
        resourceId: ruleId,
        metadata: { kind: body.kind, note: body.note ?? null, findingId: body.findingId ?? null },
      });
      return reply.code(201).send({ feedback: row });
    },
  );

  // Put a rule in observation (its alerts are shown, never decide) or back
  // to active once improved. Overrides the automatic noisy-rule observation.
  app.put(
    "/api/v1/rules/:ruleId/setting",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req) => {
      const { ruleId } = req.params as { ruleId: string };
      const body = ruleSettingSchema.parse(req.body);
      const setting = await prisma.ruleSetting.upsert({
        where: { organizationId_ruleId: { organizationId: req.principal.organizationId, ruleId } },
        create: { organizationId: req.principal.organizationId, ruleId, mode: body.mode, reason: body.reason, setById: req.principal.userId },
        update: { mode: body.mode, reason: body.reason, setById: req.principal.userId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: body.mode === "observation" ? "rule.observed" : "rule.reactivated",
        resourceType: "rule",
        resourceId: ruleId,
        metadata: { reason: body.reason },
      });
      return { setting };
    },
  );

  // Every rule seen in the organization: its health, state and feedback.
  app.get("/api/v1/rules", { preHandler: [app.authenticate] }, async (req) => {
    const orgId = req.principal.organizationId;
    const since = new Date(Date.now() - 90 * DAY);
    const [groups, observed, settings, feedback] = await Promise.all([
      prisma.finding.groupBy({
        by: ["ruleId", "status"],
        where: { createdAt: { gte: since }, ruleId: { not: null }, pullRequest: { repository: { organizationId: orgId } } },
        _count: { _all: true },
      }),
      observedRules(orgId),
      prisma.ruleSetting.findMany({ where: { organizationId: orgId } }),
      prisma.ruleFeedback.groupBy({ by: ["ruleId", "kind"], where: { organizationId: orgId }, _count: { _all: true } }),
    ]);
    const quality = ruleQuality(groups.map((g) => ({ ruleId: g.ruleId, status: g.status, count: g._count._all })));
    return {
      rules: quality.map((q) => ({
        ...q,
        mode: observed.has(q.ruleId) ? "observation" : "active",
        observationReason: observed.get(q.ruleId) ?? null,
        setting: settings.find((s) => s.ruleId === q.ruleId) ?? null,
        feedback: Object.fromEntries(feedback.filter((f) => f.ruleId === q.ruleId).map((f) => [f.kind, f._count._all])),
      })),
    };
  });

  // ── Contesting a block ────────────────────────────────────────────────────

  app.post(
    "/api/v1/pull-requests/:id/contest",
    { preHandler: [app.authenticate, app.requireRole(...MEMBERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = contestBlockSchema.parse(req.body);
      const pr = await prisma.pullRequest.findFirst({
        where: { id, repository: { organizationId: req.principal.organizationId } },
        select: { id: true, status: true },
      });
      if (!pr) return reply.code(404).send({ error: "not_found" });
      if (pr.status !== "blocked") return reply.code(409).send({ error: "not_blocked" });
      const open = await prisma.blockContest.findFirst({ where: { pullRequestId: id, status: "open" } });
      if (open) return reply.code(409).send({ error: "already_contested" });
      const contest = await prisma.blockContest.create({
        data: { pullRequestId: id, userId: req.principal.userId, reason: body.reason },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "pr.block_contested",
        resourceType: "pull_request",
        resourceId: id,
        metadata: { contestId: contest.id, reason: body.reason },
      });
      return reply.code(201).send({ contest });
    },
  );

  // A reviewer upholds the block, or overturns it: the PR then needs a human
  // decision (escalated) rather than an automatic block — the alerts stay.
  app.post(
    "/api/v1/contests/:id/resolve",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = resolveContestSchema.parse(req.body);
      const contest = await prisma.blockContest.findFirst({
        where: { id, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
      });
      if (!contest) return reply.code(404).send({ error: "not_found" });
      if (contest.status !== "open") return reply.code(409).send({ error: "already_resolved" });
      const resolved = await prisma.blockContest.update({
        where: { id },
        data: { status: body.decision, resolution: body.resolution, resolvedById: req.principal.userId, resolvedAt: new Date() },
      });
      if (body.decision === "overturned") {
        await prisma.pullRequest.update({ where: { id: contest.pullRequestId }, data: { status: "escalated" } });
      }
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: body.decision === "overturned" ? "pr.block_overturned" : "pr.block_upheld",
        resourceType: "pull_request",
        resourceId: contest.pullRequestId,
        metadata: { contestId: id, resolution: body.resolution, contestedBy: contest.userId },
      });
      return { contest: resolved };
    },
  );

  app.get("/api/v1/pull-requests/:id/contests", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const pr = await prisma.pullRequest.findFirst({
      where: { id, repository: { organizationId: req.principal.organizationId } },
      select: { id: true },
    });
    if (!pr) return reply.code(404).send({ error: "not_found" });
    return { contests: await prisma.blockContest.findMany({ where: { pullRequestId: id }, orderBy: { createdAt: "desc" } }) };
  });

  // ── Anti-noise metrics ────────────────────────────────────────────────────

  // Per-rule false-positive rate — kept for the existing dashboard.
  app.get("/api/v1/metrics/rule-quality", { preHandler: [app.authenticate] }, async (req) => {
    const { days } = z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }).parse(req.query);
    const since = new Date(Date.now() - days * DAY);
    const groups = await prisma.finding.groupBy({
      by: ["ruleId", "status"],
      where: { createdAt: { gte: since }, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
      _count: { _all: true },
    });
    const rules = ruleQuality(groups.map((g) => ({ ruleId: g.ruleId, status: g.status, count: g._count._all })));
    const total = rules.reduce(
      (acc, r) => ({ alerts: acc.alerts + r.alerts, fp: acc.fp + r.falsePositives, ok: acc.ok + r.confirmed }),
      { alerts: 0, fp: 0, ok: 0 },
    );
    return {
      days,
      alerts: total.alerts,
      reviewed: total.fp + total.ok,
      falsePositives: total.fp,
      falsePositiveRate: total.fp + total.ok ? total.fp / (total.fp + total.ok) : null,
      rules,
    };
  });

  // Everything the anti-noise rules ask to measure, over a window.
  app.get("/api/v1/metrics/noise", { preHandler: [app.authenticate] }, async (req) => {
    const { days } = z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }).parse(req.query);
    const orgId = req.principal.organizationId;
    const since = new Date(Date.now() - days * DAY);
    const inOrg = { pullRequest: { repository: { organizationId: orgId } }, createdAt: { gte: since } };
    const [byRuleStatus, byRepoStatus, byType, unlocated, unexplained, blockedPrs, contests, verdicts, exceptionsCreated, exceptionsExpired, noisy] =
      await Promise.all([
        prisma.finding.groupBy({ by: ["ruleId", "status"], where: inOrg, _count: { _all: true } }),
        prisma.finding.findMany({
          where: { ...inOrg, status: "false_positive" },
          select: { pullRequest: { select: { repository: { select: { name: true } } } } },
        }),
        prisma.finding.groupBy({ by: ["type"], where: inOrg, _count: { _all: true } }),
        prisma.finding.count({ where: { ...inOrg, OR: [{ filePath: null }, { line: null, type: { not: "config" } }] } }),
        prisma.finding.count({ where: { ...inOrg, details: { equals: Prisma.DbNull } } }),
        prisma.pullRequest.findMany({
          where: { repository: { organizationId: orgId }, status: "blocked", updatedAt: { gte: since } },
          select: { findings: { where: { assurance: "verified", severity: { in: ["high", "critical"] }, status: { in: ["open", "acknowledged"] } }, select: { ruleId: true } } },
        }),
        prisma.blockContest.groupBy({
          by: ["status"],
          where: { createdAt: { gte: since }, pullRequest: { repository: { organizationId: orgId } } },
          _count: { _all: true },
        }),
        prisma.findingFeedback.findMany({
          where: { createdAt: { gte: since }, repository: { organizationId: orgId }, verdict: "false_positive" },
          select: { createdAt: true, fingerprint: true, repositoryId: true },
        }),
        prisma.findingException.count({ where: { organizationId: orgId, createdAt: { gte: since } } }),
        prisma.findingException.count({ where: { organizationId: orgId, expiresAt: { gte: since, lte: new Date() }, revokedAt: null } }),
        noisyRules(orgId),
      ]);

    const rules = ruleQuality(byRuleStatus.map((g) => ({ ruleId: g.ruleId, status: g.status, count: g._count._all })));
    const blocksByRule = new Map<string, number>();
    for (const pr of blockedPrs) for (const f of new Set(pr.findings.map((x) => x.ruleId ?? "?"))) blocksByRule.set(f, (blocksByRule.get(f) ?? 0) + 1);
    const repoNoise = new Map<string, number>();
    for (const f of byRepoStatus) {
      const name = f.pullRequest.repository.name;
      repoNoise.set(name, (repoNoise.get(name) ?? 0) + 1);
    }
    // Time from the first alert to its false-positive verdict.
    let dismissalHours = 0;
    let dismissalCount = 0;
    for (const v of verdicts.slice(0, 200)) {
      const first = await prisma.finding.findFirst({
        where: { fingerprint: v.fingerprint, pullRequest: { repositoryId: v.repositoryId } },
        orderBy: { createdAt: "asc" },
        select: { createdAt: true },
      });
      if (!first) continue;
      dismissalHours += (v.createdAt.getTime() - first.createdAt.getTime()) / 3_600_000;
      dismissalCount++;
    }
    const contestCount = (s: string) => contests.find((c) => c.status === s)?._count._all ?? 0;
    const totalAlerts = rules.reduce((a, r) => a + r.alerts, 0);

    return {
      days,
      alerts: totalAlerts,
      perRule: rules.map((r) => ({
        ...r,
        blocks: blocksByRule.get(r.ruleId) ?? 0,
        blockRate: r.alerts ? (blocksByRule.get(r.ruleId) ?? 0) / r.alerts : 0,
      })),
      blockedPullRequests: blockedPrs.length,
      contestedBlocks: contestCount("open") + contestCount("upheld") + contestCount("overturned"),
      overturnedBlocks: contestCount("overturned"),
      meanHoursToDismissal: dismissalCount ? Math.round((dismissalHours / dismissalCount) * 10) / 10 : null,
      alertsWithoutLocation: unlocated,
      alertsWithoutScenario: unexplained,
      exceptionsCreated,
      exceptionsExpired,
      rulesInAutoObservation: noisy.map((n) => n.ruleId),
      topNoisyRules: [...rules].sort((a, b) => b.falsePositives - a.falsePositives).filter((r) => r.falsePositives > 0).slice(0, 10),
      topValuableRules: [...rules].sort((a, b) => b.confirmed - a.confirmed).filter((r) => r.confirmed > 0).slice(0, 10),
      topNoisyRepositories: [...repoNoise.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([repository, falsePositives]) => ({ repository, falsePositives })),
      topRiskTypes: byType.sort((a, b) => b._count._all - a._count._all).slice(0, 10).map((t) => ({ type: t.type, alerts: t._count._all })),
    };
  });
}
