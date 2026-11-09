import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { prisma } from "@codegate/db";
import { findingsQuerySchema, updateFindingSchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { decide } from "../analysis/risk.js";
import { ruleQuality } from "../analysis/feedback.js";
import { revocationGuide } from "../analysis/revocation.js";

/**
 * Findings triage and the team's verdicts (cahier §13.1, §13.3, US02 "les
 * faux positifs peuvent être marqués").
 *
 * A verdict — "false positive" or "confirmed" — is stored per repository and
 * alert fingerprint (rule + file + flagged code, see analysis/fingerprint.ts),
 * so it survives re-analysis and applies to the same alert in every PR of the
 * repository. A false positive stops weighing on the score; it stays stored,
 * with its status, for the per-rule false-positive rate. Dismissing an alert
 * is a security decision: only reviewers may do it, and it is audited.
 */

/** Who may give a verdict: a false positive removes an alert from the score. */
const REVIEWERS = ["owner", "admin", "security_manager"] as const;
const IS_REVIEWER = new Set<string>(REVIEWERS);

const feedbackSchema = z.object({
  verdict: z.enum(["false_positive", "confirmed"]),
  note: z.string().trim().max(500).optional(),
});
type Verdict = z.infer<typeof feedbackSchema>["verdict"];

/** Recompute a PR's score/status from what is still open (after triage). */
async function rescorePullRequest(pullRequestId: string) {
  const [findings, secrets, dependencies] = await Promise.all([
    prisma.finding.findMany({ where: { pullRequestId, status: { not: "false_positive" } } }),
    prisma.secretFinding.findMany({ where: { pullRequestId, status: { notIn: ["false_positive", "resolved"] } } }),
    prisma.dependency.findMany({ where: { pullRequestId } }),
  ]);
  const { riskScore, status } = decide({
    findings: findings.map((f) => ({
      type: f.type,
      severity: f.severity,
      title: f.title,
      description: f.description,
      ...(f.ruleId ? { ruleId: f.ruleId } : {}),
    })),
    secrets: secrets.map((s) => ({
      secretType: s.secretType,
      location: s.location,
      maskedPreview: s.maskedPreview,
      severity: s.severity,
    })),
    dependencies: dependencies.map((d) => ({
      ecosystem: d.ecosystem,
      name: d.name,
      version: d.version,
      trustScore: d.trustScore ?? 0,
      riskLevel: d.riskLevel,
    })),
  });
  await prisma.pullRequest.update({ where: { id: pullRequestId }, data: { riskScore, status } });
  return { riskScore, status };
}

async function findOwnedFinding(id: string, organizationId: string) {
  return prisma.finding.findFirst({
    where: { id, pullRequest: { repository: { organizationId } } },
    select: {
      id: true,
      ruleId: true,
      filePath: true,
      status: true,
      fingerprint: true,
      pullRequestId: true,
      pullRequest: { select: { repositoryId: true } },
    },
  });
}
type OwnedFinding = NonNullable<Awaited<ReturnType<typeof findOwnedFinding>>>;

/**
 * Store (or clear, with `verdict: null`) the repository's verdict on this
 * alert, apply it to the same alert in every PR of the repository, and
 * rescore the PRs whose open alerts changed. Returns this PR's new score.
 */
async function applyVerdict(
  finding: OwnedFinding & { fingerprint: string },
  verdict: Verdict | null,
  by: { userId: string; note?: string | null },
) {
  const repositoryId = finding.pullRequest.repositoryId;
  const fingerprint = finding.fingerprint;
  const sameAlert = { fingerprint, pullRequest: { repositoryId } };
  const affected = await prisma.finding.findMany({ where: sameAlert, select: { pullRequestId: true } });
  const status = verdict === "false_positive" ? "false_positive" : verdict === "confirmed" ? "acknowledged" : "open";

  await prisma.$transaction([
    verdict
      ? prisma.findingFeedback.upsert({
          where: { repositoryId_fingerprint: { repositoryId, fingerprint } },
          create: {
            repositoryId,
            fingerprint,
            verdict,
            note: by.note ?? null,
            userId: by.userId,
            ruleId: finding.ruleId,
            filePath: finding.filePath,
          },
          update: { verdict, note: by.note ?? null, userId: by.userId },
        })
      : prisma.findingFeedback.deleteMany({ where: { repositoryId, fingerprint } }),
    prisma.finding.updateMany({ where: sameAlert, data: { status } }),
  ]);

  let current: Awaited<ReturnType<typeof rescorePullRequest>> | null = null;
  for (const pullRequestId of new Set(affected.map((a) => a.pullRequestId))) {
    const rescored = await rescorePullRequest(pullRequestId);
    if (pullRequestId === finding.pullRequestId) current = rescored;
  }
  return current;
}

/** Findings stored before fingerprints existed get one at the next analysis. */
function needsFingerprint(finding: OwnedFinding, reply: FastifyReply) {
  if (finding.fingerprint) return false;
  void reply.code(409).send({ error: "rescan_required" });
  return true;
}

export async function findingRoutes(app: FastifyInstance) {
  app.get("/api/v1/findings", { preHandler: [app.authenticate] }, async (req) => {
    const q = findingsQuerySchema.parse(req.query);
    const findings = await prisma.finding.findMany({
      where: {
        pullRequest: {
          repository: {
            organizationId: req.principal.organizationId,
            ...(q.repositoryId ? { id: q.repositoryId } : {}),
          },
        },
        ...(q.status ? { status: q.status } : {}),
        ...(q.severity ? { severity: q.severity } : {}),
      },
      orderBy: { createdAt: "desc" },
      take: q.limit,
      include: {
        pullRequest: {
          select: { id: true, number: true, title: true, repository: { select: { name: true } } },
        },
      },
    });
    return { findings };
  });

  // Triage status of one finding. Marking (or un-marking) a false positive is
  // a verdict on the alert: reviewers only, applied repository-wide.
  app.patch(
    "/api/v1/findings/:id",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager", "developer"),
      ],
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = updateFindingSchema.parse(req.body);
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding) return reply.code(404).send({ error: "not_found" });

      const touchesFp = body.status === "false_positive" || finding.status === "false_positive";
      if (touchesFp && !IS_REVIEWER.has(req.principal.role)) {
        return reply.code(403).send({ error: "forbidden" });
      }

      let rescored = null;
      if (touchesFp) {
        if (needsFingerprint(finding, reply)) return reply;
        rescored = await applyVerdict(
          { ...finding, fingerprint: finding.fingerprint! },
          body.status === "false_positive" ? "false_positive" : null,
          { userId: req.principal.userId, note: body.reason ?? null },
        );
        if (body.status !== "false_positive" && body.status !== "open") {
          await prisma.finding.update({ where: { id }, data: { status: body.status } });
        }
      } else {
        await prisma.finding.update({ where: { id }, data: { status: body.status } });
      }

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: `finding.${body.status}`,
        resourceType: "finding",
        resourceId: id,
        metadata: {
          from: finding.status,
          to: body.status,
          ruleId: finding.ruleId,
          ...(body.reason ? { reason: body.reason } : {}),
        },
      });

      return { finding: { id, status: body.status }, pullRequest: rescored };
    },
  );

  // The team's verdict on an alert: false positive, or confirmed as real.
  app.put(
    "/api/v1/findings/:id/feedback",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req: FastifyRequest, reply) => {
      const { id } = req.params as { id: string };
      const body = feedbackSchema.parse(req.body);
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding) return reply.code(404).send({ error: "not_found" });
      if (needsFingerprint(finding, reply)) return reply;

      const rescored = await applyVerdict({ ...finding, fingerprint: finding.fingerprint! }, body.verdict, {
        userId: req.principal.userId,
        note: body.note ?? null,
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "finding.feedback",
        resourceType: "finding",
        resourceId: finding.id,
        metadata: { verdict: body.verdict, ruleId: finding.ruleId, note: body.note ?? null },
      });
      return { status: "recorded", verdict: body.verdict, pullRequest: rescored };
    },
  );

  app.delete(
    "/api/v1/findings/:id/feedback",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding?.fingerprint) return reply.code(404).send({ error: "not_found" });
      await applyVerdict({ ...finding, fingerprint: finding.fingerprint }, null, { userId: req.principal.userId });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "finding.feedback_cleared",
        resourceType: "finding",
        resourceId: finding.id,
        metadata: { ruleId: finding.ruleId },
      });
      return reply.code(204).send();
    },
  );

  // Per-rule false-positive rate over a window — the pilot's main metric.
  app.get("/api/v1/metrics/rule-quality", { preHandler: [app.authenticate] }, async (req) => {
    const { days } = z
      .object({ days: z.coerce.number().int().min(1).max(365).default(30) })
      .parse(req.query);
    const since = new Date(Date.now() - days * 86_400_000);
    const groups = await prisma.finding.groupBy({
      by: ["ruleId", "status"],
      where: {
        createdAt: { gte: since },
        pullRequest: { repository: { organizationId: req.principal.organizationId } },
      },
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

  // US03: guided revocation of an exposed secret.
  app.get("/api/v1/secrets/:id/revocation", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const secret = await prisma.secretFinding.findFirst({
      where: { id, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
      select: { secretType: true, location: true, maskedPreview: true, status: true, revokedAt: true },
    });
    if (!secret) return reply.code(404).send({ error: "not_found" });
    return { secret, guide: revocationGuide(secret.secretType) };
  });

  // Proof of remediation: the key was rotated at the provider.
  app.post(
    "/api/v1/secrets/:id/revoked",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager", "developer")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const secret = await prisma.secretFinding.findFirst({
        where: { id, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
        select: { id: true, pullRequestId: true, secretType: true },
      });
      if (!secret) return reply.code(404).send({ error: "not_found" });
      await prisma.secretFinding.update({
        where: { id },
        data: { status: "resolved", revokedAt: new Date() },
      });
      const rescored = await rescorePullRequest(secret.pullRequestId);
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "secret.revoked",
        resourceType: "secret_finding",
        resourceId: id,
        metadata: { secretType: secret.secretType },
      });
      return { id, revoked: true, pullRequest: rescored };
    },
  );
}
