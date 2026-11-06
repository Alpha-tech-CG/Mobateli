import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import { ruleQuality } from "../analysis/feedback.js";

/**
 * Pilot false-positive tracking. A security reviewer marks an alert as a
 * false positive or confirms it; the verdict is stored per repository and
 * alert fingerprint, so it survives re-analysis, and a false positive stops
 * weighing on later verdicts for the same code. Every verdict is audited —
 * dismissing an alert is a security decision.
 */

const feedbackSchema = z.object({
  verdict: z.enum(["false_positive", "confirmed"]),
  note: z.string().trim().max(500).optional(),
});

const REVIEWERS = ["owner", "admin", "security_manager"] as const;

async function findOwnedFinding(id: string, organizationId: string) {
  return prisma.finding.findFirst({
    where: { id, pullRequest: { repository: { organizationId } } },
    select: {
      id: true,
      ruleId: true,
      filePath: true,
      fingerprint: true,
      pullRequest: { select: { repositoryId: true } },
    },
  });
}

export async function findingRoutes(app: FastifyInstance) {
  app.put(
    "/api/v1/findings/:id/feedback",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = feedbackSchema.parse(req.body);
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding) return reply.code(404).send({ error: "not_found" });
      // Findings stored before fingerprints existed: a re-analysis assigns one.
      if (!finding.fingerprint) return reply.code(409).send({ error: "rescan_required" });

      const repositoryId = finding.pullRequest.repositoryId;
      const data = {
        verdict: body.verdict,
        note: body.note ?? null,
        userId: req.principal.userId,
        ruleId: finding.ruleId,
        filePath: finding.filePath,
      };
      await prisma.$transaction([
        prisma.findingFeedback.upsert({
          where: { repositoryId_fingerprint: { repositoryId, fingerprint: finding.fingerprint } },
          create: { repositoryId, fingerprint: finding.fingerprint, ...data },
          update: data,
        }),
        // The same alert across this repo's PRs carries the same verdict.
        prisma.finding.updateMany({
          where: { fingerprint: finding.fingerprint, pullRequest: { repositoryId } },
          data: { status: body.verdict === "false_positive" ? "false_positive" : "acknowledged" },
        }),
      ]);
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "finding.feedback",
        resourceType: "finding",
        resourceId: finding.id,
        metadata: { verdict: body.verdict, ruleId: finding.ruleId, note: body.note ?? null },
      });
      return { status: "recorded", verdict: body.verdict };
    },
  );

  app.delete(
    "/api/v1/findings/:id/feedback",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding?.fingerprint) return reply.code(404).send({ error: "not_found" });
      const repositoryId = finding.pullRequest.repositoryId;
      await prisma.$transaction([
        prisma.findingFeedback.deleteMany({ where: { repositoryId, fingerprint: finding.fingerprint } }),
        prisma.finding.updateMany({
          where: { fingerprint: finding.fingerprint, pullRequest: { repositoryId } },
          data: { status: "open" },
        }),
      ]);
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
  app.get(
    "/api/v1/metrics/rule-quality",
    { preHandler: [app.authenticate] },
    async (req) => {
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
      const rules = ruleQuality(
        groups.map((g) => ({ ruleId: g.ruleId, status: g.status, count: g._count._all })),
      );
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
    },
  );
}
