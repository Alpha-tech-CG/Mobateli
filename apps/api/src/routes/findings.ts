import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { findingsQuerySchema, updateFindingSchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { decide } from "../analysis/risk.js";
import { findingFingerprint } from "../analysis/analyzer.js";

/** Who may hide a finding: marking a false positive removes it from the score. */
const TRIAGE_FP = new Set(["owner", "admin", "security_manager"]);

/** Recompute a PR's score/status from what is still open (after triage). */
async function rescorePullRequest(pullRequestId: string) {
  const [findings, secrets, dependencies] = await Promise.all([
    prisma.finding.findMany({ where: { pullRequestId, status: { not: "false_positive" } } }),
    prisma.secretFinding.findMany({ where: { pullRequestId, status: { not: "false_positive" } } }),
    prisma.dependency.findMany({ where: { pullRequestId } }),
  ]);
  const { riskScore, status } = decide({
    findings: findings.map((f) => ({
      type: f.type,
      severity: f.severity,
      title: f.title,
      description: f.description,
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

/** Findings triage (cahier §13.3, US02 "les faux positifs peuvent être marqués"). */
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
      const finding = await prisma.finding.findFirst({
        where: { id, pullRequest: { repository: { organizationId: req.principal.organizationId } } },
        include: { pullRequest: { select: { id: true, repositoryId: true } } },
      });
      if (!finding) return reply.code(404).send({ error: "not_found" });

      const touchesFp = body.status === "false_positive" || finding.status === "false_positive";
      if (touchesFp && !TRIAGE_FP.has(req.principal.role)) {
        return reply.code(403).send({ error: "forbidden" });
      }

      const repositoryId = finding.pullRequest.repositoryId;
      const fingerprint = findingFingerprint({
        title: finding.title,
        ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
        ...(finding.filePath ? { filePath: finding.filePath } : {}),
      });

      await prisma.finding.update({ where: { id }, data: { status: body.status } });
      if (body.status === "false_positive") {
        await prisma.findingSuppression.upsert({
          where: { repositoryId_fingerprint: { repositoryId, fingerprint } },
          create: {
            repositoryId,
            fingerprint,
            reason: body.reason ?? null,
            createdById: req.principal.userId,
          },
          update: { reason: body.reason ?? null },
        });
      } else if (finding.status === "false_positive") {
        await prisma.findingSuppression.deleteMany({ where: { repositoryId, fingerprint } });
      }

      const rescored = touchesFp ? await rescorePullRequest(finding.pullRequest.id) : null;

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
}
