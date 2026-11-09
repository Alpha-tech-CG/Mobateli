import type { FastifyInstance, FastifyReply } from "fastify";
import { prisma } from "@codegate/db";
import {
  findingFeedbackSchema,
  findingsQuerySchema,
  updateFindingSchema,
  type FindingFeedbackInput,
} from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { rescorePullRequest } from "../lib/rescore.js";
import { revocationGuide } from "../analysis/revocation.js";

/**
 * Findings triage and the team's verdicts (cahier §13.1, §13.3, US02; anti-
 * noise rules).
 *
 * A verdict is stored per repository and alert fingerprint (rule + file +
 * flagged code, see analysis/fingerprint.ts), so it survives re-analysis and
 * applies to the same alert in every PR of the repository:
 *  - "false positive": a category and a reason are required; it lapses after
 *    90 days by default (the alert then comes back for a fresh look);
 *  - "accepted risk": a reason and an expiry date are required;
 *  - "confirmed" (true positive): anyone in the team may say so.
 * Dismissing or accepting an alert is a security decision: reviewers only,
 * always audited.
 */

const REVIEWERS = ["owner", "admin", "security_manager"] as const;
const IS_REVIEWER = new Set<string>(REVIEWERS);
const DEFAULT_FP_DAYS = 90;

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

const STATUS_OF = {
  false_positive: "false_positive",
  accepted_risk: "accepted_risk",
  confirmed: "acknowledged",
} as const;

/**
 * Store (or clear, with `input: null`) the repository's verdict on this
 * alert, apply it to the same alert in every PR of the repository, and
 * rescore the PRs whose open alerts changed. Returns this PR's new score.
 */
async function applyVerdict(finding: OwnedFinding & { fingerprint: string }, input: FindingFeedbackInput | null, userId: string) {
  const repositoryId = finding.pullRequest.repositoryId;
  const fingerprint = finding.fingerprint;
  const sameAlert = { fingerprint, pullRequest: { repositoryId } };
  const affected = await prisma.finding.findMany({ where: sameAlert, select: { pullRequestId: true } });
  const expiresAt = input?.expiresAt
    ? new Date(input.expiresAt)
    : input?.verdict === "false_positive"
      ? new Date(Date.now() + DEFAULT_FP_DAYS * 86_400_000)
      : null;
  const data = input
    ? {
        verdict: input.verdict,
        note: input.note ?? null,
        category: input.verdict === "false_positive" ? (input.category ?? null) : null,
        expiresAt,
        userId,
      }
    : null;

  await prisma.$transaction([
    data
      ? prisma.findingFeedback.upsert({
          where: { repositoryId_fingerprint: { repositoryId, fingerprint } },
          create: { repositoryId, fingerprint, ruleId: finding.ruleId, filePath: finding.filePath, ...data },
          update: data,
        })
      : prisma.findingFeedback.deleteMany({ where: { repositoryId, fingerprint } }),
    prisma.finding.updateMany({ where: sameAlert, data: { status: input ? STATUS_OF[input.verdict] : "open" } }),
  ]);

  let current: Awaited<ReturnType<typeof rescorePullRequest>> | null = null;
  for (const pullRequestId of new Set(affected.map((a) => a.pullRequestId))) {
    const rescored = await rescorePullRequest(pullRequestId);
    if (pullRequestId === finding.pullRequestId) current = rescored;
  }
  return { rescored: current, expiresAt };
}

/** Findings stored before fingerprints existed get one at the next analysis. */
function needsFingerprint(finding: OwnedFinding, reply: FastifyReply) {
  if (finding.fingerprint) return false;
  void reply.code(409).send({ error: "rescan_required" });
  return true;
}

const DISMISSING = new Set(["false_positive", "accepted_risk"]);

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

  // Triage status of one finding. Dismissing it (false positive, accepted
  // risk) or reopening a dismissed one is a verdict on the alert: reviewers
  // only, with the same requirements as PUT …/feedback, applied repository-wide.
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
      if (finding.status === "suppressed") return reply.code(409).send({ error: "covered_by_exception" });

      const touchesVerdict = DISMISSING.has(body.status) || DISMISSING.has(finding.status);
      if (touchesVerdict && !IS_REVIEWER.has(req.principal.role)) {
        return reply.code(403).send({ error: "forbidden" });
      }

      let rescored = null;
      if (touchesVerdict) {
        if (needsFingerprint(finding, reply)) return reply;
        let verdict: FindingFeedbackInput | null = null;
        if (DISMISSING.has(body.status)) {
          const parsed = findingFeedbackSchema.safeParse({
            verdict: body.status,
            ...(body.reason ? { note: body.reason } : {}),
            ...(body.category ? { category: body.category } : {}),
            ...(body.expiresAt ? { expiresAt: body.expiresAt } : {}),
          });
          if (!parsed.success) return reply.code(400).send({ error: "validation_error", issues: parsed.error.issues });
          verdict = parsed.data;
        }
        ({ rescored } = await applyVerdict({ ...finding, fingerprint: finding.fingerprint! }, verdict, req.principal.userId));
        if (!DISMISSING.has(body.status) && body.status !== "open") {
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
          ...(body.category ? { category: body.category } : {}),
        },
      });

      return { finding: { id, status: body.status }, pullRequest: rescored };
    },
  );

  // The team's verdict on an alert: false positive, accepted risk, or
  // confirmed as real (true positive — any team member may say so).
  app.put(
    "/api/v1/findings/:id/feedback",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager", "developer"),
      ],
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = findingFeedbackSchema.parse(req.body);
      if (body.verdict !== "confirmed" && !IS_REVIEWER.has(req.principal.role)) {
        return reply.code(403).send({ error: "forbidden" });
      }
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding) return reply.code(404).send({ error: "not_found" });
      if (needsFingerprint(finding, reply)) return reply;

      const { rescored, expiresAt } = await applyVerdict(
        { ...finding, fingerprint: finding.fingerprint! },
        body,
        req.principal.userId,
      );
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "finding.feedback",
        resourceType: "finding",
        resourceId: finding.id,
        metadata: {
          verdict: body.verdict,
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          note: body.note ?? null,
          category: body.category ?? null,
          expiresAt: expiresAt?.toISOString() ?? null,
        },
      });
      return { status: "recorded", verdict: body.verdict, expiresAt, pullRequest: rescored };
    },
  );

  app.delete(
    "/api/v1/findings/:id/feedback",
    { preHandler: [app.authenticate, app.requireRole(...REVIEWERS)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const finding = await findOwnedFinding(id, req.principal.organizationId);
      if (!finding?.fingerprint) return reply.code(404).send({ error: "not_found" });
      await applyVerdict({ ...finding, fingerprint: finding.fingerprint }, null, req.principal.userId);
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
