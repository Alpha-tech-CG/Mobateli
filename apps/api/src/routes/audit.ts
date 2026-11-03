import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { prisma, type Prisma } from "@codegate/db";
import { auditQuerySchema, auditExportSchema } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { renderSignedReport } from "../lib/audit-report.js";
import { buildEvidencePack, evidenceToCsv } from "../lib/evidence.js";
import { getSigningIdentity } from "../lib/report-signing.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Audit trail + Compliance Evidence Pack export (cahier §5.8, §13.3, US07).
 */
export async function auditRoutes(app: FastifyInstance, config: AppConfig) {
  // Paginated audit event list for the dashboard.
  app.get(
    "/api/v1/audit-events",
    { preHandler: [app.authenticate] },
    async (req) => {
      const q = auditQuerySchema.parse(req.query);
      const range: Prisma.DateTimeFilter = {};
      if (q.from) range.gte = new Date(q.from);
      if (q.to) range.lte = new Date(q.to);

      const events = await prisma.auditEvent.findMany({
        where: {
          organizationId: req.principal.organizationId,
          ...(q.from || q.to ? { createdAt: range } : {}),
          ...(q.action ? { action: q.action } : {}),
        },
        orderBy: { createdAt: "desc" },
        take: q.limit,
      });
      return { events };
    },
  );

  // Export the evidence pack in the requested format.
  app.post(
    "/api/v1/audit/export",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const body = auditExportSchema.parse(req.body);
      const pack = await buildEvidencePack(req.principal.organizationId, {
        ...(body.repositoryId ? { repositoryId: body.repositoryId } : {}),
        ...(body.from ? { from: body.from } : {}),
        ...(body.to ? { to: body.to } : {}),
        ...(body.severityThreshold ? { severityThreshold: body.severityThreshold } : {}),
      });

      const stamp = new Date().toISOString().slice(0, 10);
      if (body.format !== "pdf") {
        await recordAudit({
          organizationId: req.principal.organizationId,
          actorType: "user",
          actorId: req.principal.userId,
          action: "audit.exported",
          resourceType: "organization",
          resourceId: req.principal.organizationId,
          metadata: { format: body.format },
        });
      }
      if (body.format === "json") {
        return reply
          .header("content-type", "application/json")
          .header("content-disposition", `attachment; filename="codegate-evidence-${stamp}.json"`)
          .send(JSON.stringify(pack, null, 2));
      }
      if (body.format === "csv") {
        return reply
          .header("content-type", "text/csv")
          .header("content-disposition", `attachment; filename="codegate-evidence-${stamp}.csv"`)
          .send(evidenceToCsv(pack));
      }

      // Signed PDF report, recorded in the public verification register.
      const reportId = randomUUID();
      const [identity, user] = await Promise.all([
        getSigningIdentity(config),
        prisma.user.findUnique({ where: { id: req.principal.userId }, select: { name: true, email: true } }),
      ]);
      const { pdf, sha256 } = await renderSignedReport(pack, {
        reportId,
        verifyUrl: `${config.WEB_ORIGIN.replace(/\/$/, "")}/verify/${reportId}`,
        generatedBy: user ? `${user.name} <${user.email}>` : "CodeGate",
        identity,
      });
      await prisma.auditReport.create({
        data: {
          id: reportId,
          organizationId: req.principal.organizationId,
          generatedById: req.principal.userId,
          sha256,
          signerFingerprint: identity.fingerprint,
          filters: pack.filters as Prisma.InputJsonValue,
          summary: pack.summary as unknown as Prisma.InputJsonValue,
        },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "audit.exported",
        resourceType: "audit_report",
        resourceId: reportId,
        metadata: { format: "pdf", sha256, signer: identity.fingerprint },
      });
      return reply
        .header("content-type", "application/pdf")
        .header("content-disposition", `attachment; filename="codegate-rapport-audit-${stamp}-${reportId.slice(0, 8)}.pdf"`)
        .header("x-report-id", reportId)
        .send(pdf);
    },
  );

  // Public verification of a signed report (no account needed: the id is
  // printed on the report and only its fingerprint is disclosed).
  app.get("/api/v1/reports/:id/verify", async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!UUID.test(id)) return reply.code(404).send({ error: "report_not_found" });
    const report = await prisma.auditReport.findUnique({
      where: { id },
      include: { organization: { select: { name: true } } },
    });
    if (!report) return reply.code(404).send({ error: "report_not_found" });
    const { sha256 } = (req.query ?? {}) as { sha256?: string };
    return {
      report: {
        id: report.id,
        organization: report.organization.name,
        issuedAt: report.createdAt,
        sha256: report.sha256,
        signerFingerprint: report.signerFingerprint,
        summary: report.summary,
      },
      ...(sha256 ? { matches: sha256.toLowerCase() === report.sha256 } : {}),
    };
  });

  // Reports this org has issued.
  app.get("/api/v1/reports", { preHandler: [app.authenticate] }, async (req) => {
    const reports = await prisma.auditReport.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
      take: 50,
      select: { id: true, sha256: true, createdAt: true, filters: true, summary: true, signerFingerprint: true },
    });
    return { reports };
  });
}
