import type { FastifyInstance } from "fastify";
import { prisma, type Prisma } from "@codegate/db";
import { auditQuerySchema, auditExportSchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { buildEvidencePack, evidenceToCsv, evidenceToPdf } from "../lib/evidence.js";

/**
 * Audit trail + Compliance Evidence Pack export (cahier §5.8, §13.3, US07).
 */
export async function auditRoutes(app: FastifyInstance) {
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

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "audit.exported",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { format: body.format },
      });

      const stamp = new Date().toISOString().slice(0, 10);
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
      const pdf = await evidenceToPdf(pack);
      return reply
        .header("content-type", "application/pdf")
        .header("content-disposition", `attachment; filename="codegate-evidence-${stamp}.pdf"`)
        .send(pdf);
    },
  );
}
