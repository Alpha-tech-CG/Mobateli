import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { approvalDecisionSchema, approvalsQuerySchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import { effectiveStatus } from "../lib/approvals.js";

/**
 * Human approvals (cahier §5.4, §5.5, §10.5, US06). Reviewers decide in the
 * dashboard; agents poll the decision of their own request.
 */
export async function approvalRoutes(app: FastifyInstance) {
  app.get("/api/v1/approvals", { preHandler: [app.authenticate] }, async (req) => {
    const q = approvalsQuerySchema.parse(req.query);
    const now = new Date();
    const rows = await prisma.approvalRequest.findMany({
      where: {
        organizationId: req.principal.organizationId,
        ...(q.status === "pending"
          ? { status: "pending", expiresAt: { gt: now } }
          : q.status === "expired"
            ? { status: "pending", expiresAt: { lte: now } }
            : q.status
              ? { status: q.status }
              : {}),
      },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
    return { approvals: rows.map((r) => ({ ...r, status: effectiveStatus(r, now) })) };
  });

  app.post(
    "/api/v1/approvals/:id/decision",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = approvalDecisionSchema.parse(req.body);
      const request = await prisma.approvalRequest.findFirst({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!request) return reply.code(404).send({ error: "not_found" });
      const status = effectiveStatus(request);
      if (status !== "pending") return reply.code(409).send({ error: `already_${status}` });

      const decided = body.decision === "approve" ? "approved" : "denied";
      await prisma.approvalRequest.update({
        where: { id },
        data: {
          status: decided,
          decidedById: req.principal.userId,
          decidedAt: new Date(),
          reason: body.reason ?? null,
        },
      });

      // A deployment waiting for validation takes the human decision.
      const detail = request.detail as { deployCheckId?: string };
      if (request.kind === "deployment" && detail.deployCheckId) {
        await prisma.deployCheck.updateMany({
          where: { id: detail.deployCheckId, repository: { organizationId: req.principal.organizationId } },
          data: {
            decision: decided === "approved" ? "authorized" : "blocked",
            reason: `${decided === "approved" ? "Validé" : "Refusé"} par un humain${body.reason ? ` : ${body.reason}` : ""}.`,
          },
        });
      }

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: `approval.${decided}`,
        resourceType: "approval_request",
        resourceId: id,
        metadata: { kind: request.kind, title: request.title, ...(body.reason ? { reason: body.reason } : {}) },
      });
      return { id, status: decided };
    },
  );

  // Polled by the agent that asked (same organization).
  app.get("/api/v1/agent/approvals/:id", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const r = await prisma.approvalRequest.findFirst({
      where: { id, organizationId: req.principal.organizationId },
      select: { status: true, expiresAt: true, reason: true, decidedAt: true },
    });
    if (!r) return reply.code(404).send({ error: "not_found" });
    return { status: effectiveStatus(r), reason: r.reason, decidedAt: r.decidedAt };
  });
}
