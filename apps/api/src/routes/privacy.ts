import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { deleteOrganizationSchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";

/**
 * RGPD (cahier §10.1 « suppression des données sur demande », §11.3 droit à
 * l'effacement, portabilité). Exports never contain secrets: no password or
 * token hashes, no encrypted integration credentials, no MFA secrets.
 */
export async function privacyRoutes(app: FastifyInstance) {
  app.get(
    "/api/v1/organization/export",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const organizationId = req.principal.organizationId;
      const [organization, users, repositories, policies, servers, backups, auditEvents] =
        await Promise.all([
          prisma.organization.findUniqueOrThrow({ where: { id: organizationId } }),
          prisma.user.findMany({
            where: { organizationId },
            select: { id: true, email: true, name: true, role: true, mfaEnabled: true, active: true, createdAt: true },
          }),
          prisma.repository.findMany({
            where: { organizationId },
            select: {
              id: true,
              provider: true,
              name: true,
              defaultBranch: true,
              protectionLevel: true,
              createdAt: true,
              pullRequests: {
                include: {
                  findings: true,
                  dependencies: true,
                  secretFindings: { select: { secretType: true, location: true, maskedPreview: true, status: true } },
                },
              },
            },
          }),
          prisma.policy.findMany({ where: { organizationId } }),
          prisma.server.findMany({
            where: { organizationId },
            select: {
              id: true, name: true, provider: true, environment: true, hostname: true, os: true,
              securityScore: true, lastReportAt: true, findings: true,
            },
          }),
          prisma.backupJob.findMany({
            where: { organizationId },
            select: { id: true, name: true, type: true, frequencyHours: true, runs: true, restoreTests: true },
          }),
          prisma.auditEvent.findMany({ where: { organizationId }, orderBy: { createdAt: "asc" } }),
        ]);

      await recordAudit({
        organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "org.data_exported",
        resourceType: "organization",
        resourceId: organizationId,
      });

      return reply
        .header("content-disposition", `attachment; filename="codegate-export-${organizationId}.json"`)
        .send({
          exportedAt: new Date().toISOString(),
          organization,
          users,
          repositories,
          policies,
          servers,
          backups,
          auditEvents,
        });
    },
  );

  // Right to erasure for a whole organization: irreversible, owner only, and
  // the exact organization name must be typed to confirm.
  app.delete(
    "/api/v1/organization",
    { preHandler: [app.authenticate, app.requireRole("owner")] },
    async (req, reply) => {
      const body = deleteOrganizationSchema.parse(req.body);
      const org = await prisma.organization.findUniqueOrThrow({
        where: { id: req.principal.organizationId },
        select: { id: true, name: true },
      });
      if (body.confirmName !== org.name) {
        return reply.code(400).send({ error: "confirmation_mismatch" });
      }
      // Every tenant table cascades from the organization (including the
      // audit trail, which is part of the data to erase).
      await prisma.organization.delete({ where: { id: org.id } });
      req.log.info({ organizationId: org.id }, "organization erased on request");
      return reply.code(204).send();
    },
  );

  // A member erases their own account (an owner must hand over first).
  app.delete("/api/v1/account", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { userId, organizationId, role } = req.principal;
    if (role === "owner") {
      const owners = await prisma.user.count({ where: { organizationId, role: "owner", active: true } });
      if (owners <= 1) return reply.code(409).send({ error: "last_owner" });
    }
    await prisma.user.delete({ where: { id: userId } });
    await recordAudit({
      organizationId,
      actorType: "system",
      action: "user.erased",
      resourceType: "user",
      resourceId: userId,
    });
    return reply.code(204).send();
  });
}
