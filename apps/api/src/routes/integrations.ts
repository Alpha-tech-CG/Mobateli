import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { connectLinearSchema } from "@codegate/shared";
import { encrypt } from "../lib/crypto.js";
import { recordAudit } from "../lib/audit.js";
import type { AppConfig } from "../config.js";

/**
 * Integration management. The Linear API key is encrypted at rest and never
 * returned to the client (cahier §10.3).
 */
export async function integrationRoutes(app: FastifyInstance, config: AppConfig) {
  app.get(
    "/api/v1/integrations/linear",
    { preHandler: [app.authenticate] },
    async (req) => {
      const conn = await prisma.linearConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { teamId: true, createdAt: true },
      });
      return { connected: conn !== null, teamId: conn?.teamId ?? null };
    },
  );

  app.post(
    "/api/v1/integrations/linear",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager"),
      ],
    },
    async (req, reply) => {
      const body = connectLinearSchema.parse(req.body);
      const apiKeyEncrypted = encrypt(body.apiKey, config.ENCRYPTION_KEY);

      await prisma.linearConnection.upsert({
        where: { organizationId: req.principal.organizationId },
        create: {
          organizationId: req.principal.organizationId,
          apiKeyEncrypted,
          teamId: body.teamId,
        },
        update: { apiKeyEncrypted, teamId: body.teamId },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.linear_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { teamId: body.teamId },
      });

      return reply.code(201).send({ connected: true, teamId: body.teamId });
    },
  );

  app.delete(
    "/api/v1/integrations/linear",
    {
      preHandler: [app.authenticate, app.requireRole("owner", "admin")],
    },
    async (req) => {
      await prisma.linearConnection.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.linear_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );
}
