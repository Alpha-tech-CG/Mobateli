import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { createPolicySchema } from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";

/**
 * Policy Engine management (cahier §5.5, §13.3). Security managers define, per
 * org or per repo, the action to take above a severity threshold.
 */
export async function policyRoutes(app: FastifyInstance) {
  app.get(
    "/api/v1/policies",
    { preHandler: [app.authenticate] },
    async (req) => {
      const policies = await prisma.policy.findMany({
        where: { organizationId: req.principal.organizationId },
        orderBy: { createdAt: "desc" },
      });
      return { policies };
    },
  );

  app.post(
    "/api/v1/policies",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager"),
      ],
    },
    async (req, reply) => {
      const body = createPolicySchema.parse(req.body);

      // If scoped to a repo, ensure it belongs to the caller's org.
      if (body.repositoryId) {
        const repo = await prisma.repository.findFirst({
          where: { id: body.repositoryId, organizationId: req.principal.organizationId },
          select: { id: true },
        });
        if (!repo) return reply.code(404).send({ error: "repository_not_found" });
      }

      const policy = await prisma.policy.create({
        data: {
          organizationId: req.principal.organizationId,
          repositoryId: body.repositoryId ?? null,
          rule: body.rule,
          action: body.action,
          severityThreshold: body.severityThreshold,
        },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "policy.created",
        resourceType: "policy",
        resourceId: policy.id,
        metadata: { action: body.action, severityThreshold: body.severityThreshold },
      });

      return reply.code(201).send({ policy });
    },
  );
}
