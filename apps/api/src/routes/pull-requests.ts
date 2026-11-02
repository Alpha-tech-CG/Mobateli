import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import type { Jobs } from "../lib/jobs.js";

/**
 * Read endpoints for the dashboard (cahier §13.3), plus manual rescan.
 * Everything is scoped to the caller's organization via the repository.
 */
export async function pullRequestRoutes(app: FastifyInstance, jobs: Jobs) {
  // List analyzed pull requests for the org.
  app.get(
    "/api/v1/pull-requests",
    { preHandler: [app.authenticate] },
    async (req) => {
      const prs = await prisma.pullRequest.findMany({
        where: { repository: { organizationId: req.principal.organizationId } },
        include: {
          repository: { select: { name: true } },
          _count: { select: { findings: true, secretFindings: true, dependencies: true } },
        },
        orderBy: { createdAt: "desc" },
        take: 100,
      });

      return {
        pullRequests: prs.map((pr) => ({
          id: pr.id,
          number: pr.number,
          title: pr.title,
          author: pr.author,
          aiGenerated: pr.aiGenerated,
          riskScore: pr.riskScore,
          status: pr.status,
          repository: pr.repository.name,
          counts: {
            findings: pr._count.findings,
            secrets: pr._count.secretFindings,
            dependencies: pr._count.dependencies,
          },
          createdAt: pr.createdAt,
        })),
      };
    },
  );

  // Full analysis detail for one PR.
  app.get(
    "/api/v1/pull-requests/:id",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const pr = await prisma.pullRequest.findFirst({
        where: { id, repository: { organizationId: req.principal.organizationId } },
        include: {
          repository: { select: { name: true, protectionLevel: true } },
          findings: { orderBy: { severity: "desc" } },
          dependencies: true,
          secretFindings: true,
        },
      });
      if (!pr) return reply.code(404).send({ error: "not_found" });
      return { pullRequest: pr };
    },
  );

  // Manual rescan — re-dispatches analysis for this PR.
  app.post(
    "/api/v1/pull-requests/:id/rescan",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const pr = await prisma.pullRequest.findFirst({
        where: { id, repository: { organizationId: req.principal.organizationId } },
        select: { id: true, repository: { select: { organizationId: true } } },
      });
      if (!pr) return reply.code(404).send({ error: "not_found" });

      await jobs.dispatchPrAnalysis({ pullRequestId: pr.id, reason: "manual_rescan" });
      await recordAudit({
        organizationId: pr.repository.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "pr.rescan_requested",
        resourceType: "pull_request",
        resourceId: pr.id,
      });
      return reply.code(202).send({ status: "queued" });
    },
  );
}
