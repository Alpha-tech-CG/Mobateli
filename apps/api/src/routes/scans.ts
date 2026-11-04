import type { FastifyInstance } from "fastify";
import { waitUntil } from "@vercel/functions";
import { prisma } from "@codegate/db";
import { updateRepositorySchema } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { createScan, runScan } from "../lib/repo-scan.js";

const SCAN_ROLES = ["owner", "admin", "security_manager", "developer"] as const;

/** Start a scan in the background (kept alive on Vercel by waitUntil). */
export function launchScan(config: AppConfig, scanId: string, log: FastifyInstance["log"]): void {
  waitUntil(runScan(config, scanId).catch((err: unknown) => log.error({ err, scanId }, "repository scan crashed")));
}

/**
 * Analysis of existing code: the user picks a connected repository and
 * launches a scan of its default branch; progress is polled live.
 */
export async function scanRoutes(app: FastifyInstance, config: AppConfig) {
  app.post(
    "/api/v1/repositories/:id/scans",
    { preHandler: [app.authenticate, app.requireRole(...SCAN_ROLES)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const repo = await prisma.repository.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true, name: true, provider: true, installationId: true },
      });
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });
      if (repo.provider === "github" && repo.installationId == null) {
        return reply.code(409).send({ error: "github_not_installed" });
      }
      const scan = await createScan({
        repositoryId: repo.id,
        organizationId: req.principal.organizationId,
        trigger: "manual",
        requestedById: req.principal.userId,
      });
      if (!scan.reused) {
        await recordAudit({
          organizationId: req.principal.organizationId,
          actorType: "user",
          actorId: req.principal.userId,
          action: "repository.scan_requested",
          resourceType: "repository",
          resourceId: repo.id,
          metadata: { scanId: scan.id },
        });
        launchScan(config, scan.id, app.log);
      }
      return reply.code(202).send({ scanId: scan.id, reused: scan.reused });
    },
  );

  app.get("/api/v1/scans", { preHandler: [app.authenticate] }, async (req) => {
    const { repositoryId } = req.query as { repositoryId?: string };
    const scans = await prisma.repositoryScan.findMany({
      where: {
        organizationId: req.principal.organizationId,
        ...(repositoryId ? { repositoryId } : {}),
      },
      orderBy: { createdAt: "desc" },
      take: 50,
      select: {
        id: true,
        trigger: true,
        status: true,
        phase: true,
        ref: true,
        commitSha: true,
        filesScanned: true,
        riskScore: true,
        decision: true,
        summary: true,
        error: true,
        createdAt: true,
        finishedAt: true,
        repository: { select: { id: true, name: true, provider: true } },
      },
    });
    return { scans };
  });

  app.get("/api/v1/scans/:id", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const scan = await prisma.repositoryScan.findFirst({
      where: { id, organizationId: req.principal.organizationId },
      include: { repository: { select: { id: true, name: true, provider: true } } },
    });
    if (!scan) return reply.code(404).send({ error: "not_found" });
    return { scan };
  });

  // Automatic re-scan of the default branch when it changes (daily cron).
  app.patch(
    "/api/v1/repositories/:id",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = updateRepositorySchema.parse(req.body);
      const res = await prisma.repository.updateMany({
        where: { id, organizationId: req.principal.organizationId },
        data: body,
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      return { id, ...body };
    },
  );
}
