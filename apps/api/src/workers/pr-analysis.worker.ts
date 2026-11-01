import { Worker } from "bullmq";
import type { Redis } from "ioredis";
import { prisma } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import { PR_ANALYSIS_QUEUE, type PrAnalysisJob } from "../queues/pr-analysis.js";

/**
 * Consumes pr-analysis jobs. For now this is a skeleton: it marks the PR as
 * analyzing, then passed, and records an audit event. The real pipeline
 * (secret scan, dependency trust, SAST, AI triage, decision engine) plugs in
 * here in étape 3.
 */
export function createPrAnalysisWorker(connection: Redis): Worker<PrAnalysisJob> {
  return new Worker<PrAnalysisJob>(
    PR_ANALYSIS_QUEUE,
    async (job) => {
      const { pullRequestId } = job.data;

      const pr = await prisma.pullRequest.findUnique({
        where: { id: pullRequestId },
        include: { repository: true },
      });
      if (!pr) {
        // PR was deleted between enqueue and processing — nothing to do.
        return;
      }

      await prisma.pullRequest.update({
        where: { id: pr.id },
        data: { status: "analyzing" },
      });

      // TODO(étape 3): run scanners + decision engine. Placeholder result.
      const riskScore = 0;
      const status = "passed" as const;

      await prisma.pullRequest.update({
        where: { id: pr.id },
        data: { riskScore, status },
      });

      await recordAudit({
        organizationId: pr.repository.organizationId,
        actorType: "system",
        action: "pr.analyzed",
        resourceType: "pull_request",
        resourceId: pr.id,
        metadata: { riskScore, status, reason: job.data.reason },
      });
    },
    { connection, concurrency: 5 },
  );
}
