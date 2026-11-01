import { Worker } from "bullmq";
import type { Redis } from "ioredis";
import { prisma } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import { fetchPrDiff } from "../lib/github-diff.js";
import { analyzeDiff } from "../analysis/analyzer.js";
import { PR_ANALYSIS_QUEUE, type PrAnalysisJob } from "../queues/pr-analysis.js";
import type { AppConfig } from "../config.js";

/**
 * Consumes pr-analysis jobs: fetch the PR diff, run the deterministic analysis
 * pipeline (secrets, dependencies, SAST), persist findings, and apply the
 * decision to the PR (cahier §5, §6.2). Posting the GitHub check/comment is
 * étape 4.
 */
export function createPrAnalysisWorker(
  connection: Redis,
  config: AppConfig,
): Worker<PrAnalysisJob> {
  return new Worker<PrAnalysisJob>(
    PR_ANALYSIS_QUEUE,
    async (job) => {
      const { pullRequestId } = job.data;

      const pr = await prisma.pullRequest.findUnique({
        where: { id: pullRequestId },
        include: { repository: true },
      });
      if (!pr) return; // PR deleted between enqueue and processing.

      await prisma.pullRequest.update({
        where: { id: pr.id },
        data: { status: "analyzing" },
      });

      // Fetch the diff via GitHub when the App is configured; otherwise run on
      // an empty diff (local dev / unconfigured) → clean result.
      let diff = "";
      if (pr.repository.installationId != null) {
        const fetched = await fetchPrDiff(
          config,
          Number(pr.repository.installationId),
          pr.repository.name,
          pr.number,
        );
        if (fetched) diff = fetched;
      }

      const result = analyzeDiff(diff);

      // Replace previous findings for this PR (idempotent re-analysis), then
      // persist the new set and the decision — atomically.
      await prisma.$transaction([
        prisma.finding.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.dependency.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.secretFinding.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.finding.createMany({
          data: result.findings.map((f) => ({
            pullRequestId: pr.id,
            type: f.type,
            severity: f.severity,
            title: f.title,
            description: f.description,
            filePath: f.filePath ?? null,
            line: f.line ?? null,
            ruleId: f.ruleId ?? null,
            remediation: f.remediation ?? null,
          })),
        }),
        prisma.dependency.createMany({
          data: result.dependencies.map((d) => ({
            pullRequestId: pr.id,
            ecosystem: d.ecosystem,
            name: d.name,
            version: d.version,
            trustScore: d.trustScore,
            riskLevel: d.riskLevel,
            reason: d.reason ?? null,
          })),
        }),
        prisma.secretFinding.createMany({
          data: result.secrets.map((s) => ({
            pullRequestId: pr.id,
            secretType: s.secretType,
            location: s.location,
            maskedPreview: s.maskedPreview,
          })),
        }),
        prisma.pullRequest.update({
          where: { id: pr.id },
          data: { riskScore: result.riskScore, status: result.status },
        }),
      ]);

      await recordAudit({
        organizationId: pr.repository.organizationId,
        actorType: "system",
        action: "pr.analyzed",
        resourceType: "pull_request",
        resourceId: pr.id,
        metadata: {
          riskScore: result.riskScore,
          decision: result.decision,
          status: result.status,
          counts: {
            findings: result.findings.length,
            secrets: result.secrets.length,
            dependencies: result.dependencies.length,
          },
          reason: job.data.reason,
        },
      });
    },
    { connection, concurrency: 5 },
  );
}
