import { Worker } from "bullmq";
import type { Redis } from "ioredis";
import { prisma, withDbRetry } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import { fetchPrDiff } from "../lib/github-diff.js";
import { analyzeDiffWithIntel } from "../analysis/analyzer.js";
import { buildPrComment } from "../analysis/explainer.js";
import { resolveEnforcement } from "../analysis/policy.js";
import { createCheckRun, upsertPrComment } from "../lib/github-feedback.js";
import {
  buildRemediationIssue,
  createLinearIssue,
  shouldCreateRemediation,
} from "../lib/linear.js";
import { buildJiraIssue, createJiraIssue } from "../lib/jira.js";
import { decrypt } from "../lib/crypto.js";
import { notifySlack } from "../lib/notify.js";
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

      // Deterministic core + OSV known-vulnerability enrichment (fails open).
      const result = await analyzeDiffWithIntel(diff);

      // Replace previous findings for this PR (idempotent re-analysis), then
      // persist the new set and the decision — atomically, with retry on a
      // transient connection drop.
      await withDbRetry(() =>
        prisma.$transaction([
        prisma.finding.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.dependency.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.secretFinding.deleteMany({ where: { pullRequestId: pr.id } }),
        prisma.finding.createMany({
          data: result.findings.map((f) => {
            // Fold the CWE/OWASP/confidence references into the stored
            // description so the audit trail keeps them without a schema change.
            const refs = [f.cwe, f.owasp, f.confidence ? `confiance: ${f.confidence}` : null]
              .filter(Boolean)
              .join(" · ");
            return {
              pullRequestId: pr.id,
              type: f.type,
              severity: f.severity,
              title: f.title,
              description: refs ? `${f.description} [${refs}]` : f.description,
              filePath: f.filePath ?? null,
              line: f.line ?? null,
              ruleId: f.ruleId ?? null,
              remediation: f.remediation ?? null,
            };
          }),
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
        ]),
      );

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

      // ── Slack : alerte d'incident si la PR est bloquée ou expose un secret ──
      if (result.decision === "block" || result.secrets.length > 0) {
        await notifySlack(pr.repository.organizationId, config.ENCRYPTION_KEY, {
          title: result.secrets.length ? "Secret détecté dans une PR" : "Pull request bloquée",
          severity: "critical",
          repository: pr.repository.name,
          detail: `PR #${pr.number} « ${pr.title} » — risque ${result.riskScore}/100, décision ${result.decision}.`,
        });
      }

      // ── Linear : issue de remédiation (cahier §5.7), idempotente ──
      if (shouldCreateRemediation(result)) {
        const linear = await prisma.linearConnection.findUnique({
          where: { organizationId: pr.repository.organizationId },
        });
        const existing = await prisma.remediationIssue.findUnique({
          where: { pullRequestId_provider: { pullRequestId: pr.id, provider: "linear" } },
        });
        if (linear && !existing) {
          try {
            const apiKey = decrypt(linear.apiKeyEncrypted, config.ENCRYPTION_KEY);
            const issue = buildRemediationIssue({
              repository: pr.repository.name,
              prNumber: pr.number,
              prTitle: pr.title,
              result,
            });
            const ref = await createLinearIssue(apiKey, linear.teamId, issue);
            await prisma.remediationIssue.create({
              data: {
                pullRequestId: pr.id,
                provider: "linear",
                externalId: ref.id,
                identifier: ref.identifier,
                url: ref.url,
              },
            });
            await recordAudit({
              organizationId: pr.repository.organizationId,
              actorType: "system",
              action: "remediation.created",
              resourceType: "pull_request",
              resourceId: pr.id,
              metadata: { provider: "linear", identifier: ref.identifier, url: ref.url },
            });
          } catch (err) {
            await recordAudit({
              organizationId: pr.repository.organizationId,
              actorType: "system",
              action: "remediation.failed",
              resourceType: "pull_request",
              resourceId: pr.id,
              metadata: { provider: "linear", error: err instanceof Error ? err.message : "unknown" },
            });
          }
        }
      }

      // ── Jira : issue de remédiation (cahier §12.2 P3), idempotente ──
      if (shouldCreateRemediation(result)) {
        const jira = await prisma.jiraConnection.findUnique({
          where: { organizationId: pr.repository.organizationId },
        });
        const existing = await prisma.remediationIssue.findUnique({
          where: { pullRequestId_provider: { pullRequestId: pr.id, provider: "jira" } },
        });
        if (jira && !existing) {
          try {
            const issue = buildJiraIssue({
              repository: pr.repository.name,
              prNumber: pr.number,
              prTitle: pr.title,
              result,
            });
            const ref = await createJiraIssue(
              {
                baseUrl: jira.baseUrl,
                email: jira.email,
                apiToken: decrypt(jira.apiTokenEncrypted, config.ENCRYPTION_KEY),
                projectKey: jira.projectKey,
              },
              issue,
            );
            await prisma.remediationIssue.create({
              data: {
                pullRequestId: pr.id,
                provider: "jira",
                externalId: ref.key,
                identifier: ref.key,
                url: ref.url,
              },
            });
            await recordAudit({
              organizationId: pr.repository.organizationId,
              actorType: "system",
              action: "remediation.created",
              resourceType: "pull_request",
              resourceId: pr.id,
              metadata: { provider: "jira", identifier: ref.key, url: ref.url },
            });
          } catch (err) {
            await recordAudit({
              organizationId: pr.repository.organizationId,
              actorType: "system",
              action: "remediation.failed",
              resourceType: "pull_request",
              resourceId: pr.id,
              metadata: { provider: "jira", error: err instanceof Error ? err.message : "unknown" },
            });
          }
        }
      }

      // ── Feedback GitHub (check run + commentaire), selon la politique ──
      if (pr.repository.installationId == null || pr.headSha == null) return;

      const policies = await prisma.policy.findMany({
        where: {
          organizationId: pr.repository.organizationId,
          OR: [{ repositoryId: pr.repository.id }, { repositoryId: null }],
        },
        select: { action: true, severityThreshold: true },
      });

      const enforcement = resolveEnforcement(
        result,
        pr.repository.protectionLevel,
        policies,
      );
      const comment = buildPrComment(result);
      const installationId = Number(pr.repository.installationId);

      try {
        await createCheckRun(config, installationId, pr.repository.name, pr.headSha, {
          conclusion: enforcement.conclusion,
          title: enforcement.title,
          summary: comment,
        });
        await upsertPrComment(
          config,
          installationId,
          pr.repository.name,
          pr.number,
          comment,
        );
        await recordAudit({
          organizationId: pr.repository.organizationId,
          actorType: "system",
          action: "pr.feedback_posted",
          resourceType: "pull_request",
          resourceId: pr.id,
          metadata: {
            conclusion: enforcement.conclusion,
            blocked: enforcement.blocked,
            protectionLevel: pr.repository.protectionLevel,
          },
        });
      } catch (err) {
        // Posting failed (token, rate limit…) — analysis is already saved.
        await recordAudit({
          organizationId: pr.repository.organizationId,
          actorType: "system",
          action: "pr.feedback_failed",
          resourceType: "pull_request",
          resourceId: pr.id,
          metadata: { error: err instanceof Error ? err.message : "unknown" },
        });
        throw err; // let BullMQ retry the posting
      }
    },
    { connection, concurrency: 5 },
  );
}
