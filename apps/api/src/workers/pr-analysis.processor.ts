import { prisma, withDbRetry } from "@codegate/db";
import { recordAudit } from "../lib/audit.js";
import { fetchDefaultBranchFile, fetchPrDiff } from "../lib/github-diff.js";
import { judgementFor } from "../lib/exceptions.js";
import { dependencyRow, findingRow } from "../lib/finding-rows.js";
import { decisionTrace } from "../analysis/decision-trace.js";
import { IGNORE_FILE, parseIgnoreFile } from "../analysis/ignore.js";
import { resolveAnalysisSettings } from "@codegate/shared";
import { runAnalysis } from "../analysis/engines/pipeline.js";
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
import { fetchMrDiff, gitlabForOrg, setCommitStatus, upsertMrNote } from "../lib/gitlab.js";
import type { PrAnalysisJob } from "../queues/pr-analysis.js";
import type { AppConfig } from "../config.js";

/**
 * Analyse one pull request: fetch the PR diff, run the deterministic analysis
 * pipeline (secrets, dependencies, SAST), persist findings, then apply the
 * decision (Slack, remediation issues, GitHub check + comment) — cahier §5,
 * §6.2. Shared by the BullMQ worker and the inline (serverless) mode.
 */
export async function processPrAnalysis(
  config: AppConfig,
  data: PrAnalysisJob,
  /** False while BullMQ will retry (queue mode); inline mode has no retry. */
  attempt: { last: boolean } = { last: true },
): Promise<void> {
  const { pullRequestId } = data;

  const pr = await prisma.pullRequest.findUnique({
    where: { id: pullRequestId },
    include: { repository: { include: { organization: { select: { analysisSettings: true } } } } },
  });
  if (!pr) return; // PR deleted between enqueue and processing.

  await prisma.pullRequest.update({
    where: { id: pr.id },
    data: { status: "analyzing" },
  });

  // Fetch the diff from the SCM (GitHub App, or GitLab API token).
  const gitlab =
    pr.repository.provider === "gitlab"
      ? await gitlabForOrg(pr.repository.organizationId, config.ENCRYPTION_KEY)
      : null;
  if (!gitlab && pr.repository.installationId == null) {
    // No way to read this PR's code (GitLab not connected, GitHub repo without
    // an App installation). Analyzing an empty diff would show it "passed" —
    // say instead that nothing was checked and a human must review it.
    await prisma.pullRequest.update({
      where: { id: pr.id },
      data: { status: "escalated", riskScore: null },
    });
    await recordAudit({
      organizationId: pr.repository.organizationId,
      actorType: "system",
      action: "pr.analysis_unavailable",
      resourceType: "pull_request",
      resourceId: pr.id,
      metadata: { reason: "no_diff_source", provider: pr.repository.provider },
    });
    return;
  }

  let diff: string | null = null;
  try {
    diff = gitlab
      ? await fetchMrDiff(gitlab, pr.repository.externalId, pr.number)
      : await fetchPrDiff(
          config,
          Number(pr.repository.installationId),
          pr.repository.name,
          pr.number,
        );
  } catch {
    diff = null;
  }
  if (diff == null) {
    // Fail closed: an unreadable diff must never become a green check. While
    // retries remain, give it back to the queue; then flag it for a human.
    await prisma.pullRequest.update({
      where: { id: pr.id },
      data: { status: attempt.last ? "escalated" : "pending" },
    });
    if (attempt.last) {
      await recordAudit({
        organizationId: pr.repository.organizationId,
        actorType: "system",
        action: "pr.analysis_failed",
        resourceType: "pull_request",
        resourceId: pr.id,
        metadata: { reason: "diff_unavailable" },
      });
    }
    throw new Error("diff_unavailable");
  }

  // The team's verdicts on this repository (false positive / confirmed),
  // keyed by alert fingerprint: they survive a re-analysis.
  // A verdict lapses at its expiry date: the alert then comes back.
  const now = new Date();
  const verdicts = await prisma.findingFeedback.findMany({
    where: { repositoryId: pr.repository.id, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
    select: { fingerprint: true, verdict: true },
  });
  const verdictOf = new Map(verdicts.map((v) => [v.fingerprint, v.verdict]));
  // False positives and accepted risks are kept for the record, not scored.
  const dismissed = new Set(verdicts.filter((v) => v.verdict !== "confirmed").map((v) => v.fingerprint));
  // Approved exceptions and rules in observation (noisy or set by a reviewer).
  const judge = await judgementFor(pr.repository.organizationId, pr.repository.id, pr.baseBranch, now);
  // .codegateignore is read from the default branch, never from the PR head:
  // a PR must not be able to exempt itself (see ignore.ts).
  let ignoreFile: string | null = null;
  if (!gitlab) {
    try {
      ignoreFile = await fetchDefaultBranchFile(
        config,
        Number(pr.repository.installationId),
        pr.repository.name,
        IGNORE_FILE,
      );
    } catch {
      ignoreFile = null;
    }
  }
  // The analysis pipeline (docs/ARCHITECTURE-ANALYSE.md): every engine with
  // its status, the organization/repository parameters, the human
  // false-positive verdicts. Binary engines (Semgrep, Trivy, native taint
  // engine) only run with a worker — reported as skipped in serverless mode.
  const result = await runAnalysis(diff, {
    settings: resolveAnalysisSettings(
      pr.repository.organization.analysisSettings,
      pr.repository.analysisSettings,
    ),
    suppressed: dismissed,
    judge,
    ...(ignoreFile ? { isIgnored: parseIgnoreFile(ignoreFile) } : {}),
    runtime: { worker: config.ANALYSIS_MODE === "queue" },
  });

  // Replace previous findings for this PR (idempotent re-analysis), then
  // persist the new set and the decision — atomically, with retry on a
  // transient connection drop.
  await withDbRetry(() =>
    prisma.$transaction([
      prisma.finding.deleteMany({ where: { pullRequestId: pr.id } }),
      prisma.dependency.deleteMany({ where: { pullRequestId: pr.id } }),
      prisma.secretFinding.deleteMany({ where: { pullRequestId: pr.id } }),
      prisma.finding.createMany({
        data: [
          ...result.findings.map((f) =>
            findingRow(pr.id, f, verdictOf.get(f.fingerprint ?? "") === "confirmed" ? "acknowledged" : "open"),
          ),
          // Team verdicts (false positive, accepted risk) and approved
          // exceptions: kept for the record and the metrics, not scored.
          ...result.suppressed.map((f) =>
            findingRow(pr.id, f, verdictOf.get(f.fingerprint ?? "") === "accepted_risk" ? "accepted_risk" : "false_positive"),
          ),
          ...result.excepted.map((f) => findingRow(pr.id, f, "suppressed")),
        ],
      }),
      prisma.dependency.createMany({
        data: [...result.dependencies, ...result.exceptedDependencies].map((d) => dependencyRow(pr.id, d)),
      }),
      prisma.secretFinding.createMany({
        data: result.secrets.map((s) => ({
          pullRequestId: pr.id,
          secretType: s.secretType,
          location: s.location,
          maskedPreview: s.maskedPreview,
          severity: s.severity,
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
      engine: result.engine,
      // Traceability of a block: which proven alert decided it (rule, place,
      // proof level, fingerprint). The policy applied is recorded with the
      // GitHub/GitLab feedback (pr.feedback_posted).
      decidedBy: JSON.parse(JSON.stringify(decisionTrace(result))),
      inObservation: result.findings.filter((f) => f.details?.observationReason).length,
      excepted: result.excepted.length + result.exceptedDependencies.length,
      // Which engines ran / were skipped / failed — shown on the PR page.
      engines: JSON.parse(JSON.stringify(result.engines ?? {})),
      counts: {
        findings: result.findings.length,
        secrets: result.secrets.length,
        dependencies: result.dependencies.length,
      },
      reason: data.reason,
    },
  });

  // §10.5: log every detected prompt injection attempt.
  const injections = result.findings.filter((f) => f.type === "prompt_injection");
  if (injections.length) {
    await recordAudit({
      organizationId: pr.repository.organizationId,
      actorType: "system",
      action: "security.prompt_injection_detected",
      resourceType: "pull_request",
      resourceId: pr.id,
      metadata: {
        rules: [...new Set(injections.map((f) => f.ruleId ?? "unknown"))],
        files: [...new Set(injections.map((f) => f.filePath ?? ""))].slice(0, 20),
      },
    });
  }

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

  // ── Feedback SCM (GitHub check run / GitLab commit status + commentaire) ──
  if (pr.headSha == null) return;
  if (!gitlab && pr.repository.installationId == null) return;

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
  const comment = buildPrComment(result, { suppressed: result.suppressed.length });
  const installationId = Number(pr.repository.installationId);

  try {
    if (gitlab) {
      const state = enforcement.conclusion === "success" || enforcement.conclusion === "neutral" ? "success" : "failed";
      await setCommitStatus(gitlab, pr.repository.externalId, pr.headSha, state, enforcement.title);
      await upsertMrNote(gitlab, pr.repository.externalId, pr.number, comment);
    } else {
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
    }
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
    throw err; // let the caller (BullMQ) retry the posting
  }
}
