import { prisma, type Prisma } from "@codegate/db";
import type { Severity } from "@codegate/shared";
import { evaluateBackup } from "../analysis/backup.js";

/**
 * Compliance Evidence Pack (cahier §5.8, US07). Gathers auditable proof of the
 * security control applied to an org's pull requests, then serializes it to
 * JSON, CSV or PDF. No raw secret ever leaves here — secrets are stored masked.
 */

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface EvidenceFilters {
  repositoryId?: string;
  from?: string;
  to?: string;
  severityThreshold?: Severity;
}

export interface EvidencePack {
  organization: { id: string; name: string };
  generatedAt: string;
  filters: EvidenceFilters;
  summary: {
    pullRequests: number;
    byStatus: Record<string, number>;
    findingsBySeverity: Record<string, number>;
    secretsBlocked: number;
    dependenciesRefused: number;
    remediationIssues: number;
    auditEvents: number;
  };
  pullRequests: Array<{
    repository: string;
    number: number;
    title: string;
    author: string;
    aiGenerated: boolean;
    riskScore: number | null;
    status: string;
    counts: { findings: number; secrets: number; dependencies: number };
    createdAt: string;
  }>;
  auditEvents: Array<{
    createdAt: string;
    actorType: string;
    actorId: string | null;
    action: string;
    resourceType: string;
    resourceId: string | null;
    metadata: unknown;
  }>;
  policies: Array<{ rule: string; action: string; severityThreshold: string; scope: string }>;
  /** Extension §10.3: infrastructure, access and backup evidence. */
  infrastructure: Array<{
    server: string;
    environment: string;
    securityScore: number | null;
    lastAuditAt: string | null;
    openFindings: Record<string, number>;
  }>;
  bruteForce: {
    policies: Array<{ endpoint: string; maxAttempts: number; windowSeconds: number; lockoutSeconds: number }>;
    tests: Array<{ target: string; endpoint: string; testType: string; result: string; createdAt: string }>;
  };
  backups: Array<{
    name: string;
    type: string;
    status: string;
    recoveryScore: number;
    ransomwareReady: boolean;
    lastRunAt: string | null;
    lastRestoreTestAt: string | null;
    failedChecks: string[];
  }>;
}

export async function buildEvidencePack(
  organizationId: string,
  filters: EvidenceFilters,
): Promise<EvidencePack> {
  const range: Prisma.DateTimeFilter = {};
  if (filters.from) range.gte = new Date(filters.from);
  if (filters.to) range.lte = new Date(filters.to);
  const createdAt = filters.from || filters.to ? range : undefined;

  const prWhere: Prisma.PullRequestWhereInput = {
    repository: {
      organizationId,
      ...(filters.repositoryId ? { id: filters.repositoryId } : {}),
    },
    ...(createdAt ? { createdAt } : {}),
  };

  const [
    org, prs, secretsBlocked, depsRefused, remediationIssues, audits, policies, findingGroups,
    servers, bfPolicies, bfTests, backupJobs,
  ] =
    await Promise.all([
      prisma.organization.findUniqueOrThrow({
        where: { id: organizationId },
        select: { id: true, name: true },
      }),
      prisma.pullRequest.findMany({
        where: prWhere,
        include: {
          repository: { select: { name: true } },
          _count: { select: { findings: true, secretFindings: true, dependencies: true } },
        },
        orderBy: { createdAt: "desc" },
      }),
      prisma.secretFinding.count({ where: { pullRequest: prWhere } }),
      prisma.dependency.count({
        where: { pullRequest: prWhere, riskLevel: { in: ["high", "critical"] } },
      }),
      prisma.remediationIssue.count({ where: { pullRequest: prWhere } }),
      prisma.auditEvent.findMany({
        where: { organizationId, ...(createdAt ? { createdAt } : {}) },
        orderBy: { createdAt: "desc" },
        take: 1000,
      }),
      prisma.policy.findMany({ where: { organizationId } }),
      prisma.finding.groupBy({
        by: ["severity"],
        where: { pullRequest: prWhere, status: { not: "false_positive" } },
        _count: { _all: true },
      }),
      prisma.server.findMany({
        where: { organizationId },
        select: {
          name: true,
          environment: true,
          securityScore: true,
          lastReportAt: true,
          findings: { select: { severity: true } },
        },
      }),
      prisma.bruteForcePolicy.findMany({ where: { organizationId } }),
      prisma.bruteForceTest.findMany({
        where: { target: { organizationId }, ...(createdAt ? { createdAt } : {}) },
        include: { target: { select: { origin: true } } },
        orderBy: { createdAt: "desc" },
        take: 200,
      }),
      prisma.backupJob.findMany({
        where: { organizationId },
        include: {
          runs: { orderBy: { finishedAt: "desc" }, take: 1 },
          restoreTests: { orderBy: { completedAt: "desc" }, take: 1 },
        },
      }),
    ]);

  const byStatus: Record<string, number> = {};
  for (const pr of prs) byStatus[pr.status] = (byStatus[pr.status] ?? 0) + 1;

  const findingsBySeverity: Record<string, number> = {};
  for (const g of findingGroups) {
    if (
      filters.severityThreshold &&
      SEVERITY_RANK[g.severity] < SEVERITY_RANK[filters.severityThreshold]
    ) {
      continue;
    }
    findingsBySeverity[g.severity] = g._count._all;
  }

  return {
    organization: org,
    generatedAt: new Date().toISOString(),
    filters,
    summary: {
      pullRequests: prs.length,
      byStatus,
      findingsBySeverity,
      secretsBlocked,
      dependenciesRefused: depsRefused,
      remediationIssues,
      auditEvents: audits.length,
    },
    pullRequests: prs.map((pr) => ({
      repository: pr.repository.name,
      number: pr.number,
      title: pr.title,
      author: pr.author,
      aiGenerated: pr.aiGenerated,
      riskScore: pr.riskScore,
      status: pr.status,
      counts: {
        findings: pr._count.findings,
        secrets: pr._count.secretFindings,
        dependencies: pr._count.dependencies,
      },
      createdAt: pr.createdAt.toISOString(),
    })),
    auditEvents: audits.map((a) => ({
      createdAt: a.createdAt.toISOString(),
      actorType: a.actorType,
      actorId: a.actorId,
      action: a.action,
      resourceType: a.resourceType,
      resourceId: a.resourceId,
      metadata: a.metadata,
    })),
    policies: policies.map((p) => ({
      rule: p.rule,
      action: p.action,
      severityThreshold: p.severityThreshold,
      scope: p.repositoryId ? "repository" : "organization",
    })),
    infrastructure: servers.map((sv) => {
      const openFindings: Record<string, number> = {};
      for (const f of sv.findings) openFindings[f.severity] = (openFindings[f.severity] ?? 0) + 1;
      return {
        server: sv.name,
        environment: sv.environment,
        securityScore: sv.securityScore,
        lastAuditAt: sv.lastReportAt?.toISOString() ?? null,
        openFindings,
      };
    }),
    bruteForce: {
      policies: bfPolicies.map((p) => ({
        endpoint: p.endpoint,
        maxAttempts: p.maxAttempts,
        windowSeconds: p.windowSeconds,
        lockoutSeconds: p.lockoutSeconds,
      })),
      tests: bfTests.map((t) => ({
        target: t.target.origin,
        endpoint: t.endpoint,
        testType: t.testType,
        result: t.result,
        createdAt: t.createdAt.toISOString(),
      })),
    },
    backups: backupJobs.map((j) => {
      const e = evaluateBackup(j, j.runs[0] ?? null, j.restoreTests[0] ?? null);
      return {
        name: j.name,
        type: j.type,
        status: e.status,
        recoveryScore: e.score,
        ransomwareReady: e.ransomwareReady,
        lastRunAt: j.runs[0]?.finishedAt.toISOString() ?? null,
        lastRestoreTestAt: j.restoreTests[0]?.completedAt.toISOString() ?? null,
        failedChecks: e.checks.filter((c) => !c.ok).map((c) => c.label),
      };
    }),
  };
}

function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** CSV of the audit trail — the primary machine-readable evidence. */
export function evidenceToCsv(pack: EvidencePack): string {
  const header = ["timestamp", "actor_type", "actor_id", "action", "resource_type", "resource_id", "metadata"];
  const rows = pack.auditEvents.map((e) =>
    [
      e.createdAt,
      e.actorType,
      e.actorId,
      e.action,
      e.resourceType,
      e.resourceId,
      e.metadata ? JSON.stringify(e.metadata) : "",
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}
