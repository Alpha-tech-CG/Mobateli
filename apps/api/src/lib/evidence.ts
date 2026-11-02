import PDFDocument from "pdfkit";
import { prisma, type Prisma } from "@codegate/db";
import type { Severity } from "@codegate/shared";

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

  const [org, prs, secretsBlocked, depsRefused, remediationIssues, audits, policies, findingGroups] =
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
        where: { pullRequest: prWhere },
        _count: { _all: true },
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

/** Formatted PDF evidence report. */
export function evidenceToPdf(pack: EvidencePack): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.fontSize(20).text("CodeGate — Dossier de preuves de sécurité", { align: "left" });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor("#555")
      .text(`Organisation : ${pack.organization.name}`)
      .text(`Généré le : ${pack.generatedAt}`);
    const period =
      pack.filters.from || pack.filters.to
        ? `${pack.filters.from ?? "origine"} → ${pack.filters.to ?? "maintenant"}`
        : "toute la période";
    doc.text(`Période : ${period}`);
    doc.fillColor("#000").moveDown();

    doc.fontSize(14).text("Synthèse");
    doc.moveDown(0.3);
    doc.fontSize(10);
    doc.text(`Pull requests analysées : ${pack.summary.pullRequests}`);
    doc.text(`Statuts : ${JSON.stringify(pack.summary.byStatus)}`);
    doc.text(`Findings par sévérité : ${JSON.stringify(pack.summary.findingsBySeverity)}`);
    doc.text(`Secrets bloqués : ${pack.summary.secretsBlocked}`);
    doc.text(`Dépendances refusées (high/critical) : ${pack.summary.dependenciesRefused}`);
    doc.text(`Issues de remédiation : ${pack.summary.remediationIssues}`);
    doc.text(`Événements d'audit : ${pack.summary.auditEvents}`);
    doc.moveDown();

    doc.fontSize(14).text("Décisions par pull request");
    doc.moveDown(0.3);
    doc.fontSize(9);
    for (const pr of pack.pullRequests.slice(0, 50)) {
      doc.text(
        `${pr.repository} #${pr.number} — ${pr.status} (risque ${pr.riskScore ?? "—"}/100)` +
          `${pr.aiGenerated ? " [IA]" : ""} — ${pr.title}`,
      );
    }
    doc.moveDown();

    doc.fontSize(14).text("Journal d'audit (extrait)");
    doc.moveDown(0.3);
    doc.fontSize(8);
    for (const e of pack.auditEvents.slice(0, 80)) {
      doc.text(`${e.createdAt} · ${e.actorType} · ${e.action} · ${e.resourceType}`);
    }

    doc.end();
  });
}
