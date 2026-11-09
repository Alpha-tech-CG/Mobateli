import type { Prisma } from "@codegate/db";
import type { Confidence, DependencyResult, FindingResult } from "../analysis/types.js";

/**
 * One shape for a stored finding, both ways: what the analysis produced
 * (confidence, assurance, proof) must survive storage — a PR rescored after
 * a human verdict is judged on the same evidence as at analysis time.
 */

type Status = "open" | "acknowledged" | "resolved" | "false_positive" | "accepted_risk" | "suppressed";

export function findingRow(
  pullRequestId: string,
  f: FindingResult & { exceptionId?: string },
  status: Status,
): Prisma.FindingCreateManyInput {
  const details = {
    ...(f.cwe ? { cwe: f.cwe } : {}),
    ...(f.owasp ? { owasp: f.owasp } : {}),
    ...(f.details ?? {}),
  };
  return {
    pullRequestId,
    type: f.type,
    severity: f.severity,
    title: f.title,
    description: f.description,
    filePath: f.filePath ?? null,
    line: f.line ?? null,
    ruleId: f.ruleId ?? null,
    remediation: f.remediation ?? null,
    status,
    fingerprint: f.fingerprint ?? null,
    confidence: f.confidence ?? null,
    assurance: f.assurance ?? null,
    details: Object.keys(details).length ? (details as Prisma.InputJsonValue) : undefined,
    exceptionId: f.exceptionId ?? null,
  } as Prisma.FindingCreateManyInput;
}

interface StoredFinding {
  type: FindingResult["type"];
  severity: FindingResult["severity"];
  title: string;
  description: string;
  filePath: string | null;
  line: number | null;
  ruleId: string | null;
  confidence: string | null;
  assurance: string | null;
}

/** A stored finding back as an analysis result, for rescoring. */
export function storedFinding(r: StoredFinding): FindingResult {
  const confidence = r.confidence === "high" || r.confidence === "medium" || r.confidence === "low" ? (r.confidence as Confidence) : undefined;
  const assurance =
    r.assurance === "verified" || r.assurance === "likely" || r.assurance === "uncertain" || r.assurance === "information"
      ? r.assurance
      : undefined;
  return {
    type: r.type,
    severity: r.severity,
    title: r.title,
    description: r.description,
    ...(r.filePath ? { filePath: r.filePath } : {}),
    ...(r.line !== null ? { line: r.line } : {}),
    ...(r.ruleId ? { ruleId: r.ruleId } : {}),
    ...(confidence ? { confidence } : {}),
    ...(assurance ? { assurance } : {}),
  };
}

export function dependencyRow(
  pullRequestId: string,
  d: DependencyResult & { exceptionId?: string },
): Prisma.DependencyCreateManyInput {
  return {
    pullRequestId,
    ecosystem: d.ecosystem,
    name: d.name,
    version: d.version,
    trustScore: d.trustScore,
    riskLevel: d.riskLevel,
    reason: d.reason ?? null,
    exceptionId: d.exceptionId ?? null,
  };
}
