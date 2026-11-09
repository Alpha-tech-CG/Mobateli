import type {
  Decision,
  EngineId,
  DependencyRisk,
  FindingType,
  PullRequestStatus,
  Severity,
} from "@codegate/shared";

/**
 * Confidence that a finding is a true positive. Professional audits never
 * present a heuristic match with the same weight as a confirmed one: `high`
 * is a confirmed/near-certain issue, `medium` is likely, `low` is a signal to
 * review. It feeds both the PR comment and the risk score.
 */
export type Confidence = "high" | "medium" | "low";

/** A code/config finding (SAST, auth, config…). */
export interface FindingResult {
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  filePath?: string;
  line?: number;
  ruleId?: string;
  remediation?: string;
  /** CWE identifier, e.g. "CWE-89" (SQL injection). */
  cwe?: string;
  /** OWASP Top 10 category, e.g. "A03:2021-Injection". */
  owasp?: string;
  confidence?: Confidence;
  /** Identity of the alert for human verdicts (see fingerprint.ts). */
  fingerprint?: string;
}

/** A detected secret, with its value masked. */
export interface SecretResult {
  secretType: string;
  location: string;
  maskedPreview: string;
  severity: Severity;
  confidence?: Confidence;
}

/** A known vulnerability affecting a dependency (OSV / advisory databases). */
export interface DependencyVulnerability {
  /** OSV / CVE / GHSA identifier. */
  id: string;
  /** Highest CVSS severity label we could derive. */
  severity: DependencyRisk;
  summary: string;
  /** First version that is no longer affected, when known. */
  fixedVersion?: string;
}

/** A dependency added/changed in the PR, with its trust evaluation. */
export interface DependencyResult {
  ecosystem: string;
  name: string;
  version: string;
  /** Version actually installed, from a lockfile (`version` is the declared range). */
  resolvedVersion?: string;
  trustScore: number; // 0..100 (higher = more trustworthy)
  riskLevel: DependencyRisk;
  reason?: string;
  /** Known vulnerabilities, populated by the OSV / SCA enrichment passes. */
  vulnerabilities?: DependencyVulnerability[];
  /**
   * SPDX license identifier (e.g. "MIT", "GPL-3.0"), populated by the SCA
   * (Trivy/Grype) full-tree scan. Restrictive licenses raise the risk level.
   */
  license?: string;
}

/**
 * What happened to one external analysis pass. Every pass fails open, so
 * without this a pass that never ran is indistinguishable from "found
 * nothing" — the result would look clean while nothing was checked.
 */
export interface EngineReport {
  status: "ok" | "skipped" | "failed";
  /** Why it was skipped or failed (e.g. "binaire absent", "délai dépassé"). */
  detail?: string;
}

/** Status setter handed to a pass; last call wins. */
export type EngineStatusFn = (status: EngineReport["status"], detail?: string) => void;

/** Engine ids — see ENGINE_IDS in @codegate/shared and engines/registry.ts. */
export type EngineName = EngineId;

/** Aggregate output of the analysis pipeline. */
export interface AnalysisResult {
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
  riskScore: number; // 0..100 (higher = riskier)
  decision: Decision;
  status: PullRequestStatus;
  /** Per-pass outcome; set by the full pipeline (not the offline core). */
  engines?: Partial<Record<EngineName, EngineReport>>;
}

/** Short French reason for a subprocess failure (spawn/timeout/argv…). */
export function describeFailure(err: unknown): string {
  const e = err as { code?: string; killed?: boolean; signal?: string; message?: string };
  if (e?.code === "ENOENT") return "binaire absent";
  if (e?.killed || e?.signal === "SIGTERM" || e?.signal === "SIGKILL" || e?.code === "ETIMEDOUT") {
    return "délai dépassé";
  }
  if (e?.code === "E2BIG" || e?.code === "ENAMETOOLONG") return "ligne de commande trop longue";
  if (err instanceof SyntaxError) return "sortie illisible";
  const msg = (e?.message ?? String(err)).split("\n")[0]!;
  return msg.slice(0, 80) || "erreur inconnue";
}
