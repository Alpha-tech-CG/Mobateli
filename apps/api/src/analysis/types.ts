import type {
  Decision,
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
  trustScore: number; // 0..100 (higher = more trustworthy)
  riskLevel: DependencyRisk;
  reason?: string;
  /** Known vulnerabilities, populated by the OSV enrichment pass. */
  vulnerabilities?: DependencyVulnerability[];
}

/** Aggregate output of the analysis pipeline. */
export interface AnalysisResult {
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
  riskScore: number; // 0..100 (higher = riskier)
  decision: Decision;
  status: PullRequestStatus;
}
