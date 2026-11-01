import type {
  Decision,
  DependencyRisk,
  FindingType,
  PullRequestStatus,
  Severity,
} from "@codegate/shared";

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
}

/** A detected secret, with its value masked. */
export interface SecretResult {
  secretType: string;
  location: string;
  maskedPreview: string;
  severity: Severity;
}

/** A dependency added/changed in the PR, with its trust evaluation. */
export interface DependencyResult {
  ecosystem: string;
  name: string;
  version: string;
  trustScore: number; // 0..100 (higher = more trustworthy)
  riskLevel: DependencyRisk;
  reason?: string;
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
