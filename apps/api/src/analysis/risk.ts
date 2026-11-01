import type { Decision, PullRequestStatus, Severity } from "@codegate/shared";
import type { AnalysisResult, DependencyResult, FindingResult, SecretResult } from "./types.js";

/** Risk weight per severity — tuned so a single critical dominates. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

const SECRET_WEIGHT = 45;
const DEP_RISK_WEIGHT: Record<DependencyResult["riskLevel"], number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 0,
};

export interface DecisionInput {
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
}

/**
 * Risk Decision Engine (cahier §1, §4). Deterministic scoring → decision.
 * A secret or a critical finding/dependency always blocks.
 */
export function decide(input: DecisionInput): Pick<
  AnalysisResult,
  "riskScore" | "decision" | "status"
> {
  let score = 0;
  for (const f of input.findings) score += SEVERITY_WEIGHT[f.severity];
  for (const s of input.secrets) score += SECRET_WEIGHT + SEVERITY_WEIGHT[s.severity];
  for (const d of input.dependencies) score += DEP_RISK_WEIGHT[d.riskLevel];
  score = Math.min(100, score);

  const hasSecret = input.secrets.length > 0;
  const hasCritical =
    input.findings.some((f) => f.severity === "critical") ||
    input.dependencies.some((d) => d.riskLevel === "critical");
  const hasHigh =
    input.findings.some((f) => f.severity === "high") ||
    input.dependencies.some((d) => d.riskLevel === "high");
  const hasMedium =
    input.findings.some((f) => f.severity === "medium") ||
    input.dependencies.some((d) => d.riskLevel === "medium");

  let decision: Decision;
  let status: PullRequestStatus;

  if (hasSecret || hasCritical || score >= 70) {
    decision = "block";
    status = "blocked";
  } else if (hasHigh || score >= 40) {
    decision = "fix";
    status = "warning";
  } else if (hasMedium || score > 0) {
    decision = "fix";
    status = "warning";
  } else {
    decision = "allow";
    status = "passed";
  }

  return { riskScore: score, decision, status };
}
