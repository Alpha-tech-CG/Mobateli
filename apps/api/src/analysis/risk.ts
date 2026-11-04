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

/**
 * Confidence scales a finding's contribution to the score — a low-confidence
 * heuristic should not inflate the risk like a confirmed issue (cahier §13.1,
 * taux de faux positifs < 15 %). Absent confidence is treated as full weight
 * for backward compatibility.
 */
const CONFIDENCE_FACTOR = { high: 1, medium: 0.8, low: 0.5 } as const;
function confidenceFactor(c: FindingResult["confidence"] | SecretResult["confidence"]): number {
  return c ? CONFIDENCE_FACTOR[c] : 1;
}

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
  // Repeats of the same rule are one weakness to fix, not N independent risks:
  // the first hit counts in full, each repeat a quarter, capped at 2× a single
  // hit. Linear summing pushed whole codebases to 100 on hygiene warnings
  // (e.g. 8 unpinned GitHub Actions = 64 points).
  const perRule = new Map<string, { weight: number; repeats: number }>();
  for (const f of input.findings) {
    const w = SEVERITY_WEIGHT[f.severity] * confidenceFactor(f.confidence);
    const key = `${f.ruleId ?? f.title}:${f.severity}`;
    const seen = perRule.get(key);
    if (!seen) perRule.set(key, { weight: w, repeats: 0 });
    else seen.repeats++;
  }
  for (const { weight, repeats } of perRule.values()) {
    score += Math.min(weight * (1 + 0.25 * repeats), weight * 2);
  }
  for (const s of input.secrets) score += (SECRET_WEIGHT + SEVERITY_WEIGHT[s.severity]) * confidenceFactor(s.confidence);
  for (const d of input.dependencies) score += DEP_RISK_WEIGHT[d.riskLevel];
  score = Math.round(Math.min(100, score));

  // A low-confidence secret (e.g. a provider-shaped value in a sample file) is
  // reported and scored, but only a confirmed secret forces a block.
  const hasSecret = input.secrets.some((s) => s.confidence !== "low");
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
