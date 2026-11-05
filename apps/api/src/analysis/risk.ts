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

/** Low-confidence signals alone warn only once they add up to this score. */
const LOW_SIGNAL_THRESHOLD = 20;

export interface DecisionInput {
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
}

/**
 * Risk Decision Engine (cahier §1, §4). Deterministic scoring → decision.
 * A secret, a critical finding/dependency or a confirmed high-severity
 * finding always blocks.
 */
export function decide(input: DecisionInput): Pick<
  AnalysisResult,
  "riskScore" | "decision" | "status"
> {
  // A low-confidence signal is reported "to review" but never decides on its
  // own: only firm (medium/high) findings set the verdict, unless many weak
  // signals add up (LOW_SIGNAL_THRESHOLD). Otherwise a clean PR would be
  // warned for a checksum MD5 or an eval the taint engine cleared.
  const firm = (c: FindingResult["confidence"] | SecretResult["confidence"]) => c !== "low";
  const firmFindings = input.findings.filter((f) => firm(f.confidence));

  let score = 0;
  let firmScore = 0;
  for (const f of input.findings) {
    const w = SEVERITY_WEIGHT[f.severity] * confidenceFactor(f.confidence);
    score += w;
    if (firm(f.confidence)) firmScore += w;
  }
  for (const s of input.secrets) {
    const w = (SECRET_WEIGHT + SEVERITY_WEIGHT[s.severity]) * confidenceFactor(s.confidence);
    score += w;
    if (firm(s.confidence)) firmScore += w;
  }
  for (const d of input.dependencies) {
    score += DEP_RISK_WEIGHT[d.riskLevel];
    firmScore += DEP_RISK_WEIGHT[d.riskLevel];
  }
  score = Math.round(Math.min(100, score));

  // A low-confidence secret (e.g. a provider-shaped value in a sample file) is
  // reported and scored, but only a confirmed secret forces a block.
  const hasSecret = input.secrets.some((s) => s.confidence !== "low");
  const hasCritical =
    input.findings.some((f) => f.severity === "critical") ||
    input.dependencies.some((d) => d.riskLevel === "critical");
  // A high-severity issue that is CONFIRMED — a near-certain match (high
  // confidence) or a source→sink path proven by the taint engine — blocks:
  // a proven SQL/command/code injection must not merely warn. An unconfirmed
  // regex hit of the same severity still only warns.
  const hasConfirmedHigh = firmFindings.some(
    (f) => f.severity === "high" && (f.confidence === "high" || (f.ruleId ?? "").startsWith("RUST-")),
  );
  const hasHigh =
    firmFindings.some((f) => f.severity === "high") ||
    input.dependencies.some((d) => d.riskLevel === "high");
  const hasMedium =
    firmFindings.some((f) => f.severity === "medium") ||
    input.dependencies.some((d) => d.riskLevel === "medium");

  let decision: Decision;
  let status: PullRequestStatus;

  if (hasSecret || hasCritical || hasConfirmedHigh || score >= 70) {
    decision = "block";
    status = "blocked";
  } else if (hasHigh || score >= 40) {
    decision = "fix";
    status = "warning";
  } else if (hasMedium || firmScore > 0 || score >= LOW_SIGNAL_THRESHOLD) {
    decision = "fix";
    status = "warning";
  } else {
    decision = "allow";
    status = "passed";
  }

  return { riskScore: score, decision, status };
}
