import type { PolicyAction, ProtectionLevel, Severity } from "@codegate/shared";
import type { AnalysisResult } from "./types.js";

/**
 * Policy Engine (cahier §5.5, §4). Turns an analysis result into an
 * enforcement outcome, given the repository's protection level and any
 * configured policies. Separates the *verdict* (what the analysis found) from
 * *enforcement* (whether the GitHub check fails) — observe mode reports
 * without ever blocking.
 */

export type CheckConclusion = "success" | "failure" | "neutral" | "action_required";

export interface PolicyRule {
  action: PolicyAction;
  severityThreshold: Severity;
}

export interface Enforcement {
  conclusion: CheckConclusion;
  blocked: boolean;
  title: string;
}

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Highest severity present across all finding kinds. */
function worstSeverity(result: AnalysisResult): Severity {
  let worst: Severity = "info";
  const consider = (s: Severity) => {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
  };
  for (const f of result.findings) consider(f.severity);
  for (const s of result.secrets) consider(s.severity);
  for (const d of result.dependencies) {
    if (d.riskLevel === "critical") consider("critical");
    else if (d.riskLevel === "high") consider("high");
    else if (d.riskLevel === "medium") consider("medium");
  }
  return worst;
}

export function resolveEnforcement(
  result: AnalysisResult,
  protectionLevel: ProtectionLevel,
  policies: PolicyRule[],
): Enforcement {
  const worst = worstSeverity(result);
  // Informational notes (test fixtures, review reminders) are not findings.
  const hasFindings =
    result.findings.some((f) => f.severity !== "info") ||
    result.secrets.length > 0 ||
    result.dependencies.some((d) => d.riskLevel !== "low");

  // A policy demands blocking when its action is block/require_approval and the
  // worst severity meets its threshold.
  const policyBlocks = policies.some(
    (p) =>
      (p.action === "block" || p.action === "require_approval") &&
      SEVERITY_RANK[worst] >= SEVERITY_RANK[p.severityThreshold],
  );

  const wantsBlock = result.decision === "block" || policyBlocks;

  // Observe mode never fails the check — it only reports.
  if (protectionLevel === "observe") {
    return {
      conclusion: hasFindings ? "neutral" : "success",
      blocked: false,
      title: hasFindings
        ? `Observation : ${result.riskScore}/100 (non bloquant)`
        : "Aucun risque détecté",
    };
  }

  if (protectionLevel === "block" && wantsBlock) {
    return {
      conclusion: "failure",
      blocked: true,
      title: `Bloqué : risque ${result.riskScore}/100`,
    };
  }

  // warn mode, or block mode without a blocking verdict.
  if (wantsBlock || result.decision === "fix") {
    return {
      conclusion: "neutral",
      blocked: false,
      title: `Avertissement : risque ${result.riskScore}/100`,
    };
  }

  return { conclusion: "success", blocked: false, title: "Aucun risque détecté" };
}
