import type { Severity } from "@codegate/shared";
import { dependencyAssurance, findingAssurance, secretAssurance, type Assurance } from "./assurance.js";
import type { AnalysisResult, DependencyResult, FindingResult, SecretResult } from "./types.js";

/** Risk weight per severity — tuned so a single critical dominates. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

export const SECRET_WEIGHT = 45;
export const DEP_RISK_WEIGHT: Record<DependencyResult["riskLevel"], number> = {
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

/** How much a signal weighs in the score, by how well it is proven. */
const ASSURANCE_FACTOR: Record<Assurance, number> = { verified: 1, likely: 0.8, uncertain: 0.5, information: 0 };

/**
 * Risk Decision Engine (cahier §1, §4) — deterministic. The score measures how
 * much risk the change carries; the DECISION follows the assurance rule only,
 * so a pile of unproven signals can never block:
 *
 *  - block    a `verified` critical/high finding (a proven injection, a
 *             near-certain pattern), a `verified` secret, a `verified`
 *             dependency risk (critical CVE, unknown package, several
 *             critical signals together);
 *  - warning  any `verified` or `likely` finding, a `likely` dependency or
 *             secret — a likely high/critical one also asks for a human
 *             review (needsHumanReview);
 *  - passed   `uncertain` alerts stay in observation, `information` is shown
 *             in the dashboard only.
 */
export function decide(input: DecisionInput): Pick<
  AnalysisResult,
  "riskScore" | "decision" | "status"
> {
  const findings = input.findings.map((f) => ({ f, level: findingAssurance(f) }));
  const secrets = input.secrets.map((s) => ({ s, level: secretAssurance(s) }));
  const deps = input.dependencies.map((d) => ({ d, level: dependencyAssurance(d) }));

  let score = 0;
  // Repeats of the same rule are one weakness to fix, not N independent risks:
  // the first hit counts in full, each repeat a quarter, capped at 2× a single
  // hit. Linear summing pushed whole codebases to 100 on hygiene warnings
  // (e.g. 8 unpinned GitHub Actions = 64 points).
  const perRule = new Map<string, { weight: number; repeats: number }>();
  for (const { f, level } of findings) {
    const w = SEVERITY_WEIGHT[f.severity] * ASSURANCE_FACTOR[level];
    const key = `${f.ruleId ?? f.title}:${f.severity}:${level}`;
    const seen = perRule.get(key);
    if (!seen) perRule.set(key, { weight: w, repeats: 0 });
    else seen.repeats++;
  }
  for (const { weight, repeats } of perRule.values()) score += Math.min(weight * (1 + 0.25 * repeats), weight * 2);
  for (const { s, level } of secrets) score += (SECRET_WEIGHT + SEVERITY_WEIGHT[s.severity]) * ASSURANCE_FACTOR[level];
  for (const { d } of deps) score += DEP_RISK_WEIGHT[d.riskLevel];
  score = Math.round(Math.min(100, score));

  const proven = (l: Assurance) => l === "verified";
  const firm = (l: Assurance) => l === "verified" || l === "likely";
  const blocks =
    findings.some(({ f, level }) => proven(level) && (f.severity === "critical" || f.severity === "high")) ||
    secrets.some(({ level }) => proven(level)) ||
    deps.some(({ level }) => proven(level));
  const warns =
    findings.some(({ level }) => firm(level)) ||
    secrets.some(({ level }) => firm(level)) ||
    deps.some(({ level }) => firm(level));

  if (blocks) return { riskScore: score, decision: "block", status: "blocked" };
  if (warns) return { riskScore: score, decision: "fix", status: "warning" };
  return { riskScore: score, decision: "allow", status: "passed" };
}
