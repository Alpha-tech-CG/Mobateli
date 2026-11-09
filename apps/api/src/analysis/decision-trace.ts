import { dependencyAssurance, findingAssurance, secretAssurance } from "./assurance.js";
import type { AnalysisResult } from "./types.js";

/**
 * Why a PR was blocked or warned, in a form the audit trail keeps: every
 * alert that decided (rule, place, proof level, fingerprint). Uncertain and
 * informational alerts never decide, so they are not listed. Secret values
 * never appear — only their type, place and masked preview.
 */
export interface DecisionEntry {
  kind: "finding" | "secret" | "dependency";
  rule: string;
  severity: string;
  assurance: string;
  location?: string;
  fingerprint?: string;
}

export function decisionTrace(result: Pick<AnalysisResult, "findings" | "secrets" | "dependencies" | "decision">): DecisionEntry[] {
  if (result.decision === "allow") return [];
  const blocking = result.decision === "block";
  const decides = (level: string, severity: string) =>
    blocking ? level === "verified" && (severity === "critical" || severity === "high") : level === "verified" || level === "likely";
  const out: DecisionEntry[] = [];
  for (const f of result.findings) {
    const level = findingAssurance(f);
    if (!decides(level, f.severity)) continue;
    out.push({
      kind: "finding",
      rule: f.ruleId ?? f.title,
      severity: f.severity,
      assurance: level,
      ...(f.filePath ? { location: `${f.filePath}${f.line ? `:${f.line}` : ""}` } : {}),
      ...(f.fingerprint ? { fingerprint: f.fingerprint } : {}),
    });
  }
  for (const s of result.secrets) {
    const level = secretAssurance(s);
    if (!(blocking ? level === "verified" : level !== "uncertain")) continue;
    out.push({ kind: "secret", rule: s.secretType, severity: s.severity, assurance: level, location: s.location });
  }
  for (const d of result.dependencies) {
    const level = dependencyAssurance(d);
    if (!(blocking ? level === "verified" : level === "verified" || level === "likely")) continue;
    out.push({ kind: "dependency", rule: `${d.name}@${d.version}`, severity: d.riskLevel, assurance: level });
  }
  return out.slice(0, 50);
}
