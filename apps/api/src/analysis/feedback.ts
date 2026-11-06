import { createHash } from "node:crypto";
import type { ParsedDiff } from "./diff.js";
import { decide } from "./risk.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/**
 * Pilot false-positive tracking (cahier §13.1 — taux de faux positifs).
 *
 * Findings are re-created on every analysis, so a team's verdict ("this alert
 * is wrong" / "this one is real") is attached to a FINGERPRINT that survives a
 * re-analysis: the rule, the file and the normalized content of the flagged
 * line — not its number, which shifts as soon as a line is added above it.
 */

export type FeedbackVerdict = "false_positive" | "confirmed";

/** Stable identity of an alert. */
export function findingFingerprint(f: FindingResult, lineContent: string | undefined): string {
  const content = (lineContent ?? "").trim().replace(/\s+/g, " ");
  return createHash("sha256")
    .update([f.ruleId ?? f.title, f.filePath ?? "", content || `line:${f.line ?? ""}`].join("\u0000"))
    .digest("hex")
    .slice(0, 32);
}

/** Fingerprints for every finding of a result, from the diff's added lines. */
export function fingerprintAll(result: AnalysisResult, diff: ParsedDiff): string[] {
  const content = new Map<string, string>();
  for (const l of diff.addedLines) content.set(`${l.file}:${l.line}`, l.content);
  return result.findings.map((f) => findingFingerprint(f, content.get(`${f.filePath}:${f.line}`)));
}

export interface FeedbackOutcome {
  /** The result once team-dismissed alerts are set aside, verdict recomputed. */
  result: AnalysisResult;
  /** Per finding of the ORIGINAL result: its fingerprint and stored status. */
  statuses: { fingerprint: string; status: "open" | "acknowledged" | "false_positive" }[];
  /** How many alerts the team had marked as false positives. */
  suppressed: number;
}

/**
 * Apply the repository's stored verdicts: a false positive no longer weighs
 * on the decision (it is still persisted, with status false_positive, for the
 * metrics); a confirmed alert is stored as acknowledged.
 */
export function applyFeedback(
  result: AnalysisResult,
  fingerprints: string[],
  verdicts: Map<string, FeedbackVerdict>,
): FeedbackOutcome {
  const statuses = fingerprints.map((fp) => {
    const v = verdicts.get(fp);
    return {
      fingerprint: fp,
      status: v === "false_positive" ? ("false_positive" as const) : v === "confirmed" ? ("acknowledged" as const) : ("open" as const),
    };
  });
  const kept = result.findings.filter((_, i) => statuses[i]!.status !== "false_positive");
  const suppressed = result.findings.length - kept.length;
  if (!suppressed) return { result, statuses, suppressed };
  const verdict = decide({ findings: kept, secrets: result.secrets, dependencies: result.dependencies });
  return { result: { ...result, findings: kept, ...verdict }, statuses, suppressed };
}

export interface RuleQuality {
  ruleId: string;
  alerts: number;
  falsePositives: number;
  confirmed: number;
  /** Share of the alerts the team reviewed that were false (null: none reviewed). */
  falsePositiveRate: number | null;
}

/** Per-rule false-positive rate from finding counts grouped by status. */
export function ruleQuality(
  rows: { ruleId: string | null; status: string; count: number }[],
): RuleQuality[] {
  const byRule = new Map<string, RuleQuality>();
  for (const r of rows) {
    const id = r.ruleId ?? "(sans règle)";
    const q = byRule.get(id) ?? { ruleId: id, alerts: 0, falsePositives: 0, confirmed: 0, falsePositiveRate: null };
    q.alerts += r.count;
    if (r.status === "false_positive") q.falsePositives += r.count;
    if (r.status === "acknowledged") q.confirmed += r.count;
    byRule.set(id, q);
  }
  for (const q of byRule.values()) {
    const reviewed = q.falsePositives + q.confirmed;
    q.falsePositiveRate = reviewed ? q.falsePositives / reviewed : null;
  }
  return [...byRule.values()].sort((a, b) => b.falsePositives - a.falsePositives || b.alerts - a.alerts);
}
