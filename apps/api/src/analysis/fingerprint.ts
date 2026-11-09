import { createHash } from "node:crypto";
import type { ParsedDiff } from "./diff.js";
import type { FindingResult } from "./types.js";

/**
 * Stable identity of an alert across analyses, the key of a human verdict
 * (false positive / confirmed): the rule, the file and the normalized content
 * of the flagged line — not its number, which shifts as soon as a line is
 * added above it. A new alert of the same rule elsewhere in the file is a
 * different alert: a verdict never hides code it was not given on.
 */
export function findingFingerprint(
  f: Pick<FindingResult, "ruleId" | "title" | "filePath" | "line">,
  lineContent: string | undefined,
): string {
  const content = (lineContent ?? "").trim().replace(/\s+/g, " ");
  return createHash("sha256")
    .update([f.ruleId ?? f.title, f.filePath ?? "", content || `line:${f.line ?? ""}`].join("\u0000"))
    .digest("hex")
    .slice(0, 32);
}

/** The findings, each with its fingerprint, from the diff's added lines. */
export function fingerprintFindings(findings: FindingResult[], diff: ParsedDiff): FindingResult[] {
  const content = new Map<string, string>();
  for (const l of diff.addedLines) content.set(`${l.file}:${l.line}`, l.content);
  return findings.map((f) => ({
    ...f,
    fingerprint: f.fingerprint ?? findingFingerprint(f, content.get(`${f.filePath}:${f.line}`)),
  }));
}
