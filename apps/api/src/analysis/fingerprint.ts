import type { FindingResult } from "./types.js";

/**
 * Stable identity of a finding across commits: rule + file, not the line
 * (lines move). Used to carry a human "false positive" verdict forward.
 */
export function findingFingerprint(f: Pick<FindingResult, "ruleId" | "title" | "filePath">): string {
  return `${f.ruleId ?? f.title}|${f.filePath ?? ""}`;
}
