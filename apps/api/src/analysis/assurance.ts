import type { DependencyResult, FindingResult, SecretResult } from "./types.js";

/**
 * How well an alert is proven — distinct from its severity (how bad it would
 * be). The decision rule only lets a PROVEN alert block:
 *
 *  - `verified`    a deterministic rule matched with an exploitable context:
 *                  a source→sink path proven by the taint engine, a near-
 *                  certain pattern (high confidence), a provider-format secret
 *                  outside test/sample files;
 *  - `likely`      probable, needs a human check (medium confidence);
 *  - `uncertain`   a possible signal without enough context (low confidence):
 *                  observation only;
 *  - `information` good practice, technical debt (severity info): shown in
 *                  the dashboard, never decides.
 *
 * An alert without a reliable location (no file or no line for code) cannot
 * be `verified`: nobody could check the proof.
 */
export type Assurance = "verified" | "likely" | "uncertain" | "information";

export const ASSURANCES: readonly Assurance[] = ["verified", "likely", "uncertain", "information"];

/** Rules whose finding carries a proven source→sink dataflow. */
const isTaintProof = (ruleId: string | undefined) => (ruleId ?? "").startsWith("RUST-");

export function findingAssurance(f: FindingResult): Assurance {
  if (f.assurance) return f.assurance;
  if (f.severity === "info") return "information";
  const located = Boolean(f.filePath) && (f.line !== undefined || f.type === "config");
  // A proven source→sink path is the proof itself, whatever the engine's own
  // confidence label (it reports "medium" for a long path); low stays low.
  let level: Assurance =
    f.confidence === "low"
      ? "uncertain"
      : isTaintProof(f.ruleId) || f.confidence === "high"
        ? "verified"
        : "likely";
  if (level === "verified" && !located) level = "likely";
  return level;
}

export function secretAssurance(s: SecretResult): Assurance {
  if (s.confidence === "low") return "uncertain";
  if (s.confidence === "medium") return "likely";
  return "verified";
}

/**
 * Dependencies: a single weak signal (a name close to a popular package, a
 * recent publication, few downloads, one maintainer, a licence) never proves
 * an attack. `verified` needs a critical known vulnerability, a package the
 * registry does not know, or several critical signals together — that is
 * what riskLevel "critical" means after dependency-intel.
 */
export function dependencyAssurance(d: DependencyResult): Assurance {
  if (d.riskLevel === "critical") return "verified";
  if (d.riskLevel === "high") return "likely";
  if (d.riskLevel === "medium") return "uncertain";
  return "information";
}

/** A likely high/critical alert waits for a human decision before it can block. */
export function needsHumanReview(f: FindingResult): boolean {
  return findingAssurance(f) === "likely" && (f.severity === "high" || f.severity === "critical");
}

/** Every finding with its assurance set (idempotent). */
export function withAssurance(findings: FindingResult[]): FindingResult[] {
  return findings.map((f) => (f.assurance ? f : { ...f, assurance: findingAssurance(f) }));
}
