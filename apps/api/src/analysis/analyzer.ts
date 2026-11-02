import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { detectPromptInjection } from "./prompt-injection.js";
import { scanWithEngine } from "./engine/index.js";
import { decide } from "./risk.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/**
 * Stable identity of a finding across commits: rule + file, not the line
 * (lines move). Used to carry a human "false positive" verdict forward.
 */
export function findingFingerprint(f: Pick<FindingResult, "ruleId" | "title" | "filePath">): string {
  return `${f.ruleId ?? f.title}|${f.filePath ?? ""}`;
}

/**
 * Analysis pipeline entry point. Deterministic and pure: given a unified
 * diff, produce findings, secrets, dependencies, a risk score and a decision.
 * This is what the worker runs at its `TODO(étape 3)` point.
 */
export function analyzeDiff(
  diff: string,
  suppressed: ReadonlySet<string> = new Set(),
): AnalysisResult & { suppressed: FindingResult[]; engine: string } {
  const parsed = parseUnifiedDiff(diff);

  // Rust engine (WebAssembly) first: secrets + syntax-tree rules for JS/TS.
  // Files it could not parse, other languages, or no engine ⇒ line rules.
  const engine = scanWithEngine(parsed.addedLines);
  const astFiles = new Set(engine?.astFiles ?? []);
  const secrets = engine?.secrets ?? scanSecrets(parsed.addedLines);
  const dependencies = scanDependencies(parsed);
  const all = [
    ...(engine?.findings ?? []),
    ...runSastRules(parsed.addedLines.filter((l) => !astFiles.has(l.file))),
    ...flagSensitiveFiles(parsed.files),
    ...detectPromptInjection(parsed.addedLines, parsed.files),
  ];
  // False positives marked by a human are kept for the record but no longer
  // weigh on the score or the decision (US02).
  const findings = all.filter((f) => !suppressed.has(findingFingerprint(f)));
  const suppressedFindings = all.filter((f) => suppressed.has(findingFingerprint(f)));

  const { riskScore, decision, status } = decide({ findings, secrets, dependencies });

  return {
    findings,
    secrets,
    dependencies,
    riskScore,
    decision,
    status,
    suppressed: suppressedFindings,
    engine: engine ? `rust-wasm ${engine.version}` : "typescript",
  };
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
