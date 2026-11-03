import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { detectPromptInjection } from "./prompt-injection.js";
import { scanWithEngine } from "./engine/index.js";
import { decide } from "./risk.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/** Test, spec and fixture files (any language). */
export function isTestPath(file: string): boolean {
  return (
    /(^|\/)(__tests__|__fixtures__|tests?|spec|specs|fixtures?|testdata)\//i.test(file) ||
    /\.(test|spec|itest|e2e)\.[a-z0-9]+$/i.test(file) ||
    /(^|\/)test_[^/]+\.py$|_test\.(go|py)$/i.test(file)
  );
}

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
  // Generic (entropy-based) matches in test files are fixtures, not leaks;
  // provider-format keys stay reported wherever they appear.
  const secrets = (engine?.secrets ?? scanSecrets(parsed.addedLines)).filter(
    (s) => !(s.secretType.startsWith("generic_") && isTestPath(s.location.replace(/:\d+$/, ""))),
  );
  const dependencies = scanDependencies(parsed);
  const raw = [
    ...(engine?.findings ?? []),
    ...runSastRules(parsed.addedLines.filter((l) => !astFiles.has(l.file))),
    ...flagSensitiveFiles(parsed.files),
    ...detectPromptInjection(parsed.addedLines, parsed.files),
  ];
  // Test code deliberately contains attacks and dangerous calls: still shown,
  // but as low severity so it never blocks a merge on its own.
  const all = raw.map((f) =>
    f.filePath && isTestPath(f.filePath) && (f.type === "sast" || f.type === "prompt_injection") && f.severity !== "low"
      ? { ...f, severity: "low" as const, description: `${f.description} (fichier de test)` }
      : f,
  );
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
