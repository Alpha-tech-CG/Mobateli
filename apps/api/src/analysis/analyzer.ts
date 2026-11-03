import { parseUnifiedDiff, type ParsedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules } from "./sast.js";
import { analyzeConfig } from "./config-rules.js";
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
  return analyzeParsed(parseUnifiedDiff(diff), suppressed);
}

/** Whole files of a repository snapshot, analysed as if every line were added. */
export function analyzeFiles(
  files: { path: string; content: string }[],
  suppressed: ReadonlySet<string> = new Set(),
): AnalysisResult & { suppressed: FindingResult[]; engine: string } {
  const parsed: ParsedDiff = { files: [], addedLines: [], addedByFile: new Map() };
  for (const f of files) {
    parsed.files.push(f.path);
    parsed.addedByFile.set(f.path, f.content);
    f.content.split("\n").forEach((content, i) => {
      parsed.addedLines.push({ file: f.path, line: i + 1, content: content.replace(/\r$/, "") });
    });
  }
  return analyzeParsed(parsed, suppressed);
}

function analyzeParsed(
  parsed: ParsedDiff,
  suppressed: ReadonlySet<string>,
): AnalysisResult & { suppressed: FindingResult[]; engine: string } {

  // Rust engine (WebAssembly) first: secrets + syntax-tree rules for JS/TS.
  // Files it could not parse, other languages, or no engine ⇒ line rules.
  const engine = scanWithEngine(parsed.addedLines);
  const astFiles = new Set(engine?.astFiles ?? []);
  const secrets = engine?.secrets ?? scanSecrets(parsed.addedLines);
  const dependencies = scanDependencies(parsed);
  const all = [
    ...(engine?.findings ?? []),
    ...runSastRules(parsed.addedLines.filter((l) => !astFiles.has(l.file))),
    ...analyzeConfig(parsed.addedLines, parsed.files),
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
