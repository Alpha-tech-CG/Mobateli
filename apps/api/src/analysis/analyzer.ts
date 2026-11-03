import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import { scanSemgrep, type SemgrepOptions } from "./semgrep.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/** Options for the network/subprocess-backed intelligence passes. */
export interface IntelOptions extends OsvOptions {
  semgrep?: SemgrepOptions;
}

/**
 * Identity of a finding for deduplication: same file and line, and the same
 * rule or the same weakness (CWE). Semgrep and the regex rules often flag the
 * same line under different rule ids, so matching on CWE too avoids reporting
 * one issue twice while keeping genuinely distinct findings.
 */
function isDuplicateFinding(candidate: FindingResult, existing: FindingResult[]): boolean {
  return existing.some(
    (f) =>
      f.filePath === candidate.filePath &&
      f.line === candidate.line &&
      ((f.ruleId !== undefined && f.ruleId === candidate.ruleId) ||
        (f.cwe !== undefined && f.cwe === candidate.cwe)),
  );
}

/**
 * Analysis pipeline entry point. Deterministic and pure: given a unified
 * diff, produce findings, secrets, dependencies, a risk score and a decision.
 * This is the offline, synchronous core — fully testable without network.
 */
export function analyzeDiff(diff: string): AnalysisResult {
  const parsed = parseUnifiedDiff(diff);

  const secrets = scanSecrets(parsed.addedLines);
  const dependencies = scanDependencies(parsed);
  const findings = [
    ...runSastRules(parsed.addedLines),
    ...flagSensitiveFiles(parsed.files),
  ];

  const { riskScore, decision, status } = decide({ findings, secrets, dependencies });

  return { findings, secrets, dependencies, riskScore, decision, status };
}

/**
 * Full analysis: the deterministic core plus network-backed intelligence
 * (OSV known-vulnerability lookup for dependencies, Semgrep semantic SAST).
 * The decision is recomputed after enrichment so a freshly discovered CVE or
 * Semgrep finding can change the verdict. Fails open — if OSV and Semgrep are
 * both unreachable the result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff);
  const parsed = parseUnifiedDiff(diff);

  const [dependencies, semgrepFindings] = await Promise.all([
    enrichDependenciesWithOsv(base.dependencies, opts),
    scanSemgrep(parsed.files, opts.semgrep),
  ]);

  // Merge Semgrep findings with the regex-rule findings, dropping any that
  // duplicate an existing one on (rule|CWE, file, line).
  const findings = [...base.findings];
  for (const finding of semgrepFindings) {
    if (!isDuplicateFinding(finding, findings)) findings.push(finding);
  }

  const { riskScore, decision, status } = decide({
    findings,
    secrets: base.secrets,
    dependencies,
  });
  return { ...base, findings, dependencies, riskScore, decision, status };
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
