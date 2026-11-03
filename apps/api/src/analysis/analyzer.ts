import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import { scanSemgrep, type SemgrepOptions } from "./semgrep.js";
import { runSca, mergeScaIntoDependencies, type ScaOptions } from "./sca.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/**
 * Options for the network/subprocess-backed intelligence passes. OSV fields
 * stay at the top level for backward compatibility; Semgrep (semantic SAST) and
 * the full-tree SCA scan (Trivy/Grype over lockfiles and container images) are
 * opt-in and only run when their inputs/tools are available.
 */
export interface IntelOptions extends OsvOptions {
  semgrep?: SemgrepOptions;
  sca?: ScaOptions;
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
 * Full analysis: the deterministic core plus network/subprocess-backed
 * intelligence, all fail-open and run concurrently:
 *  - OSV known-vulnerability lookup on the dependencies added in the diff;
 *  - an optional full-tree SCA scan (Trivy/Grype over lockfiles and container
 *    images), merged into the dependencies without duplicating a CVE;
 *  - Semgrep semantic SAST, merged into the findings without duplicating a
 *    regex-rule hit on (rule|CWE, file, line).
 * The decision is recomputed after enrichment so a freshly discovered CVE,
 * restrictive license or Semgrep finding can change the verdict. If every
 * external pass is unreachable the result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff);
  const parsed = parseUnifiedDiff(diff);

  const [osvEnriched, scaDeps, semgrepFindings] = await Promise.all([
    enrichDependenciesWithOsv(base.dependencies, opts),
    runSca(opts.sca ?? {}),
    scanSemgrep(parsed.files, opts.semgrep),
  ]);

  const dependencies = mergeScaIntoDependencies(osvEnriched, scaDeps);

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
