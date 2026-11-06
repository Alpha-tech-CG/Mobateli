import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { withoutIgnored } from "./ignore.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import { scanSemgrep, type SemgrepOptions } from "./semgrep.js";
import { runSca, mergeScaIntoDependencies, type ScaOptions } from "./sca.js";
import {
  runRustEngineDetailed,
  filesFromDiff,
  mergeRustFindings,
  corroborate,
  type RustEngineOptions,
} from "./rust-engine.js";
import type { AnalysisResult, FindingResult } from "./types.js";

/**
 * Options for the network/subprocess-backed intelligence passes. OSV fields
 * stay at the top level for backward compatibility; Semgrep (semantic SAST),
 * the full-tree SCA scan (Trivy/Grype over lockfiles and container images) and
 * the Rust taint engine are opt-in and only run when their inputs/tools are
 * available.
 */
export interface AnalyzeOptions {
  /**
   * Paths excluded by the repository's `.codegateignore` (see ignore.ts):
   * skipped by SAST, dependency and Semgrep/Rust passes — but NOT by the
   * secret scanner, nor by the sensitive-file notice.
   */
  isIgnored?: (path: string) => boolean;
}

export interface IntelOptions extends OsvOptions, AnalyzeOptions {
  semgrep?: SemgrepOptions;
  sca?: ScaOptions;
  rust?: RustEngineOptions;
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
export function analyzeDiff(diff: string, opts: AnalyzeOptions = {}): AnalysisResult {
  const parsed = parseUnifiedDiff(diff);
  const scoped = opts.isIgnored ? withoutIgnored(parsed, opts.isIgnored) : parsed;

  const secrets = scanSecrets(parsed.addedLines);
  const dependencies = scanDependencies(scoped);
  const findings = [
    ...runSastRules(scoped.addedLines),
    ...flagSensitiveFiles(parsed.files),
  ];

  const { riskScore, decision, status } = decide({ findings, secrets, dependencies });

  return { findings, secrets, dependencies, riskScore, decision, status };
}

/**
 * Full analysis: the deterministic core plus out-of-core intelligence that
 * does I/O and therefore fails open — all four passes run concurrently and
 * never block a PR on their own failure:
 *  - OSV known-vulnerability lookup on the dependencies added in the diff;
 *  - a full-tree SCA scan (Trivy/Grype over lockfiles and container images),
 *    merged into the dependencies without duplicating a CVE;
 *  - Semgrep semantic SAST, merged into the findings without duplicating a
 *    regex-rule hit on (rule|CWE, file, line);
 *  - the Rust taint engine (services/scan-engine), whose richer finding
 *    supersedes a regex finding for the same issue.
 * The decision is recomputed afterwards so a freshly discovered CVE,
 * restrictive license, Semgrep finding or confirmed injection can change the
 * verdict. With no external pass available the result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff, opts);
  const full = parseUnifiedDiff(diff);
  const parsed = opts.isIgnored ? withoutIgnored(full, opts.isIgnored) : full;

  const [osvEnriched, scaDeps, semgrepFindings, rustRun] = await Promise.all([
    enrichDependenciesWithOsv(base.dependencies, opts),
    runSca(opts.sca ?? {}),
    scanSemgrep(parsed.files, opts.semgrep),
    runRustEngineDetailed(filesFromDiff(parsed), opts.rust ?? {}),
  ]);

  const dependencies = mergeScaIntoDependencies(osvEnriched, scaDeps);

  // The Rust engine's richer finding supersedes a regex finding for the same
  // issue; then Semgrep findings are added unless they duplicate an existing
  // one on (rule|CWE, file, line).
  // A regex finding the engine did not confirm is downgraded — only after a
  // complete engine run (see corroborate).
  const findings = corroborate(
    mergeRustFindings(base.findings, rustRun.findings),
    rustRun.findings,
    rustRun.ran,
  );
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
