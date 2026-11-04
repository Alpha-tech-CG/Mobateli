import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import { scanSemgrep, type SemgrepOptions } from "./semgrep.js";
import { runSca, mergeScaIntoDependencies, type ScaOptions } from "./sca.js";
import {
  runRustEngine,
  filesFromDiff,
  mergeRustFindings,
  type RustEngineOptions,
} from "./rust-engine.js";
import type { AnalysisResult, FindingResult } from "./types.js";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** A diff path that stays inside the scratch dir (no absolute path, no ".."). */
function isSafeRelativePath(p: string): boolean {
  return (
    p.length > 0 &&
    !p.includes("\0") &&
    !/^([a-zA-Z]:)?[\\/]/.test(p) &&
    !p.split(/[\\/]/).includes("..")
  );
}

/** Write the PR's added code to a fresh temp dir; returns its path. */
async function materializeFiles(files: { path: string; content: string }[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "codegate-semgrep-"));
  for (const f of files) {
    if (!isSafeRelativePath(f.path)) continue;
    const target = join(dir, f.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, f.content, "utf8");
  }
  return dir;
}

/**
 * Options for the network/subprocess-backed intelligence passes. OSV fields
 * stay at the top level for backward compatibility; Semgrep (semantic SAST),
 * the full-tree SCA scan (Trivy/Grype over lockfiles and container images) and
 * the Rust taint engine are opt-in and only run when their inputs/tools are
 * available.
 */
export interface IntelOptions extends OsvOptions {
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
  const base = analyzeDiff(diff);
  const parsed = parseUnifiedDiff(diff);
  const engineFiles = filesFromDiff(parsed);

  // Semgrep reads files from disk, but the worker only has the diff. Unless
  // the caller points at a checkout (cwd), write the added code to a scratch
  // directory so Semgrep scans what the PR actually adds — not nothing, nor
  // same-named files in the API's own working directory.
  let scratch: string | undefined;
  let semgrepOpts = opts.semgrep;
  if (!opts.semgrep?.cwd && engineFiles.length) {
    scratch = await materializeFiles(engineFiles);
    semgrepOpts = { ...opts.semgrep, cwd: scratch };
  }

  let osvEnriched, scaDeps, semgrepFindings, rustFindings;
  try {
    [osvEnriched, scaDeps, semgrepFindings, rustFindings] = await Promise.all([
      enrichDependenciesWithOsv(base.dependencies, opts),
      runSca(opts.sca ?? {}),
      scanSemgrep(
        // The scratch dir holds exactly the PR's files, so scan it as a whole:
        // listing thousands of paths overflows the OS command-line limit
        // (32 767 chars on Windows) and Semgrep would silently not run.
        scratch
          ? ["."]
          : engineFiles.map((f) => f.path).filter((p) => isSafeRelativePath(p)),
        semgrepOpts,
      ),
      runRustEngine(engineFiles, opts.rust ?? {}),
    ]);
  } finally {
    // Best effort: a file still locked (Windows, a timed-out Semgrep child)
    // must never turn a finished analysis into a failure.
    if (scratch) {
      await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(
        () => undefined,
      );
    }
  }

  const dependencies = mergeScaIntoDependencies(osvEnriched, scaDeps);

  // The Rust engine's richer finding supersedes a regex finding for the same
  // issue; then Semgrep findings are added unless they duplicate an existing
  // one on (rule|CWE, file, line).
  const findings = mergeRustFindings(base.findings, rustFindings);
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
