import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import {
  runRustEngine,
  filesFromDiff,
  mergeRustFindings,
  type RustEngineOptions,
} from "./rust-engine.js";
import type { AnalysisResult } from "./types.js";

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
 * does I/O and therefore fails open — OSV known-vulnerability lookup for
 * dependencies, and the Rust semantic scan engine (services/scan-engine) for
 * taint-based SAST. Both run concurrently and never block a PR on their own
 * failure; the decision is recomputed afterwards so a freshly discovered CVE
 * or a confirmed injection can change the verdict. With neither available the
 * result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: OsvOptions & { rust?: RustEngineOptions } = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff);

  const [dependencies, rustFindings] = await Promise.all([
    enrichDependenciesWithOsv(base.dependencies, opts),
    runRustEngine(filesFromDiff(parseUnifiedDiff(diff)), opts.rust ?? {}),
  ]);

  // The engine's richer finding supersedes a regex finding for the same issue.
  const findings = mergeRustFindings(base.findings, rustFindings);

  const { riskScore, decision, status } = decide({
    findings,
    secrets: base.secrets,
    dependencies,
  });
  return { ...base, findings, dependencies, riskScore, decision, status };
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
