import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
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
 * Full analysis: the deterministic core plus network-backed intelligence
 * (OSV known-vulnerability lookup for dependencies). The decision is
 * recomputed after enrichment so a freshly discovered CVE can change the
 * verdict. Fails open — if OSV is unreachable the result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: OsvOptions = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff);
  const dependencies = await enrichDependenciesWithOsv(base.dependencies, opts);
  const { riskScore, decision, status } = decide({
    findings: base.findings,
    secrets: base.secrets,
    dependencies,
  });
  return { ...base, dependencies, riskScore, decision, status };
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
