import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import { enrichDependenciesWithOsv, type OsvOptions } from "./osv.js";
import { runSca, mergeScaIntoDependencies, type ScaOptions } from "./sca.js";
import type { AnalysisResult } from "./types.js";

/**
 * Options for the network-backed analysis. OSV fields stay at the top level for
 * backward compatibility; the full-tree SCA (Trivy/Grype) scan is opt-in under
 * `sca` and only runs when a workspace dir or container image is provided.
 */
export type IntelOptions = OsvOptions & { sca?: ScaOptions };

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
 * Full analysis: the deterministic core plus network-backed intelligence —
 * OSV known-vulnerability lookup on the dependencies added in the diff, then an
 * optional full-tree SCA scan (Trivy/Grype over lockfiles and container images)
 * whose findings are merged in without duplicating a CVE (dedup by id). The
 * decision is recomputed after enrichment so a freshly discovered CVE or
 * restrictive license can change the verdict. Fails open — if both OSV and the
 * SCA tool are unreachable the result equals `analyzeDiff`.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
): Promise<AnalysisResult> {
  const base = analyzeDiff(diff);
  const osvEnriched = await enrichDependenciesWithOsv(base.dependencies, opts);
  const scaDeps = await runSca(opts.sca ?? {});
  const dependencies = mergeScaIntoDependencies(osvEnriched, scaDeps);
  const { riskScore, decision, status } = decide({
    findings: base.findings,
    secrets: base.secrets,
    dependencies,
  });
  return { ...base, dependencies, riskScore, decision, status };
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
