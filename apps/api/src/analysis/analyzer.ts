import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets } from "./secret-scanner.js";
import { scanDependencies } from "./dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "./sast.js";
import { decide } from "./risk.js";
import type { AnalysisResult } from "./types.js";

/**
 * Analysis pipeline entry point. Deterministic and pure: given a unified
 * diff, produce findings, secrets, dependencies, a risk score and a decision.
 * This is what the worker runs at its `TODO(étape 3)` point.
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

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
