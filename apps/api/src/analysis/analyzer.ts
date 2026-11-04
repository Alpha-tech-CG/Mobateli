import type { AnalysisSettings } from "@codegate/shared";
import type { AnalysisResult } from "./types.js";
import type { EngineRuntimeOptions } from "./engines/engine.js";
import { runAnalysis, runCoreAnalysis } from "./engines/pipeline.js";

/**
 * Analysis entry points. The pipeline itself — engines, merge order, status
 * reporting, settings — lives in ./engines (see engines/engine.ts for how to
 * add an engine, and @codegate/shared analysis-settings.ts for parameters).
 */

/**
 * Runtime options for the tool/network engines (OSV fetch, Semgrep/Trivy/
 * Rust runners and binaries). Kept as the historical name for callers.
 */
export type IntelOptions = EngineRuntimeOptions;

/**
 * Offline, synchronous analysis: the core engines only (secrets, dependency
 * trust, SAST rules, sensitive files) — deterministic and testable without
 * network or subprocesses.
 */
export function analyzeDiff(diff: string, settings?: AnalysisSettings): AnalysisResult {
  return runCoreAnalysis(diff, settings);
}

/**
 * Full analysis: core engines, then every enabled intel engine (OSV, SCA,
 * Rust taint engine, Semgrep), which fail open and report their status.
 * `settings` are the resolved organization/repository parameters.
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
  settings?: AnalysisSettings,
): Promise<AnalysisResult> {
  return runAnalysis(diff, { runtime: opts, ...(settings ? { settings } : {}) });
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
