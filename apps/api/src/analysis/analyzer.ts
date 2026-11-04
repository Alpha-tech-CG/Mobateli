import type { AnalysisSettings } from "@codegate/shared";
import type { ParsedDiff, NewSideLine } from "./diff.js";
import type { EngineRuntimeOptions } from "./engines/engine.js";
import { runAnalysis, runCoreAnalysis, type PipelineResult } from "./engines/pipeline.js";

/**
 * Analysis entry points. The pipeline itself — engines, merge order, status
 * reporting, parameters, human false-positive verdicts — lives in ./engines
 * (see engines/engine.ts to add an engine, and @codegate/shared
 * analysis-settings.ts for parameters; docs/ARCHITECTURE-ANALYSE.md).
 */

export { findingFingerprint } from "./fingerprint.js";
export type { PipelineResult } from "./engines/pipeline.js";

/** Runtime options for the network/binary engines. Historical name. */
export type IntelOptions = EngineRuntimeOptions;

/**
 * Offline, synchronous analysis of a diff: the core engines only (Rust
 * WebAssembly engine + TypeScript rules, dependency trust, configuration,
 * prompt injection) — deterministic, no network.
 * `suppressed`: fingerprints a human marked as false positives.
 */
export function analyzeDiff(
  diff: string,
  suppressed: ReadonlySet<string> = new Set(),
  settings?: AnalysisSettings,
): PipelineResult {
  return runCoreAnalysis(diff, settings, suppressed);
}

/** Whole files of a repository snapshot, analysed as if every line were added. */
export function analyzeFiles(
  files: { path: string; content: string }[],
  suppressed: ReadonlySet<string> = new Set(),
  settings?: AnalysisSettings,
): PipelineResult {
  const parsed: ParsedDiff = {
    files: [],
    addedLines: [],
    addedByFile: new Map(),
    newSideByFile: new Map(),
  };
  for (const f of files) {
    parsed.files.push(f.path);
    parsed.addedByFile.set(f.path, f.content);
    const side: NewSideLine[] = [];
    f.content.split("\n").forEach((raw, i) => {
      const content = raw.replace(/\r$/, "");
      parsed.addedLines.push({ file: f.path, line: i + 1, content });
      side.push({ content, added: true, hunkStart: i === 0 });
    });
    parsed.newSideByFile.set(f.path, side);
  }
  return runCoreAnalysis(parsed, settings, suppressed);
}

/**
 * Full analysis: core engines, then every enabled network/binary engine
 * (dependency intelligence, Trivy/Grype, Semgrep, native taint engine), which
 * fail open and report their status. Binary engines need a worker
 * (`opts.worker === false` in serverless mode reports them as skipped).
 */
export async function analyzeDiffWithIntel(
  diff: string,
  opts: IntelOptions = {},
  settings?: AnalysisSettings,
  suppressed?: ReadonlySet<string>,
): Promise<PipelineResult> {
  return runAnalysis(diff, {
    runtime: opts,
    ...(settings ? { settings } : {}),
    ...(suppressed ? { suppressed } : {}),
  });
}

export * from "./types.js";
export { buildPrComment } from "./explainer.js";
