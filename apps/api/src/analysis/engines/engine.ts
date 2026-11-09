import type { AnalysisSettings, EngineId } from "@codegate/shared";
import type { ParsedDiff } from "../diff.js";
import type { EngineFile } from "../rust-engine.js";
import type {
  DependencyResult,
  EngineStatusFn,
  FindingResult,
  SecretResult,
} from "../types.js";
import type { EngineOutput } from "../engine/index.js";
import type { SemgrepOptions } from "../semgrep.js";
import type { ScaOptions } from "../sca.js";
import type { RustEngineOptions } from "../rust-engine.js";

/**
 * Analysis engine contract. Every pass of the pipeline — built-in regex rules
 * or an external tool — is an engine: it reads the PR (`EngineContext`) and
 * returns a `Contribution`, a function that folds its results into the
 * running totals. Each engine owns its merge semantics (OSV enriches the
 * dependencies, the Rust engine supersedes a regex finding for the same issue,
 * Semgrep skips duplicates…), so the pipeline stays generic.
 *
 * Adding an engine: implement this interface in a file of this folder, add its
 * id to ENGINE_IDS / ENGINE_CATALOG (@codegate/shared) and register it in
 * registry.ts. It then gets on/off switches, status reporting ("Analyse
 * partielle") and per-org/per-repo settings for free.
 */

/** What the pipeline has found so far. */
export interface AnalysisTotals {
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
}

/** Folds an engine's results into the totals (pure). */
export type Contribution = (totals: AnalysisTotals) => AnalysisTotals;

/** Runtime options for engines backed by a tool or a network service. */
export interface EngineRuntimeOptions {
  /** HTTP client for registry/OSV lookups (tests inject a fake). */
  fetchImpl?: typeof fetch;
  /**
   * Whether external binaries may run (Semgrep, Trivy, native taint engine).
   * False in serverless mode (ANALYSIS_MODE=inline): those engines are then
   * reported "skipped", not "failed". Defaults to true.
   */
  worker?: boolean;
  /** Status callback of the dependency-intel (OSV) engine, for callers. */
  onStatus?: EngineStatusFn;
  semgrep?: SemgrepOptions;
  sca?: ScaOptions;
  rust?: RustEngineOptions;
}

export interface EngineContext {
  /** The PR diff, minus the ignored paths. */
  parsed: ParsedDiff;
  /**
   * The whole diff, ignored paths included. Only the secret scanner reads it:
   * a credential committed under an ignored path is leaked all the same.
   */
  unfiltered: ParsedDiff;
  /** The PR's added code, rebuilt per file at its real line numbers. */
  files: EngineFile[];
  settings: AnalysisSettings;
  options: EngineRuntimeOptions;
  /** The PR's added files written to disk, for tools that read files. */
  scratchDir?: string;
  /** Results of the core phase — what external (intel) engines build on. */
  core: Readonly<AnalysisTotals>;
  /**
   * The in-process Rust engine (WebAssembly) run on the added lines — computed
   * once per analysis and shared by the engines that use it (secrets, SAST).
   * Null when the module is unavailable: TypeScript rules take over.
   */
  ast: () => EngineOutput | null;
}

export interface AnalysisEngine {
  id: EngineId;
  /**
   * "core": deterministic, in-process, offline (always fast).
   * "intel": network or subprocess backed; runs concurrently after the core
   * phase and fails open — reported as skipped/failed, never blocking.
   */
  phase: "core" | "intel";
  run(ctx: EngineContext, setStatus: EngineStatusFn): Contribution | Promise<Contribution>;
}

/** A contribution that changes nothing. */
export const NO_CONTRIBUTION: Contribution = (t) => t;
