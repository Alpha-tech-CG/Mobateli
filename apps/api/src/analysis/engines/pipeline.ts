import { rm } from "node:fs/promises";
import {
  DEFAULT_ANALYSIS_SETTINGS,
  ENGINE_CATALOG,
  type AnalysisSettings,
  type EngineId,
  type Severity,
} from "@codegate/shared";
import { parseUnifiedDiff, type ParsedDiff } from "../diff.js";
import { filesFromDiff } from "../rust-engine.js";
import { scanWithEngine, type EngineOutput } from "../engine/index.js";
import { fingerprintFindings } from "../fingerprint.js";
import { decide } from "../risk.js";
import type { AnalysisResult, EngineReport, EngineStatusFn, FindingResult } from "../types.js";
import type {
  AnalysisEngine,
  AnalysisTotals,
  Contribution,
  EngineContext,
  EngineRuntimeOptions,
} from "./engine.js";
import { pathMatcher } from "./glob.js";
import { materializeFiles } from "./paths.js";
import { ENGINES } from "./registry.js";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface RunAnalysisOptions {
  /** Resolved parameters (see resolveAnalysisSettings). Defaults when absent. */
  settings?: AnalysisSettings;
  /** Runtime options for tool/network engines (runners, binaries, timeouts). */
  runtime?: EngineRuntimeOptions;
  /** Only these phases run — "core" alone is the offline, synchronous analysis. */
  phases?: ReadonlyArray<AnalysisEngine["phase"]>;
  /** Engines to run (tests, a custom pipeline). Defaults to the registry. */
  engines?: readonly AnalysisEngine[];
  /**
   * Fingerprints a human marked as false positives on this repository: those
   * findings are returned in `suppressed` (kept for the record) and do not
   * weigh on the score or the decision.
   */
  suppressed?: ReadonlySet<string>;
  /**
   * Paths excluded by the repository's `.codegateignore` (read from the
   * default branch, see ignore.ts), on top of the configured ignorePaths.
   */
  isIgnored?: (path: string) => boolean;
}

/** Analysis result, plus what the dashboard and the audit trail record. */
export type PipelineResult = AnalysisResult & {
  /** Findings matching a human "false positive" verdict — not scored. */
  suppressed: FindingResult[];
  /** Which code analyzer ran: "rust-wasm <version>" or "typescript". */
  engine: string;
};

/**
 * Drop the ignored files from the diff before the code engines see it (the
 * secret scanner still reads the whole diff, see EngineContext.unfiltered).
 */
function withoutIgnored(
  parsed: ParsedDiff,
  ignorePaths: string[],
  isIgnored?: (path: string) => boolean,
): ParsedDiff {
  if (!ignorePaths.length && !isIgnored) return parsed;
  const ignored = ignorePaths.length ? pathMatcher(ignorePaths) : () => false;
  const keep = (file: string) => !ignored(file) && !isIgnored?.(file);
  return {
    ...parsed,
    files: parsed.files.filter(keep),
    addedLines: parsed.addedLines.filter((l) => keep(l.file)),
    addedByFile: new Map([...parsed.addedByFile].filter(([f]) => keep(f))),
    newSideByFile: new Map([...parsed.newSideByFile].filter(([f]) => keep(f))),
  };
}

/** Findings and secrets below the configured severity are not reported. */
function aboveMinSeverity(totals: AnalysisTotals, min: Severity): AnalysisTotals {
  if (min === "info") return totals;
  const keep = (s: Severity) => SEVERITY_RANK[s] >= SEVERITY_RANK[min];
  return {
    ...totals,
    findings: totals.findings.filter((f) => keep(f.severity)),
    secrets: totals.secrets.filter((s) => keep(s.severity)),
  };
}

/** The in-process Rust engine runs at most once per analysis, on demand. */
function astMemo(parsed: ParsedDiff): () => EngineOutput | null {
  let done = false;
  let out: EngineOutput | null = null;
  return () => {
    if (!done) {
      out = scanWithEngine(parsed.addedLines);
      done = true;
    }
    return out;
  };
}

/** Severity floor, human verdicts, then the risk decision. */
function finish(
  totals: AnalysisTotals,
  settings: AnalysisSettings,
  suppressedSet: ReadonlySet<string>,
  statuses: Partial<Record<EngineId, EngineReport>>,
  ast: () => EngineOutput | null,
  astUsed: boolean,
  unfiltered: ParsedDiff,
): PipelineResult {
  const kept = aboveMinSeverity(totals, settings.minSeverity);
  // Each finding carries its fingerprint (rule, file, flagged code): the key of
  // a human verdict, stable when the line moves.
  const all = fingerprintFindings(kept.findings, unfiltered);
  const findings = all.filter((f) => !suppressedSet.has(f.fingerprint!));
  const suppressed = all.filter((f) => suppressedSet.has(f.fingerprint!));
  const { riskScore, decision, status } = decide({ ...kept, findings });
  const wasm = astUsed ? ast() : null;
  return {
    ...kept,
    findings,
    suppressed,
    riskScore,
    decision,
    status,
    engines: statuses,
    engine: wasm ? `rust-wasm ${wasm.version}` : "typescript",
  };
}

function toParsed(
  input: string | ParsedDiff,
  settings: AnalysisSettings,
  isIgnored?: (path: string) => boolean,
): { parsed: ParsedDiff; unfiltered: ParsedDiff } {
  const unfiltered = typeof input === "string" ? parseUnifiedDiff(input) : input;
  return { parsed: withoutIgnored(unfiltered, settings.ignorePaths, isIgnored), unfiltered };
}

/** Engines that run a binary cannot run without a worker (serverless). */
function unavailable(e: AnalysisEngine, runtime: EngineRuntimeOptions): string | null {
  // The taint engine is a static binary: the Vercel bundle ships it
  // (build-vercel.mjs, vercel.ts sets CODEGATE_SCAN_BIN), so it runs inline.
  const bundled = e.id === "rust" && Boolean(runtime.rust?.binaryPath ?? process.env.CODEGATE_SCAN_BIN);
  if (ENGINE_CATALOG[e.id]?.needsWorker && runtime.worker === false && !bundled) {
    return "indisponible sans worker (mode serverless)";
  }
  return null;
}

/**
 * The core phase alone, synchronously (offline, deterministic) — what
 * `analyzeDiff` / `analyzeFiles` expose. Core engines must return their
 * contribution synchronously; an async core engine is a registry bug.
 */
export function runCoreAnalysis(
  input: string | ParsedDiff,
  settings: AnalysisSettings = DEFAULT_ANALYSIS_SETTINGS,
  suppressedSet: ReadonlySet<string> = new Set(),
  registry: readonly AnalysisEngine[] = ENGINES,
  isIgnored?: (path: string) => boolean,
): PipelineResult {
  const { parsed, unfiltered } = toParsed(input, settings, isIgnored);
  const files = filesFromDiff(parsed);
  const ast = astMemo(parsed);
  const statuses: Partial<Record<EngineId, EngineReport>> = {};
  let totals: AnalysisTotals = { findings: [], secrets: [], dependencies: [] };
  let astUsed = false;
  for (const engine of registry.filter((e) => e.phase === "core")) {
    if (settings.engines[engine.id] === false) {
      statuses[engine.id] = { status: "skipped", detail: "désactivé dans les paramètres" };
      continue;
    }
    if (engine.id === "secrets" || engine.id === "sast") astUsed = true;
    const contribution = engine.run(
      { parsed, unfiltered, files, settings, options: {}, core: totals, ast },
      (status, detail) => (statuses[engine.id] = detail ? { status, detail } : { status }),
    );
    if (contribution instanceof Promise) throw new Error(`core engine "${engine.id}" must be synchronous`);
    totals = contribution(totals);
    statuses[engine.id] ??= { status: "ok" };
  }
  return finish(totals, settings, suppressedSet, statuses, ast, astUsed, unfiltered);
}

/**
 * The analysis pipeline. Generic over the engine registry:
 *   1. drop ignored paths;
 *   2. core engines, in order, each folding its contribution into the totals;
 *   3. intel engines, concurrently on the core results, folded in registry
 *      order (each engine owns its merge semantics);
 *   4. severity floor, human false-positive verdicts, then the decision.
 * Every engine gets a status (ok / skipped / failed + reason), including the
 * ones switched off in the settings or unavailable without a worker, so a
 * report never looks complete when it is not.
 */
export async function runAnalysis(
  input: string | ParsedDiff,
  opts: RunAnalysisOptions = {},
): Promise<PipelineResult> {
  const settings = opts.settings ?? DEFAULT_ANALYSIS_SETTINGS;
  const runtime = opts.runtime ?? {};
  const phases = opts.phases ?? ["core", "intel"];
  const registry = opts.engines ?? ENGINES;

  const { parsed, unfiltered } = toParsed(input, settings, opts.isIgnored);
  const files = filesFromDiff(parsed);
  const ast = astMemo(parsed);
  const statuses: Partial<Record<EngineId, EngineReport>> = {};
  const statusOf =
    (id: EngineId, chained?: EngineStatusFn) =>
    (status: EngineReport["status"], detail?: string) => {
      statuses[id] = detail ? { status, detail } : { status };
      chained?.(status, detail);
    };

  const enabled = (e: AnalysisEngine) => settings.engines[e.id] !== false && !unavailable(e, runtime);
  for (const e of registry) {
    if (settings.engines[e.id] === false) {
      statuses[e.id] = { status: "skipped", detail: "désactivé dans les paramètres" };
    } else {
      const why = unavailable(e, runtime);
      if (why) statuses[e.id] = { status: "skipped", detail: why };
    }
  }

  let totals: AnalysisTotals = { findings: [], secrets: [], dependencies: [] };
  const baseCtx = { parsed, unfiltered, files, settings, options: runtime, ast };
  let astUsed = false;

  // ── Core phase ───────────────────────────────────────────────────────────
  if (phases.includes("core")) {
    for (const engine of registry.filter((e) => e.phase === "core" && enabled(e))) {
      const set = statusOf(engine.id);
      if (engine.id === "secrets" || engine.id === "sast") astUsed = true;
      try {
        const contribution = await engine.run({ ...baseCtx, core: totals }, set);
        totals = contribution(totals);
        if (!statuses[engine.id]) set("ok");
      } catch (err) {
        set("failed", err instanceof Error ? err.message.slice(0, 80) : "erreur");
      }
    }
  }

  // ── Intel phase ──────────────────────────────────────────────────────────
  const intel = phases.includes("intel")
    ? registry.filter((e) => e.phase === "intel" && enabled(e))
    : [];
  if (intel.length) {
    // Tools that read files get the PR's added code on disk.
    const needsDisk = intel.some((e) => e.id === "semgrep") && !runtime.semgrep?.cwd && files.length;
    const scratchDir = needsDisk ? await materializeFiles(files) : undefined;
    const ctx: EngineContext = { ...baseCtx, core: totals, ...(scratchDir ? { scratchDir } : {}) };
    try {
      // Callers' own status callbacks (historical per-tool options) still fire.
      const chained: Partial<Record<EngineId, EngineStatusFn | undefined>> = {
        osv: runtime.onStatus,
        sca: runtime.sca?.onStatus,
        semgrep: runtime.semgrep?.onStatus,
        rust: runtime.rust?.onStatus,
      };
      const contributions = await Promise.all(
        intel.map(async (engine): Promise<Contribution> => {
          const set = statusOf(engine.id, chained[engine.id]);
          try {
            const c = await engine.run(ctx, set);
            if (!statuses[engine.id]) set("ok");
            return c;
          } catch (err) {
            // An engine bug must not sink the analysis — report it.
            set("failed", err instanceof Error ? err.message.slice(0, 80) : "erreur");
            return (t) => t;
          }
        }),
      );
      for (const c of contributions) totals = c(totals);
    } finally {
      // Best effort: a file still locked (Windows, a timed-out Semgrep child)
      // must never turn a finished analysis into a failure.
      if (scratchDir) {
        await rm(scratchDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(
          () => undefined,
        );
      }
    }
  }

  return finish(totals, settings, opts.suppressed ?? new Set(), statuses, ast, astUsed, unfiltered);
}
