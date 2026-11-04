import { rm } from "node:fs/promises";
import {
  DEFAULT_ANALYSIS_SETTINGS,
  type AnalysisSettings,
  type EngineId,
  type Severity,
} from "@codegate/shared";
import { parseUnifiedDiff, type ParsedDiff } from "../diff.js";
import { filesFromDiff } from "../rust-engine.js";
import { decide } from "../risk.js";
import type { AnalysisResult, EngineReport, EngineStatusFn } from "../types.js";
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
}

/** Drop the ignored files from the diff before any engine sees it. */
function withoutIgnored(parsed: ParsedDiff, ignorePaths: string[]): ParsedDiff {
  if (!ignorePaths.length) return parsed;
  const ignored = pathMatcher(ignorePaths);
  const keep = (file: string) => !ignored(file);
  return {
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

/**
 * The core phase alone, synchronously (offline, deterministic) — what
 * `analyzeDiff` exposes. Core engines must return their contribution
 * synchronously; an async core engine is a registry bug and throws here.
 */
export function runCoreAnalysis(
  diff: string,
  settings: AnalysisSettings = DEFAULT_ANALYSIS_SETTINGS,
  registry: readonly AnalysisEngine[] = ENGINES,
): AnalysisResult {
  const parsed = withoutIgnored(parseUnifiedDiff(diff), settings.ignorePaths);
  const files = filesFromDiff(parsed);
  const statuses: Partial<Record<EngineId, EngineReport>> = {};
  let totals: AnalysisTotals = { findings: [], secrets: [], dependencies: [] };
  for (const engine of registry.filter((e) => e.phase === "core")) {
    if (settings.engines[engine.id] === false) {
      statuses[engine.id] = { status: "skipped", detail: "désactivé dans les paramètres" };
      continue;
    }
    const contribution = engine.run(
      { parsed, files, settings, options: {}, core: totals },
      (status, detail) => (statuses[engine.id] = detail ? { status, detail } : { status }),
    );
    if (contribution instanceof Promise) throw new Error(`core engine "${engine.id}" must be synchronous`);
    totals = contribution(totals);
    statuses[engine.id] ??= { status: "ok" };
  }
  totals = aboveMinSeverity(totals, settings.minSeverity);
  const { riskScore, decision, status } = decide(totals);
  return { ...totals, riskScore, decision, status, engines: statuses };
}

/**
 * The analysis pipeline. Generic over the engine registry:
 *   1. drop ignored paths;
 *   2. core engines, in order, each folding its contribution into the totals;
 *   3. intel engines, concurrently on the core results, folded in registry
 *      order (each engine owns its merge semantics);
 *   4. severity floor, then the risk decision.
 * Every engine gets a status (ok / skipped / failed + reason), including the
 * ones switched off in the settings, so a report never looks complete when it
 * is not.
 */
export async function runAnalysis(diff: string, opts: RunAnalysisOptions = {}): Promise<AnalysisResult> {
  const settings = opts.settings ?? DEFAULT_ANALYSIS_SETTINGS;
  const runtime = opts.runtime ?? {};
  const phases = opts.phases ?? ["core", "intel"];
  const registry = opts.engines ?? ENGINES;

  const parsed = withoutIgnored(parseUnifiedDiff(diff), settings.ignorePaths);
  const files = filesFromDiff(parsed);
  const statuses: Partial<Record<EngineId, EngineReport>> = {};
  const statusOf =
    (id: EngineId, chained?: EngineStatusFn) =>
    (status: EngineReport["status"], detail?: string) => {
      statuses[id] = detail ? { status, detail } : { status };
      chained?.(status, detail);
    };

  const enabled = (e: AnalysisEngine) => settings.engines[e.id] !== false;
  for (const e of registry) {
    if (!enabled(e)) statuses[e.id] = { status: "skipped", detail: "désactivé dans les paramètres" };
  }

  let totals: AnalysisTotals = { findings: [], secrets: [], dependencies: [] };
  const baseCtx = { parsed, files, settings, options: runtime };

  // ── Core phase ───────────────────────────────────────────────────────────
  if (phases.includes("core")) {
    for (const engine of registry.filter((e) => e.phase === "core" && enabled(e))) {
      const set = statusOf(engine.id);
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

  totals = aboveMinSeverity(totals, settings.minSeverity);
  const { riskScore, decision, status } = decide(totals);
  return { ...totals, riskScore, decision, status, engines: statuses };
}
