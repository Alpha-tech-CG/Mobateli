import type { EngineId } from "@codegate/shared";
import { scanSecrets } from "../secret-scanner.js";
import { scanDependencies } from "../dependency-scanner.js";
import { runSastRules, flagSensitiveFiles } from "../sast.js";
import { enrichDependenciesWithOsv } from "../osv.js";
import { runSca, mergeScaIntoDependencies } from "../sca.js";
import { scanSemgrep } from "../semgrep.js";
import { runRustEngine, mergeRustFindings } from "../rust-engine.js";
import type { FindingResult } from "../types.js";
import type { AnalysisEngine } from "./engine.js";
import { isSafeRelativePath } from "./paths.js";

/**
 * Identity of a finding for deduplication: same file and line, and the same
 * rule or the same weakness (CWE). Semgrep and the regex rules often flag the
 * same line under different rule ids, so matching on CWE too avoids reporting
 * one issue twice while keeping genuinely distinct findings.
 */
export function isDuplicateFinding(candidate: FindingResult, existing: FindingResult[]): boolean {
  return existing.some(
    (f) =>
      f.filePath === candidate.filePath &&
      f.line === candidate.line &&
      ((f.ruleId !== undefined && f.ruleId === candidate.ruleId) ||
        (f.cwe !== undefined && f.cwe === candidate.cwe)),
  );
}

// ── Core engines: deterministic, offline, run in this order ─────────────────

const secrets: AnalysisEngine = {
  id: "secrets",
  phase: "core",
  run: (ctx) => {
    const found = scanSecrets(ctx.parsed.addedLines);
    return (t) => ({ ...t, secrets: [...t.secrets, ...found] });
  },
};

const dependencies: AnalysisEngine = {
  id: "dependencies",
  phase: "core",
  run: (ctx) => {
    const found = scanDependencies(ctx.parsed);
    return (t) => ({ ...t, dependencies: [...t.dependencies, ...found] });
  },
};

const sast: AnalysisEngine = {
  id: "sast",
  phase: "core",
  run: (ctx) => {
    const found = runSastRules(ctx.parsed.addedLines);
    return (t) => ({ ...t, findings: [...t.findings, ...found] });
  },
};

const sensitiveFiles: AnalysisEngine = {
  id: "sensitive_files",
  phase: "core",
  run: (ctx) => {
    const found = flagSensitiveFiles(ctx.parsed.files);
    return (t) => ({ ...t, findings: [...t.findings, ...found] });
  },
};

// ── Intel engines: network/subprocess, concurrent, fail open ────────────────
// Their contributions are applied in this order.

/** Enriches the dependencies added in the PR with known CVEs. */
const osv: AnalysisEngine = {
  id: "osv",
  phase: "intel",
  run: async (ctx, setStatus) => {
    const enriched = await enrichDependenciesWithOsv(ctx.core.dependencies, {
      ...ctx.options,
      onStatus: setStatus,
    });
    // Replaces the core list entry for entry (same packages, now enriched).
    return (t) => ({ ...t, dependencies: enriched });
  },
};

/** Full-tree dependency scan; merges without duplicating a CVE. */
const sca: AnalysisEngine = {
  id: "sca",
  phase: "intel",
  run: async (ctx, setStatus) => {
    const found = await runSca({ ...ctx.options.sca, onStatus: setStatus });
    return (t) => ({ ...t, dependencies: mergeScaIntoDependencies(t.dependencies, found) });
  },
};

/** Taint analysis; its richer finding supersedes a regex one for the same issue. */
const rust: AnalysisEngine = {
  id: "rust",
  phase: "intel",
  run: async (ctx, setStatus) => {
    const found = await runRustEngine(ctx.files, { ...ctx.options.rust, onStatus: setStatus });
    return (t) => ({ ...t, findings: mergeRustFindings(t.findings, found) });
  },
};

/** Semantic SAST; adds what the other engines did not already report. */
const semgrep: AnalysisEngine = {
  id: "semgrep",
  phase: "intel",
  run: async (ctx, setStatus) => {
    const opts = ctx.options.semgrep ?? {};
    // A checkout given by the caller (cwd), else the PR's files on disk —
    // scanned as a whole: one argv entry per file overflows the OS
    // command-line limit on large PRs.
    const cwd = opts.cwd ?? ctx.scratchDir;
    const targets = opts.cwd
      ? ctx.files.map((f) => f.path).filter(isSafeRelativePath)
      : ["."];
    const found = await scanSemgrep(ctx.files.length ? targets : [], {
      ...opts,
      ...(cwd ? { cwd } : {}),
      onStatus: setStatus,
    });
    return (t) => {
      const findings = [...t.findings];
      for (const f of found) if (!isDuplicateFinding(f, findings)) findings.push(f);
      return { ...t, findings };
    };
  },
};

/**
 * Every engine, in pipeline order (core first, then intel in merge order).
 * Keep in sync with ENGINE_IDS in @codegate/shared — enforced by a test.
 */
export const ENGINES: readonly AnalysisEngine[] = [
  secrets,
  dependencies,
  sast,
  sensitiveFiles,
  osv,
  sca,
  rust,
  semgrep,
];

export function getEngine(id: EngineId): AnalysisEngine | undefined {
  return ENGINES.find((e) => e.id === id);
}
