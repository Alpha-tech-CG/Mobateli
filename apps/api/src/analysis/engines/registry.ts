import type { EngineId } from "@codegate/shared";
import { refineSecrets, scanSecrets } from "../secret-scanner.js";
import { scanDependencies } from "../dependency-scanner.js";
import { refutedByContext, runSastRules } from "../sast.js";
import { analyzeConfig } from "../config-rules.js";
import { detectPromptInjection } from "../prompt-injection.js";
import { enrichDependencies } from "../dependency-intel.js";
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

/**
 * The in-process Rust engine (WebAssembly) detects secrets when available;
 * the TypeScript scanner is the fallback.
 */
const secrets: AnalysisEngine = {
  id: "secrets",
  phase: "core",
  run: (ctx) => {
    const raw = ctx.ast()?.secrets ?? scanSecrets(ctx.parsed.addedLines);
    // Same false-positive rules whichever engine found them.
    const byLine = new Map(ctx.parsed.addedLines.map((l) => [`${l.file}:${l.line}`, l.content]));
    const { secrets: found, samples } = refineSecrets(raw, (file, line) => byLine.get(`${file}:${line}`));
    const notes: FindingResult[] = samples.map((s) => ({
      type: "secret",
      severity: "info",
      title: "Valeurs d'exemple dans un fichier de test",
      description: `${s.count} valeur(s) au format de secret (${s.types.join(", ")}) dans un fichier de test ou d'exemple : ce sont des données de test, sans impact sur le score. Vérifiez qu'aucune n'est une vraie clé.`,
      filePath: s.file,
      ruleId: "secrets/test-sample",
      confidence: "low",
    }));
    return (t) => ({ ...t, secrets: [...t.secrets, ...found], findings: [...t.findings, ...notes] });
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

/**
 * Code rules: the Rust engine works on the syntax tree of the JS/TS files it
 * could parse; every other file (other languages, unparsable code, no engine)
 * goes through the TypeScript line rules.
 */
const sast: AnalysisEngine = {
  id: "sast",
  phase: "core",
  run: (ctx) => {
    const ast = ctx.ast();
    const astFiles = new Set(ast?.astFiles ?? []);
    const byLine = new Map(ctx.parsed.addedLines.map((l) => [`${l.file}:${l.line}`, l.content]));
    const found = [
      // Same exclusions as the line rules (comments, literals, constants).
      ...(ast?.findings ?? []).filter((f) => !refutedByContext(f, byLine.get(`${f.filePath}:${f.line}`))),
      ...runSastRules(ctx.parsed.addedLines.filter((l) => !astFiles.has(l.file))),
    ];
    return (t) => ({ ...t, findings: [...t.findings, ...found] });
  },
};

/** Targeted rules for sensitive configuration (.env, compose, CI…). */
const config: AnalysisEngine = {
  id: "config",
  phase: "core",
  run: (ctx) => {
    const found = analyzeConfig(ctx.parsed.addedLines, ctx.parsed.files);
    return (t) => ({ ...t, findings: [...t.findings, ...found] });
  },
};

const promptInjection: AnalysisEngine = {
  id: "prompt_injection",
  phase: "core",
  run: (ctx) => {
    const found = detectPromptInjection(ctx.parsed.addedLines, ctx.parsed.files);
    return (t) => ({ ...t, findings: [...t.findings, ...found] });
  },
};

// ── Intel engines: network/subprocess, concurrent, fail open ────────────────
// Their contributions are applied in this order.

/**
 * Dependency intelligence: known CVEs (OSV), packages that do not exist (names
 * hallucinated by an AI agent), very recent packages, install scripts (npm,
 * PyPI, Go registries). Best effort: a network failure keeps the
 * deterministic score.
 */
const osv: AnalysisEngine = {
  id: "osv",
  phase: "intel",
  run: async (ctx, setStatus) => {
    if (!ctx.core.dependencies.length) {
      setStatus("skipped", "aucune dépendance ajoutée");
      return (t) => t;
    }
    const enriched = await enrichDependencies(
      ctx.core.dependencies,
      ctx.options.fetchImpl ?? fetch,
    );
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
  config,
  promptInjection,
  osv,
  sca,
  rust,
  semgrep,
];

export function getEngine(id: EngineId): AnalysisEngine | undefined {
  return ENGINES.find((e) => e.id === id);
}
