import { spawn } from "node:child_process";
import type { ParsedDiff } from "./diff.js";
import { isMinified } from "./sast.js";
import { describeFailure, type Confidence, type EngineStatusFn, type FindingResult } from "./types.js";
import type { FindingType, Severity } from "@codegate/shared";

/**
 * Adapter for the native Rust taint engine (services/taint-engine), run as a
 * subprocess by the worker. Not to be confused with services/scan-engine, the
 * WebAssembly engine run in-process (analysis/engine).
 *
 * The engine is a separate process — a Rust binary (`codegate-scan`) that does
 * tree-sitter parsing + taint analysis, far beyond the line-by-line regex rules
 * in sast.ts (cahier §7, §8.2, §9.3). This adapter invokes it as a subprocess,
 * feeds it the changed files on stdin as a JSON manifest, and parses its JSON
 * output straight into `FindingResult[]` (the engine emits the exact field
 * names and string values the TS side uses).
 *
 * It follows the same discipline as osv.ts: it is kept out of the synchronous
 * analysis core, it is fully injectable for tests (`runner`), and it FAILS OPEN
 * — if the binary is absent, errors, or times out, it returns `[]` so a missing
 * toolchain never blocks a PR. The binary is optional: CI/prod builds it, but
 * the TS pipeline works without it.
 */

/** One file handed to the engine. */
export interface EngineFile {
  path: string;
  content: string;
}

/** Runs the engine with a manifest on stdin and resolves its raw stdout. */
export type EngineRunner = (
  manifest: string,
  opts: { binaryPath: string; timeoutMs: number },
) => Promise<string>;

export interface RustEngineOptions {
  /** Path to the `codegate-scan` binary. */
  binaryPath?: string;
  /** Hard timeout for the subprocess. */
  timeoutMs?: number;
  /** Injectable runner (tests pass canned stdout; default spawns the binary). */
  runner?: EngineRunner;
  /** Explicit on/off. Defaults to enabled unless CODEGATE_SCAN_DISABLE is set. */
  enabled?: boolean;
  /** Receives whether the engine ran, was skipped, or failed (and why). */
  onStatus?: EngineStatusFn;
}

// Measured: a 1 900-file / 20 MB PR takes ~7 s with the release binary (25 s
// in debug). 5 s silently dropped the engine on every large PR.
const DEFAULT_TIMEOUT_MS = 60_000;
const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);
const VALID_CONFIDENCE: ReadonlySet<string> = new Set(["high", "medium", "low"]);

function resolveBinary(opts: RustEngineOptions): string {
  return opts.binaryPath ?? process.env.CODEGATE_SCAN_BIN ?? "codegate-scan";
}

function isEnabled(opts: RustEngineOptions): boolean {
  if (opts.enabled !== undefined) return opts.enabled;
  return !process.env.CODEGATE_SCAN_DISABLE;
}

/**
 * Default runner: spawn `codegate-scan --stdin`, write the manifest, collect
 * stdout. Rejects with the reason on any failure (missing binary, non-zero
 * exit, timeout); `runRustEngine` is the fail-open boundary and reports it.
 */
const spawnRunner: EngineRunner = (manifest, { binaryPath, timeoutMs }) =>
  new Promise((resolve, reject) => {
    let settled = false;
    const done = (out: string | null) => {
      if (!settled) {
        settled = true;
        if (out === null) reject(new Error("codegate-scan failed"));
        else resolve(out);
      }
    };
    const fail = (err: unknown) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    let child;
    try {
      child = spawn(binaryPath, ["--stdin"], { stdio: ["pipe", "pipe", "ignore"] });
    } catch (err) {
      return fail(err);
    }

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      fail(Object.assign(new Error("timeout"), { killed: true }));
    }, timeoutMs);

    let stdout = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      fail(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) done(stdout);
      else fail(new Error(`code de sortie ${code}`));
    });

    child.stdin.on("error", () => {
      /* broken pipe if the binary died — the close/error handler resolves */
    });
    child.stdin.end(manifest);
  });

/** Coerce one raw JSON object into a `FindingResult`, or `null` if invalid. */
function toFinding(raw: unknown): FindingResult | null {
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.title !== "string" || typeof o.description !== "string") return null;
  if (typeof o.severity !== "string" || !VALID_SEVERITIES.has(o.severity)) return null;

  const finding: FindingResult = {
    type: (typeof o.type === "string" ? o.type : "sast") as FindingType,
    severity: o.severity as Severity,
    title: o.title,
    description: o.description,
  };
  if (typeof o.filePath === "string") finding.filePath = o.filePath;
  if (typeof o.line === "number" && Number.isFinite(o.line)) finding.line = o.line;
  if (typeof o.ruleId === "string") finding.ruleId = o.ruleId;
  if (typeof o.remediation === "string") finding.remediation = o.remediation;
  if (typeof o.cwe === "string") finding.cwe = o.cwe;
  if (typeof o.owasp === "string") finding.owasp = o.owasp;
  if (typeof o.confidence === "string" && VALID_CONFIDENCE.has(o.confidence)) {
    finding.confidence = o.confidence as Confidence;
  }
  return finding;
}

/** Parsed findings, or null when the output is not a JSON array. */
function parseOutput(stdout: string): FindingResult[] | null {
  try {
    const data = JSON.parse(stdout);
    if (!Array.isArray(data)) return null;
    return data.map(toFinding).filter((f): f is FindingResult => f !== null);
  } catch {
    return null;
  }
}

/**
 * Rebuild file contents from a parsed diff, placing each added line at its real
 * line number (gaps filled with blank lines). This keeps the engine's reported
 * line numbers aligned with the actual file, and gives the taint analysis the
 * added code to work on — the same "added lines" model the regex rules use.
 */
export function filesFromDiff(parsed: ParsedDiff): EngineFile[] {
  const byFile = new Map<string, Map<number, string>>();
  for (const { file, line, content } of parsed.addedLines) {
    if (isMinified(file)) continue; // generated bundles: see sast.ts
    let lines = byFile.get(file);
    if (!lines) {
      lines = new Map();
      byFile.set(file, lines);
    }
    lines.set(line, content);
  }

  const files: EngineFile[] = [];
  for (const [path, lines] of byFile) {
    // Not `Math.max(...lines.keys())`: spreading ~100k+ arguments overflows
    // the call stack, which crashed the whole analysis of a PR adding a huge
    // file (PR left without a verdict).
    let max = 0;
    for (const line of lines.keys()) if (line > max) max = line;
    const buffer: string[] = new Array(max).fill("");
    for (const [line, content] of lines) buffer[line - 1] = content;
    files.push({ path, content: buffer.join("\n") });
  }
  return files;
}

/** Run the engine over a set of files. Always resolves (fails open to `[]`). */
/** Outcome of one engine run: `ran` is true only for a complete, valid run. */
export interface RustRun {
  findings: FindingResult[];
  ran: boolean;
}

export async function runRustEngineDetailed(
  files: EngineFile[],
  opts: RustEngineOptions = {},
): Promise<RustRun> {
  if (!isEnabled(opts)) {
    opts.onStatus?.("skipped", "désactivé");
    return { findings: [], ran: false };
  }
  if (files.length === 0) {
    opts.onStatus?.("skipped", "aucun fichier");
    return { findings: [], ran: false };
  }
  const runner = opts.runner ?? spawnRunner;
  const manifest = JSON.stringify({ files });
  try {
    const stdout = await runner(manifest, {
      binaryPath: resolveBinary(opts),
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
    const findings = parseOutput(stdout);
    if (findings === null) {
      opts.onStatus?.("failed", "sortie illisible");
      return { findings: [], ran: false };
    }
    opts.onStatus?.("ok");
    return { findings, ran: true };
  } catch (err) {
    opts.onStatus?.("failed", describeFailure(err));
    return { findings: [], ran: false };
  }
}

export async function runRustEngine(
  files: EngineFile[],
  opts: RustEngineOptions = {},
): Promise<FindingResult[]> {
  return (await runRustEngineDetailed(files, opts)).findings;
}

/** Languages the engine parses (keep in sync with services/taint-engine/src/lang.rs). */
const ENGINE_LANGUAGE = /\.(js|jsx|mjs|cjs|ts|mts|cts|tsx|py|pyi)$/i;

/**
 * Regex rules that only APPROXIMATE a dataflow question ("does user input
 * reach this sink?") that the taint engine answers properly.
 */
const TAINT_APPROXIMATIONS = new Set([
  // eval of something the engine sees no untrusted input reaching (a startup
  // file, a constant) is a smell, not a confirmed code injection.
  "DANGEROUS_EVAL",
  "SQL_STRING_CONCAT",
  "CHILD_PROCESS_INJECTION",
  "PYTHON_SHELL_INJECTION",
  "PATH_TRAVERSAL",
  "SSRF_REQUEST",
]);

/**
 * After a complete engine run, a taint-approximating regex finding that the
 * engine did not confirm (no engine finding of that family on that line) is
 * downgraded to low confidence: still reported — the input may come from a
 * source the engine does not model (a DB value, a message queue) — but it no
 * longer weighs like a confirmed injection. Never applied when the engine did
 * not run (timeout, missing binary): that must not weaken the regex net.
 */
export function corroborate(
  findings: FindingResult[],
  engineFindings: FindingResult[],
  ran: boolean,
): FindingResult[] {
  if (!ran) return findings;
  const confirmed = new Set(engineFindings.map(dedupeKey));
  return findings.map((f) =>
    f.ruleId !== undefined &&
    TAINT_APPROXIMATIONS.has(f.ruleId) &&
    ENGINE_LANGUAGE.test(f.filePath ?? "") &&
    !confirmed.has(dedupeKey(f))
      ? { ...f, confidence: "low" }
      : f,
  );
}

/**
 * Classify a finding into a vulnerability family so the Rust engine's richer
 * result (CWE/OWASP/confidence) can supersede a regex finding for the SAME
 * issue on the same line, instead of both being reported.
 */
function family(f: FindingResult): string {
  // The CWE is authoritative; text heuristics only for findings without one
  // (a code-injection title mentioning "exec()" is not a command injection).
  const byCwe: Record<string, string> = {
    "CWE-89": "sqli",
    "CWE-78": "cmdi",
    "CWE-77": "cmdi",
    "CWE-94": "code",
    "CWE-95": "code",
    "CWE-22": "path",
    "CWE-918": "ssrf",
    "CWE-79": "xss",
    "CWE-943": "nosql",
    "CWE-601": "redirect",
  };
  const cwe = f.cwe?.match(/CWE-\d+/)?.[0];
  if (cwe && byCwe[cwe]) return byCwe[cwe];
  const s = `${f.ruleId ?? ""} ${f.cwe ?? ""} ${f.title}`.toUpperCase();
  if (s.includes("CWE-89") || s.includes("SQL")) return "sqli";
  if (
    s.includes("CWE-78") ||
    s.includes("COMMAND") ||
    s.includes("CHILD_PROCESS") ||
    s.includes("EXEC")
  )
    return "cmdi";
  if (s.includes("CWE-94") || s.includes("EVAL") || s.includes("CODE INJECT")) return "code";
  if (s.includes("CWE-22")) return "path";
  if (s.includes("CWE-918")) return "ssrf";
  if (s.includes("CWE-79")) return "xss";
  return `${f.ruleId ?? f.title}`;
}

function dedupeKey(f: FindingResult): string {
  return `${f.filePath ?? ""}|${f.line ?? ""}|${family(f)}`;
}

/**
 * Merge engine findings into the base findings, de-duplicating by
 * file+line+family. The Rust finding wins on a collision (it carries
 * CWE/OWASP/confidence); base findings with no engine equivalent are kept.
 */
export function mergeRustFindings(
  base: FindingResult[],
  engine: FindingResult[],
): FindingResult[] {
  const byKey = new Map<string, FindingResult>();
  for (const f of engine) byKey.set(dedupeKey(f), f);
  const merged = [...engine];
  for (const f of base) {
    if (!byKey.has(dedupeKey(f))) merged.push(f);
  }
  return merged;
}
