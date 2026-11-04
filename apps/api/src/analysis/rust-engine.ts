import { spawn } from "node:child_process";
import type { ParsedDiff } from "./diff.js";
import type { Confidence, FindingResult } from "./types.js";
import type { FindingType, Severity } from "@codegate/shared";

/**
 * Adapter for the Rust semantic scan engine (services/scan-engine).
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
 * stdout. Resolves `"[]"` on ANY failure (missing binary, non-zero exit,
 * timeout) — this is the fail-open boundary.
 */
const spawnRunner: EngineRunner = (manifest, { binaryPath, timeoutMs }) =>
  new Promise((resolve) => {
    let settled = false;
    const done = (out: string) => {
      if (!settled) {
        settled = true;
        resolve(out);
      }
    };

    let child;
    try {
      child = spawn(binaryPath, ["--stdin"], { stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      return done("[]");
    }

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      done("[]");
    }, timeoutMs);

    let stdout = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.on("error", () => {
      clearTimeout(timer);
      done("[]");
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      done(code === 0 ? stdout : "[]");
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

function parseOutput(stdout: string): FindingResult[] {
  try {
    const data = JSON.parse(stdout);
    if (!Array.isArray(data)) return [];
    return data.map(toFinding).filter((f): f is FindingResult => f !== null);
  } catch {
    return [];
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
    let lines = byFile.get(file);
    if (!lines) {
      lines = new Map();
      byFile.set(file, lines);
    }
    lines.set(line, content);
  }

  const files: EngineFile[] = [];
  for (const [path, lines] of byFile) {
    const max = Math.max(...lines.keys());
    const buffer: string[] = new Array(max).fill("");
    for (const [line, content] of lines) buffer[line - 1] = content;
    files.push({ path, content: buffer.join("\n") });
  }
  return files;
}

/** Run the engine over a set of files. Always resolves (fails open to `[]`). */
export async function runRustEngine(
  files: EngineFile[],
  opts: RustEngineOptions = {},
): Promise<FindingResult[]> {
  if (!isEnabled(opts) || files.length === 0) return [];
  const runner = opts.runner ?? spawnRunner;
  const manifest = JSON.stringify({ files });
  try {
    const stdout = await runner(manifest, {
      binaryPath: resolveBinary(opts),
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
    return parseOutput(stdout);
  } catch {
    return [];
  }
}

/**
 * Classify a finding into a vulnerability family so the Rust engine's richer
 * result (CWE/OWASP/confidence) can supersede a regex finding for the SAME
 * issue on the same line, instead of both being reported.
 */
function family(f: FindingResult): string {
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
