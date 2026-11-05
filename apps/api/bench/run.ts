/**
 * Benchmark de précision / rappel sur le golden dataset (bench/golden).
 *
 *   pnpm --filter @codegate/api bench                      # moteur déterministe seul
 *   pnpm --filter @codegate/api bench -- --engines core,rust,semgrep
 *   pnpm --filter @codegate/api bench -- --check           # échoue si régression vs baseline
 *   pnpm --filter @codegate/api bench -- --update-baseline # réécrit la baseline
 *   pnpm --filter @codegate/api bench -- --verbose         # liste chaque FP / FN
 *   pnpm --filter @codegate/api bench -- --dataset holdout # autre jeu de cas (bench/<nom>)
 *
 * Chaque ligne annotée `VULN: <CAT>` doit être signalée (sinon FN) ; toute
 * alerte ailleurs est un FP. Voir bench/golden/README.md.
 */
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeDiff, analyzeDiffWithIntel } from "../src/analysis/analyzer.js";
import type { AnalysisResult } from "../src/analysis/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DATASETS = ["golden", "holdout"];
const BASELINE = join(HERE, "baseline.json");
const REPO = resolve(HERE, "../../..");

// ---- Annotations ------------------------------------------------------------

const MARKER = /\s*(?:\/\/|#)\s*(VULN|SAFE|ALSO):\s*([A-Z]+)\s*$/;
const SPLIT = /«\+»/g;

export interface Expectation {
  file: string;
  line: number;
  /** Other lines of the same statement (multi-line call) — see `ALSO`. */
  alsoLines?: number[];
  kind: "VULN" | "SAFE";
  category: string;
  /** For DEP: the package name on that line. */
  pkg?: string | undefined;
}

interface GoldenFile {
  path: string; // relative to golden root, forward slashes
  content: string; // markers stripped, secrets joined
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return walk(full);
    return name === "README.md" ? [] : [full];
  });
}

export function loadGolden(root = join(HERE, "golden")): { files: GoldenFile[]; expectations: Expectation[] } {
  const files: GoldenFile[] = [];
  const expectations: Expectation[] = [];
  const also: { file: string; line: number; category: string }[] = [];
  for (const full of walk(root).sort()) {
    const path = relative(root, full).split("\\").join("/");
    const lines = readFileSync(full, "utf8").replace(/\r\n/g, "\n").split("\n");
    const clean = lines.map((raw, i) => {
      const m = raw.match(MARKER);
      const content = (m ? raw.slice(0, m.index) : raw).replace(SPLIT, "");
      if (m?.[1] === "ALSO") {
        also.push({ file: path, line: i + 1, category: m[2]! });
      } else if (m) {
        const exp: Expectation = { file: path, line: i + 1, kind: m[1] as "VULN" | "SAFE", category: m[2]! };
        if (exp.category === "DEP") exp.pkg = content.match(/^\s*"([^"]+)"/)?.[1];
        expectations.push(exp);
      }
      return content;
    });
    files.push({ path, content: clean.join("\n") });
  }
  // An `ALSO` line belongs to the nearest VULN of the same category in its file.
  for (const a of also) {
    const owner = expectations
      .filter((e) => e.kind === "VULN" && e.file === a.file && e.category === a.category)
      .sort((x, y) => Math.abs(x.line - a.line) - Math.abs(y.line - a.line))[0];
    if (!owner) throw new Error(`ALSO sans VULN correspondant : ${a.file}:${a.line}`);
    (owner.alsoLines ??= []).push(a.line);
  }
  return { files, expectations };
}

function toDiff(files: GoldenFile[]): string {
  return files
    .map(({ path, content }) => {
      const lines = content.split("\n");
      return [
        `diff --git a/${path} b/${path}`,
        "--- /dev/null",
        `+++ b/${path}`,
        `@@ -0,0 +1,${lines.length} @@`,
        ...lines.map((l) => `+${l}`),
      ].join("\n");
    })
    .join("\n");
}

// ---- Normalisation des alertes ----------------------------------------------

const CWE_TO_CAT: Record<string, string> = {
  "CWE-89": "SQLI",
  "CWE-78": "CMDI",
  "CWE-77": "CMDI",
  "CWE-94": "CODEI",
  "CWE-95": "CODEI",
  "CWE-79": "XSS",
  "CWE-22": "PATH",
  "CWE-23": "PATH",
  "CWE-918": "SSRF",
  "CWE-502": "DESER",
  "CWE-327": "HASH",
  "CWE-328": "HASH",
  "CWE-916": "HASH",
  "CWE-338": "RANDOM",
  "CWE-330": "RANDOM",
  "CWE-347": "JWT",
  "CWE-942": "CORS",
  "CWE-295": "TLS",
  "CWE-943": "NOSQL",
  "CWE-601": "REDIRECT",
};

export interface Alert {
  file: string;
  line?: number | undefined;
  category: string;
  source: string; // rule id / secret type / package
  confidence: string;
}

export function alertsFrom(result: AnalysisResult): Alert[] {
  const alerts: Alert[] = [];
  for (const f of result.findings) {
    const cwe = f.cwe?.match(/CWE-\d+/)?.[0];
    alerts.push({
      // Semgrep reports native (backslash) paths on Windows.
      file: (f.filePath ?? "").split("\\").join("/"),
      line: f.line,
      category: (cwe && CWE_TO_CAT[cwe]) ?? (f.ruleId === "SENSITIVE_FILE_CHANGED" ? "CONFIG" : `OTHER:${cwe ?? f.ruleId}`),
      source: f.ruleId ?? f.title,
      confidence: f.confidence ?? "medium",
    });
  }
  for (const s of result.secrets) {
    const idx = s.location.lastIndexOf(":");
    alerts.push({
      file: s.location.slice(0, idx),
      line: Number(s.location.slice(idx + 1)),
      category: "SECRET",
      source: s.secretType,
      confidence: s.confidence ?? "medium",
    });
  }
  for (const d of result.dependencies) {
    if (d.riskLevel !== "high" && d.riskLevel !== "critical") continue;
    alerts.push({ file: "", category: "DEP", source: d.name, confidence: "high" });
  }
  return alerts;
}

// ---- Scoring ----------------------------------------------------------------

export interface CategoryScore {
  tp: number;
  fp: number;
  fn: number;
  /** SAFE lines correctly left alone. */
  tn: number;
}

export interface Score {
  byCategory: Record<string, CategoryScore>;
  falsePositives: Alert[];
  falseNegatives: Expectation[];
  /** Alerts with no line (e.g. sensitive-file notices) — informational only. */
  unscored: Alert[];
}

function matches(e: Expectation, a: Alert): boolean {
  if (e.category !== a.category) return false;
  if (e.category === "DEP") return e.pkg === a.source;
  return e.file === a.file && a.line !== undefined && (e.line === a.line || !!e.alsoLines?.includes(a.line));
}

export function score(expectations: Expectation[], alerts: Alert[], minConfidence: "low" | "medium" = "low"): Score {
  const rank = { low: 0, medium: 1, high: 2 } as Record<string, number>;
  const kept = alerts.filter((a) => (rank[a.confidence] ?? 1) >= rank[minConfidence]!);
  const unscored = kept.filter((a) => a.category === "CONFIG");
  const scored = kept.filter((a) => a.category !== "CONFIG");

  const byCategory: Record<string, CategoryScore> = {};
  const cat = (c: string) => (byCategory[c] ??= { tp: 0, fp: 0, fn: 0, tn: 0 });

  const vulns = expectations.filter((e) => e.kind === "VULN");
  const matched = new Set<Alert>();
  const falseNegatives: Expectation[] = [];
  for (const e of vulns) {
    const hits = scored.filter((a) => matches(e, a));
    if (hits.length) {
      cat(e.category).tp++;
      hits.forEach((h) => matched.add(h));
    } else {
      cat(e.category).fn++;
      falseNegatives.push(e);
    }
  }

  // Several engines may flag the same wrong line: count it once.
  const falsePositives: Alert[] = [];
  const fpKeys = new Set<string>();
  for (const a of scored) {
    if (matched.has(a)) continue;
    const key = `${a.category}|${a.file}|${a.line ?? a.source}`;
    if (fpKeys.has(key)) continue;
    fpKeys.add(key);
    cat(a.category).fp++;
    falsePositives.push(a);
  }

  for (const e of expectations.filter((x) => x.kind === "SAFE")) {
    if (!falsePositives.some((a) => matches(e, a))) cat(e.category).tn++;
  }

  return { byCategory, falsePositives, falseNegatives, unscored };
}

export function totals(s: Score): CategoryScore {
  return Object.values(s.byCategory).reduce(
    (acc, c) => ({ tp: acc.tp + c.tp, fp: acc.fp + c.fp, fn: acc.fn + c.fn, tn: acc.tn + c.tn }),
    { tp: 0, fp: 0, fn: 0, tn: 0 },
  );
}

const ratio = (a: number, b: number) => (b === 0 ? 1 : a / b);
export const precision = (c: CategoryScore) => ratio(c.tp, c.tp + c.fp);
export const recall = (c: CategoryScore) => ratio(c.tp, c.tp + c.fn);
export const f1 = (c: CategoryScore) => {
  const p = precision(c);
  const r = recall(c);
  return p + r === 0 ? 0 : (2 * p * r) / (p + r);
};

// ---- Exécution des moteurs --------------------------------------------------

async function analyze(files: GoldenFile[], engines: Set<string>): Promise<AnalysisResult> {
  const diff = toDiff(files);
  if (!engines.has("rust") && !engines.has("semgrep")) return analyzeDiff(diff);

  // Semgrep reads files from disk: materialise the stripped dataset.
  const work = mkdtempSync(join(tmpdir(), "codegate-bench-"));
  try {
    for (const f of files) {
      const dest = join(work, f.path);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, f.content);
    }
    const exe = process.platform === "win32" ? "codegate-scan.exe" : "codegate-scan";
    return await analyzeDiffWithIntel(diff, {
      // OSV is network-bound: disabled so the benchmark is reproducible.
      fetchImpl: () => Promise.reject(new Error("offline")),
      rust: engines.has("rust")
        ? { binaryPath: process.env.CODEGATE_SCAN_BIN ?? join(REPO, "services/scan-engine/target/release", exe), timeoutMs: 30_000 }
        : { enabled: false },
      semgrep: engines.has("semgrep")
        ? { cwd: work, timeoutMs: 300_000, ...(process.env.SEMGREP_CONFIG ? { config: process.env.SEMGREP_CONFIG } : {}) }
        : { runner: async () => "{}" },
    });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// ---- Rapport ----------------------------------------------------------------

const pct = (x: number) => `${(x * 100).toFixed(0).padStart(3)}%`;

function report(title: string, s: Score, verbose: boolean): void {
  console.log(`\n## ${title}\n`);
  console.log("catégorie   TP  FP  FN  TN   précision  rappel   F1");
  for (const [name, c] of Object.entries(s.byCategory).sort()) {
    console.log(
      `${name.padEnd(10)} ${String(c.tp).padStart(3)} ${String(c.fp).padStart(3)} ${String(c.fn).padStart(3)} ${String(c.tn).padStart(3)}     ${pct(precision(c))}     ${pct(recall(c))}  ${pct(f1(c))}`,
    );
  }
  const t = totals(s);
  console.log(
    `${"TOTAL".padEnd(10)} ${String(t.tp).padStart(3)} ${String(t.fp).padStart(3)} ${String(t.fn).padStart(3)} ${String(t.tn).padStart(3)}     ${pct(precision(t))}     ${pct(recall(t))}  ${pct(f1(t))}`,
  );
  if (verbose) {
    console.log("\nFaux négatifs (failles ratées) :");
    for (const e of s.falseNegatives) console.log(`  - [${e.category}] ${e.file}:${e.line}${e.pkg ? ` (${e.pkg})` : ""}`);
    console.log("\nFaux positifs (alertes à tort) :");
    for (const a of s.falsePositives)
      console.log(`  - [${a.category}] ${a.file || "(dépendance)"}${a.line ? `:${a.line}` : ""} ← ${a.source} (${a.confidence})`);
  }
}

interface Baseline {
  engines: string;
  byCategory: Record<string, CategoryScore>;
}

/** A category regresses if it finds fewer true issues or raises more false alarms. */
export function regressions(base: Baseline, s: Score): string[] {
  const out: string[] = [];
  const cats = new Set([...Object.keys(base.byCategory), ...Object.keys(s.byCategory)]);
  for (const c of cats) {
    const b = base.byCategory[c] ?? { tp: 0, fp: 0, fn: 0, tn: 0 };
    const n = s.byCategory[c] ?? { tp: 0, fp: 0, fn: 0, tn: 0 };
    if (n.tp < b.tp) out.push(`${c}: vrais positifs ${b.tp} → ${n.tp}`);
    if (n.fp > b.fp) out.push(`${c}: faux positifs ${b.fp} → ${n.fp}`);
  }
  return out;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const flag = (n: string) => args.includes(n);
  const enginesArg = args[args.indexOf("--engines") + 1];
  const engines = new Set((args.includes("--engines") && enginesArg ? enginesArg : "core").split(","));
  const datasetArg = args[args.indexOf("--dataset") + 1];
  const dataset = args.includes("--dataset") && datasetArg ? datasetArg : "golden";
  if (!DATASETS.includes(dataset)) throw new Error(`jeu de cas inconnu : ${dataset} (${DATASETS.join(", ")})`);
  const sortedEngines = [...engines].sort().join(",");
  // Baselines are per dataset; the golden one keeps its historical key.
  const engineKey = dataset === "golden" ? sortedEngines : `${dataset}:${sortedEngines}`;

  const { files, expectations } = loadGolden(join(HERE, dataset));
  const vulns = expectations.filter((e) => e.kind === "VULN").length;
  console.log(`# CodeGate benchmark — jeu « ${dataset} », moteurs : ${sortedEngines}`);
  console.log(`${files.length} fichiers, ${vulns} failles connues, ${expectations.length - vulns} lignes sûres piégeuses`);

  const result = await analyze(files, engines);
  const alerts = alertsFrom(result);
  const all = score(expectations, alerts, "low");
  const confident = score(expectations, alerts, "medium");

  report("Toutes les alertes", all, flag("--verbose"));
  report("Alertes de confiance moyenne ou haute", confident, false);
  if (all.unscored.length) console.log(`\n(${all.unscored.length} alerte(s) « fichier sensible » sans ligne, non comptées)`);

  if (flag("--json")) {
    writeFileSync(join(HERE, `report.${engineKey.replace(/[,:]/g, "+")}.json`), JSON.stringify({ engines: engineKey, all, confident }, null, 2));
  }

  const baselines: Record<string, Baseline> = (() => {
    try {
      return JSON.parse(readFileSync(BASELINE, "utf8"));
    } catch {
      return {};
    }
  })();

  if (flag("--update-baseline")) {
    baselines[engineKey] = { engines: engineKey, byCategory: all.byCategory };
    writeFileSync(BASELINE, JSON.stringify(baselines, null, 2) + "\n");
    console.log(`\nBaseline « ${engineKey} » mise à jour.`);
  }

  if (flag("--check")) {
    const base = baselines[engineKey];
    if (!base) {
      console.error(`\nPas de baseline pour « ${engineKey} » : lancez --update-baseline.`);
      process.exit(1);
    }
    const reg = regressions(base, all);
    if (reg.length) {
      console.error("\n❌ Régression par rapport à la baseline :");
      reg.forEach((r) => console.error(`  - ${r}`));
      process.exit(1);
    }
    console.log("\n✅ Aucune régression par rapport à la baseline.");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
