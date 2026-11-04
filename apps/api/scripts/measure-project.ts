/**
 * Measure false positives on a real project, without copying its code.
 *
 *   pnpm --filter @codegate/api measure D:/projets/mon-app
 *   pnpm --filter @codegate/api measure D:/projets/mon-app --labels D:/labels/mon-app.json
 *
 * First run: every alert is written to a labels file (outside the analysed
 * project, by default ~/.codegate/labels/<name>.json) with the verdict "?".
 * Open it and replace each "?" by "vrai" or "faux". Next runs compute the
 * false-positive rate on the labelled alerts, add new alerts as "?", and flag
 * a regression when an alert labelled "vrai" is no longer reported.
 *
 * Offline: only the deterministic engines run (no OSV/registry lookups).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { analyzeFiles } from "../src/analysis/analyzer.js";
import { shouldKeep } from "../src/lib/repo-archive.js";
import { isLockfile } from "../src/analysis/lockfiles.js";

type Verdict = "vrai" | "faux" | "?";
interface LabelFile {
  project: string;
  updatedAt: string;
  alerts: Record<string, { verdict: Verdict; severity: string; title: string; note?: string }>;
}

const args = process.argv.slice(2);
const dir = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--labels");
if (!dir) {
  console.error("Usage : measure <dossier du projet> [--labels <fichier.json>]");
  process.exit(2);
}
const root = resolve(dir);
const labelsArg = args.includes("--labels") ? args[args.indexOf("--labels") + 1] : undefined;
const labelsPath = resolve(labelsArg ?? join(homedir(), ".codegate", "labels", `${basename(root)}.json`));

// ── Read the project like a repository scan does ──
const files: { path: string; content: string }[] = [];
const walk = (d: string) => {
  for (const name of readdirSync(d)) {
    if (name === ".git") continue;
    const full = join(d, name);
    const rel = relative(root, full).split("\\").join("/");
    const st = statSync(full);
    if (st.isDirectory()) {
      if (shouldKeep(`${rel}/x.ts`)) walk(full);
      continue;
    }
    if (isLockfile(rel) || !shouldKeep(rel) || st.size > 512 * 1024) continue;
    const content = readFileSync(full, "utf8");
    if (!content.slice(0, 8000).includes("\0")) files.push({ path: rel, content });
  }
};
walk(root);

const result = analyzeFiles(files);
const current = new Map<string, { severity: string; title: string }>();
for (const s of result.secrets) current.set(`secret:${s.secretType}|${s.location}`, { severity: s.severity, title: s.secretType });
for (const f of result.findings) {
  if (f.severity === "info") continue;
  current.set(`${f.ruleId ?? f.title}|${f.filePath ?? ""}${f.line ? `:${f.line}` : ""}`, { severity: f.severity, title: f.title });
}

// ── Merge with the labels ──
const labels: LabelFile = existsSync(labelsPath)
  ? (JSON.parse(readFileSync(labelsPath, "utf8")) as LabelFile)
  : { project: root, updatedAt: "", alerts: {} };
let added = 0;
for (const [key, a] of current) {
  if (!labels.alerts[key]) {
    labels.alerts[key] = { verdict: "?", ...a };
    added++;
  }
}
const vanishedTrue = Object.entries(labels.alerts).filter(([k, v]) => v.verdict === "vrai" && !current.has(k));
const fixedFalse = Object.entries(labels.alerts).filter(([k, v]) => v.verdict === "faux" && !current.has(k));
labels.updatedAt = new Date().toISOString();
mkdirSync(dirname(labelsPath), { recursive: true });
writeFileSync(labelsPath, `${JSON.stringify(labels, null, 2)}\n`);

// ── Report ──
const reported = [...current.keys()].map((k) => labels.alerts[k]!.verdict);
const t = reported.filter((v) => v === "vrai").length;
const f = reported.filter((v) => v === "faux").length;
const u = reported.filter((v) => v === "?").length;
console.log(`Projet : ${root}`);
console.log(`Fichiers analysés : ${files.length} — alertes : ${current.size}`);
console.log(`  vraies : ${t}   fausses : ${f}   à étiqueter : ${u}${added ? ` (dont ${added} nouvelle(s))` : ""}`);
if (t + f) console.log(`  Taux de faux positifs (alertes étiquetées) : ${Math.round((f / (t + f)) * 1000) / 10} %`);
if (fixedFalse.length) console.log(`  ✔ ${fixedFalse.length} faux positif(s) étiqueté(s) ne sont plus signalés.`);
if (vanishedTrue.length) {
  console.log(`  ⚠ RÉGRESSION : ${vanishedTrue.length} vraie(s) alerte(s) ne sont plus signalées :`);
  for (const [k] of vanishedTrue) console.log(`    - ${k}`);
}
const bySeverity: Record<string, { faux: number; total: number }> = {};
for (const [k, a] of current) {
  const v = labels.alerts[k]!.verdict;
  if (v === "?") continue;
  const s = (bySeverity[a.severity] ??= { faux: 0, total: 0 });
  s.total++;
  if (v === "faux") s.faux++;
}
for (const [sev, s] of Object.entries(bySeverity)) console.log(`  ${sev.padEnd(9)} ${s.faux}/${s.total} faux`);
console.log(`Étiquettes : ${labelsPath}${u ? "  → remplacez les \"?\" par \"vrai\" ou \"faux\", puis relancez." : ""}`);
if (vanishedTrue.length) process.exitCode = 1;
