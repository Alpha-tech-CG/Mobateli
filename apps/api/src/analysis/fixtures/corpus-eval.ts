import { analyzeFiles } from "../analyzer.js";
import type { FindingResult, SecretResult } from "../types.js";
import { CORPUS, type CorpusCase, type ExpectedAlert } from "./corpus.js";

/**
 * Scores the analyser against the labelled corpus. Offline and deterministic
 * (core engines only: secrets, code rules, config, prompt injection).
 */

export interface Alert {
  kind: "secret" | "finding";
  rule: string;
  title: string;
  severity: string;
  file: string;
  line?: number;
}

export interface CaseResult {
  id: string;
  category: CorpusCase["category"];
  truePositives: Alert[];
  falsePositives: Alert[];
  missed: ExpectedAlert[];
}

export interface CorpusReport {
  cases: CaseResult[];
  totals: {
    alerts: number;
    truePositives: number;
    falsePositives: number;
    missed: number;
    /** Share of reported alerts that are false, in %. */
    falsePositiveRate: number;
    /** Share of expected vulnerabilities found, in %. */
    recall: number;
  };
  byCategory: Record<string, { truePositives: number; falsePositives: number; missed: number }>;
}

/** Stable key of an alert, used for the known-issues baseline. */
export const alertKey = (caseId: string, a: Pick<Alert, "rule" | "file" | "line">) =>
  `${caseId}|${a.rule}|${a.file}${a.line ? `:${a.line}` : ""}`;

function toAlerts(secrets: SecretResult[], findings: FindingResult[]): Alert[] {
  const out: Alert[] = [];
  for (const s of secrets) {
    const m = /^(.*):(\d+)$/.exec(s.location);
    out.push({
      kind: "secret",
      rule: s.secretType,
      title: s.secretType,
      severity: s.severity,
      file: m ? m[1]! : s.location,
      ...(m ? { line: Number(m[2]) } : {}),
    });
  }
  // Informational notes never count as alerts (they don't touch the score).
  for (const f of findings) {
    if (f.severity === "info") continue;
    out.push({
      kind: "finding",
      rule: f.ruleId ?? f.title,
      title: f.title,
      severity: f.severity,
      file: f.filePath ?? "",
      ...(f.line ? { line: f.line } : {}),
    });
  }
  return out;
}

function matches(e: ExpectedAlert, a: Alert): boolean {
  if (e.kind !== a.kind || e.file !== a.file) return false;
  if (e.line !== undefined && a.line !== undefined && e.line !== a.line) return false;
  return a.rule === e.rule || a.title.includes(e.rule);
}

export function evaluateCase(c: CorpusCase): CaseResult {
  const r = analyzeFiles(c.files);
  const alerts = toAlerts(r.secrets, r.findings);
  const used = new Set<number>();
  const missed: ExpectedAlert[] = [];
  for (const e of c.expect) {
    const i = alerts.findIndex((a, k) => !used.has(k) && matches(e, a));
    if (i === -1) missed.push(e);
    else used.add(i);
  }
  return {
    id: c.id,
    category: c.category,
    truePositives: alerts.filter((_, k) => used.has(k)),
    falsePositives: alerts.filter((_, k) => !used.has(k)),
    missed,
  };
}

export function evaluateCorpus(cases: CorpusCase[] = CORPUS): CorpusReport {
  const results = cases.map(evaluateCase);
  const byCategory: CorpusReport["byCategory"] = {};
  let tp = 0;
  let fp = 0;
  let miss = 0;
  for (const r of results) {
    const c = (byCategory[r.category] ??= { truePositives: 0, falsePositives: 0, missed: 0 });
    c.truePositives += r.truePositives.length;
    c.falsePositives += r.falsePositives.length;
    c.missed += r.missed.length;
    tp += r.truePositives.length;
    fp += r.falsePositives.length;
    miss += r.missed.length;
  }
  const pct = (n: number, d: number) => (d ? Math.round((n / d) * 1000) / 10 : 0);
  return {
    cases: results,
    totals: {
      alerts: tp + fp,
      truePositives: tp,
      falsePositives: fp,
      missed: miss,
      falsePositiveRate: pct(fp, tp + fp),
      recall: tp + miss ? pct(tp, tp + miss) : 100,
    },
    byCategory,
  };
}

/** Human-readable report (CLI and test output). */
export function formatCorpusReport(r: CorpusReport): string {
  const lines = [
    `Corpus : ${r.cases.length} cas, ${r.totals.alerts} alerte(s) émise(s)`,
    `  Faux positifs : ${r.totals.falsePositives} (${r.totals.falsePositiveRate} % des alertes)`,
    `  Vulnérabilités trouvées : ${r.totals.truePositives}, manquées : ${r.totals.missed} (rappel ${r.totals.recall} %)`,
    "",
    "Par catégorie :",
    ...Object.entries(r.byCategory).map(
      ([k, v]) => `  ${k.padEnd(18)} vrais ${v.truePositives}  faux ${v.falsePositives}  manqués ${v.missed}`,
    ),
  ];
  const fps = r.cases.flatMap((c) => c.falsePositives.map((a) => `  ✗ ${c.id} : ${a.rule} (${a.severity}) ${a.file}${a.line ? `:${a.line}` : ""}`));
  const misses = r.cases.flatMap((c) => c.missed.map((e) => `  ○ ${c.id} : ${e.rule} ${e.file}${e.line ? `:${e.line}` : ""}`));
  if (fps.length) lines.push("", "Faux positifs :", ...fps);
  if (misses.length) lines.push("", "Vulnérabilités manquées :", ...misses);
  return lines.join("\n");
}
