/**
 * Print the analyser's measured quality on the labelled corpus.
 *   pnpm --filter @codegate/api corpus                    → report
 *   pnpm --filter @codegate/api corpus --update-baseline  → accept current gaps
 *   pnpm --filter @codegate/api corpus --json             → machine-readable
 */
import { readFileSync, writeFileSync } from "node:fs";
import { alertKey, evaluateCorpus, formatCorpusReport } from "./corpus-eval.js";

const report = evaluateCorpus();
if (process.argv.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(formatCorpusReport(report));
}

if (process.argv.includes("--update-baseline")) {
  const url = new URL("./corpus-baseline.json", import.meta.url);
  const current = JSON.parse(readFileSync(url, "utf8")) as Record<string, unknown>;
  current.knownFalsePositives = report.cases.flatMap((c) => c.falsePositives.map((a) => alertKey(c.id, a))).sort();
  current.knownMisses = report.cases.flatMap((c) => c.missed.map((e) => alertKey(c.id, e))).sort();
  writeFileSync(url, `${JSON.stringify(current, null, 2)}\n`);
  console.log("\nBaseline mise à jour.");
}
