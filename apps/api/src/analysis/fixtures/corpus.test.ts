import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { alertKey, evaluateCorpus, formatCorpusReport } from "./corpus-eval.js";
import { CORPUS } from "./corpus.js";

const baseline = JSON.parse(readFileSync(new URL("./corpus-baseline.json", import.meta.url), "utf8")) as {
  knownFalsePositives: string[];
  knownMisses: string[];
};

test("corpus cases are well formed", () => {
  const ids = CORPUS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "case ids are unique");
  for (const c of CORPUS) {
    const paths = new Set(c.files.map((f) => f.path));
    for (const e of c.expect) assert.ok(paths.has(e.file), `${c.id}: expected alert on a file of the case (${e.file})`);
  }
  // Both sides are covered: what must be found, and what must stay silent.
  assert.ok(CORPUS.filter((c) => c.expect.length).length >= 10);
  assert.ok(CORPUS.filter((c) => !c.expect.length).length >= 10);
});

/**
 * The false-positive ratchet: any new false positive or newly missed
 * vulnerability fails the build; fixing a known one requires removing it from
 * the baseline, so the measured quality can only improve.
 */
test("no new false positive and no newly missed vulnerability on the corpus", (t) => {
  const report = evaluateCorpus();
  t.diagnostic(formatCorpusReport(report));
  const fps = report.cases.flatMap((c) => c.falsePositives.map((a) => alertKey(c.id, a)));
  const misses = report.cases.flatMap((c) => c.missed.map((e) => alertKey(c.id, e)));

  const newFps = fps.filter((k) => !baseline.knownFalsePositives.includes(k));
  const newMisses = misses.filter((k) => !baseline.knownMisses.includes(k));
  assert.deepEqual(newFps, [], "nouveaux faux positifs (corrigez le moteur, ou étiquetez le cas)");
  assert.deepEqual(newMisses, [], "vulnérabilités désormais manquées");

  const fixedFps = baseline.knownFalsePositives.filter((k) => !fps.includes(k));
  const fixedMisses = baseline.knownMisses.filter((k) => !misses.includes(k));
  assert.deepEqual(
    [...fixedFps, ...fixedMisses],
    [],
    "corrigés : retirez-les de corpus-baseline.json (pnpm --filter @codegate/api corpus --update-baseline)",
  );
});
