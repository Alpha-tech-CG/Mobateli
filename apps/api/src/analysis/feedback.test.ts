import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff } from "./diff.js";
import { analyzeDiff } from "./analyzer.js";
import { applyFeedback, findingFingerprint, fingerprintAll, ruleQuality } from "./feedback.js";
import { buildPrComment } from "./explainer.js";

const diffFor = (file: string, lines: string[], start = 1) =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -0,0 +${start},${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");

const SQL = 'db.query("SELECT * FROM t WHERE id = " + req.params.id);';

test("fingerprint: stable when the line moves, different when the code changes", () => {
  const a = analyzeDiff(diffFor("a.ts", [SQL]));
  const moved = analyzeDiff(diffFor("a.ts", ["// header", "", SQL], 40));
  const fa = fingerprintAll(a, parseUnifiedDiff(diffFor("a.ts", [SQL])));
  const fm = fingerprintAll(moved, parseUnifiedDiff(diffFor("a.ts", ["// header", "", SQL], 40)));
  assert.equal(moved.findings[0]!.line, 42);
  assert.equal(fa[0], fm[0], "same alert after the line moved");
  const changed = findingFingerprint(a.findings[0]!, 'db.query("SELECT * FROM u WHERE id = " + req.params.id);');
  assert.notEqual(fa[0], changed);
  const otherFile = findingFingerprint({ ...a.findings[0]!, filePath: "b.ts" }, SQL);
  assert.notEqual(fa[0], otherFile);
});

test("feedback: a false positive no longer decides; a confirmed alert is acknowledged", () => {
  const diff = diffFor("a.ts", [SQL, 'const h = crypto.createHash("md5").update(password).digest("hex");']);
  const result = analyzeDiff(diff);
  assert.equal(result.status, "warning");
  const fps = fingerprintAll(result, parseUnifiedDiff(diff));
  const sql = result.findings.findIndex((f) => f.ruleId === "SQL_STRING_CONCAT");
  const hash = result.findings.findIndex((f) => f.ruleId === "WEAK_HASH");

  const none = applyFeedback(result, fps, new Map());
  assert.equal(none.suppressed, 0);
  assert.equal(none.result, result, "unchanged without feedback");

  const both = applyFeedback(result, fps, new Map([[fps[sql]!, "false_positive"], [fps[hash]!, "false_positive"]]));
  assert.equal(both.suppressed, 2);
  assert.equal(both.result.findings.length, 0);
  assert.equal(both.result.status, "passed", "verdict recomputed without the dismissed alerts");
  assert.deepEqual(both.statuses.map((s) => s.status).sort(), ["false_positive", "false_positive"]);

  const confirmed = applyFeedback(result, fps, new Map([[fps[sql]!, "confirmed"]]));
  assert.equal(confirmed.statuses[sql]!.status, "acknowledged");
  assert.equal(confirmed.result.status, result.status, "a confirmed alert still counts");
});

test("feedback: secrets are never suppressed by a finding verdict", () => {
  const diff = diffFor("a.ts", ['const k = "AKIA' + 'Z7Q3MLD2KXW5PRT4";', SQL]);
  const result = analyzeDiff(diff);
  const fps = fingerprintAll(result, parseUnifiedDiff(diff));
  const out = applyFeedback(result, fps, new Map(fps.map((f) => [f, "false_positive" as const])));
  assert.equal(out.result.secrets.length, 1);
  assert.equal(out.result.status, "blocked");
});

test("comment: mentions suppressed alerts and how to report one", () => {
  const md = buildPrComment(
    { riskScore: 0, decision: "allow", status: "passed", findings: [], secrets: [], dependencies: [] },
    { suppressed: 2 },
  );
  assert.match(md, /2 alerte\(s\) masquée\(s\)/);
  assert.match(md, /Signalez-la depuis la page de la PR/);
});

test("ruleQuality: false-positive rate over reviewed alerts only", () => {
  const q = ruleQuality([
    { ruleId: "WEAK_HASH", status: "false_positive", count: 3 },
    { ruleId: "WEAK_HASH", status: "acknowledged", count: 1 },
    { ruleId: "WEAK_HASH", status: "open", count: 6 },
    { ruleId: "RUST-JS-SQLI-TAINT", status: "open", count: 4 },
  ]);
  const weak = q.find((r) => r.ruleId === "WEAK_HASH")!;
  assert.deepEqual(
    { alerts: weak.alerts, fp: weak.falsePositives, ok: weak.confirmed, rate: weak.falsePositiveRate },
    { alerts: 10, fp: 3, ok: 1, rate: 0.75 },
  );
  assert.equal(q.find((r) => r.ruleId === "RUST-JS-SQLI-TAINT")!.falsePositiveRate, null);
  assert.equal(q[0]!.ruleId, "WEAK_HASH", "rules with the most false positives first");
});
