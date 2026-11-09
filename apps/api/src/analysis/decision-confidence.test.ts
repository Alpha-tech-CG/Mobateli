import { test } from "node:test";
import assert from "node:assert/strict";
import { decide } from "./risk.js";
import { resolveEnforcement } from "./policy.js";
import { buildPrComment } from "./explainer.js";
import type { FindingResult } from "./types.js";

const finding = (over: Partial<FindingResult>): FindingResult => ({
  type: "sast",
  severity: "high",
  title: "t",
  description: "d",
  filePath: "a.ts",
  line: 1,
  ruleId: "R",
  confidence: "high",
  ...over,
});

test("decision: low-confidence findings alone do not warn", () => {
  const r = decide({
    findings: [finding({ confidence: "low" }), finding({ severity: "medium", confidence: "low" })],
    secrets: [],
    dependencies: [],
  });
  assert.equal(r.status, "passed");
  assert.equal(r.decision, "allow");
  assert.ok(r.riskScore > 0, "still scored");
});

test("decision: uncertain alerts stay in observation, however many there are", () => {
  // An alert without proof never decides: ten weak signals are still ten
  // signals to review, not a reason to warn or block.
  const weak = Array.from({ length: 10 }, (_, i) => finding({ line: i, ruleId: `R${i}`, confidence: "low" }));
  const r = decide({ findings: weak, secrets: [], dependencies: [] });
  assert.equal(r.status, "passed");
  assert.ok(r.riskScore > 0, "still scored");
});

test("decision: a likely finding warns; a critical blocks only when verified", () => {
  assert.equal(decide({ findings: [finding({ confidence: "medium" })], secrets: [], dependencies: [] }).status, "warning");
  const at = (confidence: "low" | "medium" | "high") =>
    decide({ findings: [finding({ severity: "critical", confidence })], secrets: [], dependencies: [] }).status;
  assert.equal(at("low"), "passed", "uncertain: observation");
  assert.equal(at("medium"), "warning", "likely: warning + human review");
  assert.equal(at("high"), "blocked", "verified: block");
});

test("decision: an alert without a reliable location never blocks", () => {
  const unlocated: FindingResult = { type: "sast", severity: "critical", title: "t", description: "d", ruleId: "R", confidence: "high" };
  assert.equal(decide({ findings: [unlocated], secrets: [], dependencies: [] }).status, "warning");
});

test("decision: one weak dependency signal never blocks; several critical ones do", () => {
  const dep = (riskLevel: "critical" | "high" | "medium") => ({ ecosystem: "npm", name: "x", version: "1", trustScore: 10, riskLevel });
  assert.equal(decide({ findings: [], secrets: [], dependencies: [dep("medium")] }).status, "passed");
  assert.equal(decide({ findings: [], secrets: [], dependencies: [dep("high")] }).status, "warning");
  assert.equal(decide({ findings: [], secrets: [], dependencies: [dep("critical")] }).status, "blocked");
});

test("policy: a low-confidence high finding does not trip a high threshold", () => {
  const findings = [finding({ confidence: "low" })];
  const result = { findings, secrets: [], dependencies: [], ...decide({ findings, secrets: [], dependencies: [] }) };
  const e = resolveEnforcement(result, "block", [{ action: "block", severityThreshold: "high" }]);
  assert.equal(e.blocked, false);
  assert.equal(e.conclusion, "success");
  const firm = [finding({ confidence: "medium" })];
  const r2 = { findings: firm, secrets: [], dependencies: [], ...decide({ findings: firm, secrets: [], dependencies: [] }) };
  assert.equal(resolveEnforcement(r2, "block", [{ action: "block", severityThreshold: "high" }]).blocked, true);
});

test("comment: uncertain signals are listed apart, in observation", () => {
  const findings = [finding({ title: "ferme", confidence: "high" }), finding({ title: "faible", confidence: "low", line: 2 })];
  const md = buildPrComment({ findings, secrets: [], dependencies: [], ...decide({ findings, secrets: [], dependencies: [] }) });
  assert.match(md, /Problèmes de code \(1\)/);
  assert.match(md, /En observation[^(]*\(1\)/);
});

test("decision: a confirmed high-severity finding blocks, an unconfirmed one warns", () => {
  const proven = finding({ ruleId: "RUST-JS-SQLI-TAINT", confidence: "medium" });
  assert.equal(decide({ findings: [proven], secrets: [], dependencies: [] }).status, "blocked");
  const certain = finding({ ruleId: "TLS_VERIFICATION_DISABLED", confidence: "high" });
  assert.equal(decide({ findings: [certain], secrets: [], dependencies: [] }).status, "blocked");
  const regexOnly = finding({ ruleId: "SQL_STRING_CONCAT", confidence: "medium" });
  assert.equal(decide({ findings: [regexOnly], secrets: [], dependencies: [] }).status, "warning");
});

test("coherence: same verdict whatever the file order, and run after run", async () => {
  const { analyzeDiff } = await import("./analyzer.js");
  const file = (path: string, lines: string[]) =>
    [`diff --git a/${path} b/${path}`, "--- /dev/null", `+++ b/${path}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");
  const parts = [
    file("a.ts", ['db.query("SELECT * FROM t WHERE id = " + req.params.id);']),
    file("b.py", ["h = hashlib.md5(password.encode())"]),
    file("c.ts", ['const k = "AKIA' + 'Z7Q3MLD2KXW5PRT4";']),
  ];
  const norm = (r: ReturnType<typeof analyzeDiff>) =>
    JSON.stringify({
      f: r.findings.map((x) => JSON.stringify(x)).sort(),
      s: r.secrets.map((x) => JSON.stringify(x)).sort(),
      score: r.riskScore,
      d: r.decision,
    });
  const a = norm(analyzeDiff(parts.join("\n")));
  assert.equal(a, norm(analyzeDiff(parts.join("\n"))));
  assert.equal(a, norm(analyzeDiff([...parts].reverse().join("\n"))));
});
