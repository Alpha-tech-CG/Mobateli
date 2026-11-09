import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeDiff } from "./analyzer.js";
import { runCoreAnalysis } from "./engines/pipeline.js";
import { evidenceOf, detailsFor } from "./alert-details.js";
import { findingAssurance, needsHumanReview } from "./assurance.js";
import { decisionTrace } from "./decision-trace.js";
import { environmentOfBranch, matchDependency, matchFinding, type ExceptionRow } from "../lib/exceptions.js";
import type { FindingResult } from "./types.js";

const diffFor = (file: string, lines: string[]) =>
  [`diff --git a/${file} b/${file}`, "--- /dev/null", `+++ b/${file}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");

const SQL = 'db.query("SELECT * FROM users WHERE id = " + req.params.id);';

test("every alert carries evidence, a scenario, conditions and a reproduction test", () => {
  const r = analyzeDiff(diffFor("src/users.ts", [SQL]));
  const f = r.findings.find((x) => x.ruleId === "SQL_STRING_CONCAT")!;
  assert.ok(f.assurance, "assurance set");
  assert.equal(f.details?.evidence, SQL);
  assert.match(f.details!.scenario, /OR '1'='1/);
  assert.ok(f.details!.conditions.length >= 2);
  assert.match(f.details!.reproduction, /src\/users\.ts:1/);
});

test("evidence never shows a secret", () => {
  const key = ["sk", "live", "51HxYzAbCdEfGhIjKlMnOpQrStUv"].join("_");
  const shown = evidenceOf(`const stripe = new Stripe("${key}");`)!;
  assert.ok(!shown.includes(key));
  assert.match(shown, /sk_l…/);
  // Ordinary identifiers stay readable.
  assert.equal(evidenceOf("const total = computeInvoiceTotal(order);"), "const total = computeInvoiceTotal(order);");
});

test("assurance: taint proof and high confidence are verified, without a location it is not", () => {
  const f = (over: Partial<FindingResult>): FindingResult => ({
    type: "sast", severity: "high", title: "t", description: "d", filePath: "a.ts", line: 1, ...over,
  });
  assert.equal(findingAssurance(f({ ruleId: "RUST-JS-SQLI-TAINT", confidence: "medium" })), "verified");
  assert.equal(findingAssurance(f({ confidence: "high" })), "verified");
  assert.equal(findingAssurance(f({ confidence: "medium" })), "likely");
  assert.equal(findingAssurance(f({ confidence: "low" })), "uncertain");
  assert.equal(findingAssurance(f({ severity: "info" })), "information");
  assert.equal(findingAssurance({ type: "sast", severity: "high", title: "t", description: "d", confidence: "high" }), "likely");
  assert.equal(needsHumanReview(f({ confidence: "medium" })), true);
  assert.equal(needsHumanReview(f({ confidence: "high" })), false);
});

test("a rule in observation is shown as uncertain and no longer decides", () => {
  const diff = diffFor("src/a.ts", ['tls.connect({ host, rejectUnauthorized: false });']);
  const normal = runCoreAnalysis(diff);
  assert.notEqual(normal.status, "passed");
  const observed = runCoreAnalysis(diff, undefined, new Set(), undefined, undefined, {
    observedRules: new Map([["TLS_VERIFICATION_DISABLED", "Règle en observation automatique : 80 % de faux positifs."]]),
  });
  const f = observed.findings.find((x) => x.ruleId === "TLS_VERIFICATION_DISABLED")!;
  assert.equal(f.assurance, "uncertain");
  assert.match(f.details!.observationReason!, /observation/);
  assert.equal(observed.status, "passed");
});

test("an approved exception covers matching code alerts only, and they no longer decide", () => {
  const diff = [diffFor("scripts/seed.ts", [SQL]), diffFor("src/users.ts", [SQL])].join("\n");
  const exceptions: ExceptionRow[] = [
    { id: "e1", ruleId: "SQL_STRING_CONCAT", pathGlob: "scripts/**", riskType: null, dependency: null, dependencyVersion: null, branch: null, environment: null },
  ];
  const r = runCoreAnalysis(diff, undefined, new Set(), undefined, undefined, {
    exceptionFor: (f) => matchFinding(exceptions, f, "main"),
  });
  assert.deepEqual(r.excepted.map((f) => [f.filePath, f.exceptionId]), [["scripts/seed.ts", "e1"]]);
  assert.ok(r.findings.some((f) => f.filePath === "src/users.ts" && f.ruleId === "SQL_STRING_CONCAT"));
});

test("exception scope: branch and environment, dependency and version", () => {
  const e = (over: Partial<ExceptionRow>): ExceptionRow => ({
    id: "e", ruleId: null, pathGlob: null, riskType: null, dependency: null, dependencyVersion: null, branch: null, environment: null, ...over,
  });
  const f: FindingResult = { type: "sast", severity: "high", title: "t", description: "d", ruleId: "R", filePath: "a.ts", line: 1 };
  assert.equal(matchFinding([e({ ruleId: "R", environment: "development" })], f, "feature/x"), "e");
  assert.equal(matchFinding([e({ ruleId: "R", environment: "development" })], f, "main"), null);
  assert.equal(matchFinding([e({ ruleId: "R", branch: "develop" })], f, "main"), null);
  assert.equal(matchFinding([e({ dependency: "lodash" })], f, "main"), null, "a dependency exception never covers code");
  const dep = { ecosystem: "npm", name: "lodash", version: "4.17.10", trustScore: 10, riskLevel: "critical" as const };
  assert.equal(matchDependency([e({ dependency: "lodash", dependencyVersion: "4.17.10" })], dep, "main"), "e");
  assert.equal(matchDependency([e({ dependency: "lodash", dependencyVersion: "4.17.21" })], dep, "main"), null);
  assert.equal(environmentOfBranch("main"), "production");
  assert.equal(environmentOfBranch("staging"), "staging");
  assert.equal(environmentOfBranch("feat/login"), "development");
});

test("a block is traced to the proven alerts that decided it", () => {
  const live = ["sk", "live", "abcdefABCDEF0123456789xyz"].join("_");
  const r = analyzeDiff(diffFor("config.ts", [`const stripe = "${live}";`, "x.innerHTML = '';"]));
  assert.equal(r.status, "blocked");
  const trace = decisionTrace(r);
  assert.ok(trace.some((t) => t.kind === "secret" && t.assurance === "verified" && t.location === "config.ts:1"));
  assert.ok(!JSON.stringify(trace).includes(live), "the trace never holds the secret");
});

test("details fall back to a generic, still actionable explanation", () => {
  const d = detailsFor({ type: "auth", severity: "medium", title: "t", description: "d", filePath: "a.ts", line: 3 }, "x();");
  assert.ok(d.scenario && d.conditions.length && /a\.ts:3/.test(d.reproduction));
});
