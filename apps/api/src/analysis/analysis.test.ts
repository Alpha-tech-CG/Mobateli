import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff } from "./diff.js";
import { scanSecrets, shannonEntropy } from "./secret-scanner.js";
import { scanDependencies, levenshtein, nearestPopular } from "./dependency-scanner.js";
import { runSastRules } from "./sast.js";
import { decide } from "./risk.js";
import { analyzeDiff } from "./analyzer.js";

/** Build a one-file unified diff whose added lines are `lines`. */
function diffFor(file: string, lines: string[]): string {
  const added = lines.map((l) => `+${l}`).join("\n");
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -0,0 +1,${lines.length} @@`,
    added,
  ].join("\n");
}

test("diff parser extracts added lines with new line numbers", () => {
  const d = diffFor("src/app.ts", ["const a = 1;", "const b = 2;"]);
  const parsed = parseUnifiedDiff(d);
  assert.deepEqual(parsed.files, ["src/app.ts"]);
  assert.equal(parsed.addedLines.length, 2);
  assert.equal(parsed.addedLines[0]!.line, 1);
  assert.equal(parsed.addedLines[1]!.line, 2);
  assert.equal(parsed.addedLines[1]!.content, "const b = 2;");
});

test("entropy: random string > prose", () => {
  assert.ok(shannonEntropy("aG7xQ2pLzR9mKv3wT1nB") > shannonEntropy("changemechangeme"));
});

test("secret scanner detects provider keys", () => {
  const d = diffFor("config.ts", [
    // Split so the fixture isn't a contiguous literal (secret scanners flag it).
    'const stripe = "sk_live_' + 'abcdefABCDEF0123456789xyz";',
    'const aws = "AKIA' + 'IOSFODNN7EXAMPLE";',
    "-----BEGIN RSA PRIVATE" + " KEY-----",
    'const db = "postgres' + '://user:secretpw@host:5432/db";',
  ]);
  const secrets = scanSecrets(parseUnifiedDiff(d).addedLines);
  const types = secrets.map((s) => s.secretType);
  assert.ok(types.includes("stripe_secret_key"));
  assert.ok(types.includes("aws_access_key_id"));
  assert.ok(types.includes("private_key"));
  assert.ok(types.includes("postgres_url"));
  // Masked, never the raw value.
  assert.ok(secrets.every((s) => !s.maskedPreview.includes("secretpw")));
});

test("secret scanner: generic high-entropy flagged, low-entropy ignored", () => {
  const flagged = scanSecrets(
    parseUnifiedDiff(diffFor("a.ts", ['const apiKey = "aG7xQ2pL' + 'zR9mKv3wT1nB8d";'])).addedLines,
  );
  assert.equal(flagged.length, 1);
  const ignored = scanSecrets(
    parseUnifiedDiff(diffFor("a.ts", ['const password = "changeme1234";'])).addedLines,
  );
  assert.equal(ignored.length, 0);
});

test("levenshtein + typosquat detection", () => {
  assert.equal(levenshtein("react-router-dom", "react-router-domm"), 1);
  assert.equal(nearestPopular("react"), null); // exact popular ⇒ not a squat
  const squat = nearestPopular("react-router-domm");
  assert.ok(squat && squat.target === "react-router-dom");
});

test("dependency scanner scores a typosquat as critical", () => {
  const d = diffFor("package.json", ['    "react-router-domm": "1.0.0",']);
  const deps = scanDependencies(parseUnifiedDiff(d));
  assert.equal(deps.length, 1);
  assert.equal(deps[0]!.riskLevel, "critical");
  assert.ok(deps[0]!.trustScore < 40);
});

test("sast rules catch common issues", () => {
  const d = diffFor("h.ts", [
    'const q = "SELECT * FROM users WHERE id = " + userId;',
    "eval(userInput);",
    "el.innerHTML = userInput;",
    'crypto.createHash("md5");',
    "const agent = new https.Agent({ rejectUnauthorized: false });",
  ]);
  const ids = runSastRules(parseUnifiedDiff(d).addedLines).map((f) => f.ruleId);
  assert.ok(ids.includes("SQL_STRING_CONCAT"));
  assert.ok(ids.includes("DANGEROUS_EVAL"));
  assert.ok(ids.includes("XSS_INNERHTML"));
  assert.ok(ids.includes("WEAK_HASH"));
  assert.ok(ids.includes("TLS_VERIFICATION_DISABLED"));
});

test("decision: secret ⇒ blocked, high ⇒ warning, clean ⇒ passed", () => {
  const blocked = decide({
    findings: [],
    secrets: [{ secretType: "stripe", location: "a:1", maskedPreview: "x", severity: "critical" }],
    dependencies: [],
  });
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.decision, "block");

  const warning = decide({
    findings: [{ type: "sast", severity: "high", title: "x", description: "y" }],
    secrets: [],
    dependencies: [],
  });
  assert.equal(warning.status, "warning");

  const passed = decide({ findings: [], secrets: [], dependencies: [] });
  assert.equal(passed.status, "passed");
  assert.equal(passed.riskScore, 0);
});

test("analyzeDiff: end-to-end on a risky diff ⇒ blocked", () => {
  const diff = [
    diffFor("config.ts", ['const stripe = "sk_live_' + 'abcdefABCDEF0123456789xyz";']),
    diffFor("package.json", ['    "react-router-domm": "1.0.0",']),
    diffFor("db.ts", ['const q = "SELECT * FROM t WHERE id = " + id;']),
  ].join("\n");
  const r = analyzeDiff(diff);
  assert.equal(r.status, "blocked");
  assert.equal(r.decision, "block");
  assert.ok(r.secrets.length >= 1);
  assert.ok(r.dependencies.some((d) => d.riskLevel === "critical"));
  assert.ok(r.findings.some((f) => f.ruleId === "SQL_STRING_CONCAT"));
  assert.ok(r.riskScore >= 70);
});

test("analyzeDiff: clean diff ⇒ passed", () => {
  const r = analyzeDiff(diffFor("src/util.ts", ["export const sum = (a, b) => a + b;"]));
  assert.equal(r.status, "passed");
  assert.equal(r.riskScore, 0);
});
