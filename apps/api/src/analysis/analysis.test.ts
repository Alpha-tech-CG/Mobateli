import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff, isCommentLine, isTestOrExampleFile } from "./diff.js";
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
    'const aws = "AKIA' + 'Q3ZR7TPLM2XN4VWB";',
    "-----BEGIN RSA PRIVATE" + " KEY-----",
    'const db = "postgres' + '://app:secretpw@db.prod.internal:5432/db";',
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

test("secret scanner: templates, doc examples and local dev DBs don't block", () => {
  const scan = (line: string) => scanSecrets(parseUnifiedDiff(diffFor("ci.yml", [line])).addedLines);
  // Not secrets at all → not reported.
  assert.equal(scan("return `postgresql://${u}:${pw}@${host}:5432/postgres`;").length, 0);
  assert.equal(scan("url: postgresql://user:<MOT_DE_PASSE>@db.example.com/x").length, 0);
  assert.equal(scan("'postgres://user:pw@host'").length, 0);
  assert.equal(scan('aws = "AKIAIOSFODNN7EXAMPLE"').length, 0);
  // Supabase config.toml: a reference to an env var, not a value.
  assert.equal(scan('secret = "env(SUPABASE_AUTH_EXTERNAL_GITHUB_SECRET)"').length, 0);
  // The machine itself / a reserved test domain → not a secret at all.
  assert.equal(scan("DATABASE_URL: postgresql://postgres:postgres@localhost:5432/ci").length, 0);
  // A docker-compose service name (no dot) → reported at low confidence only.
  const service = scan("DATABASE_URL: postgresql://app:app@postgres:5432/app");
  assert.equal(service.length, 1);
  assert.equal(service[0]!.confidence, "low");
  // A remote database password stays high.
  assert.equal(scan("postgresql://app:Zr8tq2Lm@db.abc.supabase.co:5432/postgres")[0]!.confidence, "high");
  const decision = decide({
    findings: [],
    dependencies: [],
    secrets: service,
  });
  assert.notEqual(decision.decision, "block");
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

test("dependency scanner: legitimate near-miss packages are not typosquats", () => {
  // Real, popular packages that sit a short edit distance from the curated
  // list — previously flagged as critical typosquats (the false positives).
  const legit = ["preact", "knex", "yup", "joi", "got", "jose", "redux", "chai", "bootstrap", "vite"];
  for (const name of legit) {
    assert.equal(nearestPopular(name), null, `${name} should not be a typosquat`);
    const [dep] = scanDependencies(
      parseUnifiedDiff(diffFor("package.json", [`    "${name}": "1.0.0",`])),
    );
    assert.equal(dep!.riskLevel, "low", `${name} should score low risk`);
  }
});

test("dependency scanner: scripts/engines are not dependencies (section-aware)", () => {
  const names = (diff: string) => scanDependencies(parseUnifiedDiff(diff)).map((d) => d.name);
  // A whole new package.json: only the dependency sections count.
  const whole = diffFor("package.json", [
    "{",
    '  "name": "app",',
    '  "scripts": {',
    '    "test": "jest",',
    '    "dev": "next dev",',
    '    "build": "vitest run"',
    "  },",
    '  "engines": {',
    '    "node": ">=22"',
    "  },",
    '  "dependencies": {',
    '    "express": "^4.18.0"',
    "  },",
    '  "devDependencies": {',
    '    "vitest": "^1.6.0"',
    "  }",
    "}",
  ]);
  assert.deepEqual(names(whole), ["express", "vitest"]);

  // A partial edit whose section header is in the hunk's context lines.
  const ctx = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -10,4 +10,6 @@",
    '   "scripts": {',
    '+    "test": "jest",',
    '     "lint": "eslint ."',
    "   },",
    '   "dependencies": {',
    '+    "zod": "^3.23.0",',
    '     "express": "^4.18.0"',
  ].join("\n");
  assert.deepEqual(names(ctx), ["zod"]);

  // Section out of view: fall back to "does the value look like a version?".
  const blind = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -20,2 +20,4 @@",
    '+    "test": "jest --maxWorkers=4",',
    '+    "left-pad": "1.3.0",',
  ].join("\n");
  assert.deepEqual(names(blind), ["left-pad"]);
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

test("SSRF only when the URL host can come from input, not from config", () => {
  const ids = (line: string) =>
    runSastRules(parseUnifiedDiff(diffFor("a.ts", [line])).addedLines).map((f) => f.ruleId);
  // Flagged: request input or a variable host.
  assert.ok(ids("await fetch(req.query.url);").includes("SSRF_REQUEST"));
  assert.ok(ids("await fetch(`${target}/status`);").includes("SSRF_REQUEST"));
  assert.ok(ids("axios.get(`${body.callbackUrl}`);").includes("SSRF_REQUEST"));
  // Not flagged: constant base URL or fixed origin.
  assert.ok(!ids("await fetch(`${API_URL}/api/flashcards?limit=20`);").includes("SSRF_REQUEST"));
  assert.ok(!ids("await fetch(`${process.env.API_URL}/x`);").includes("SSRF_REQUEST"));
  assert.ok(!ids("await fetch(`${config.BASE_URL}/x`);").includes("SSRF_REQUEST"));
  assert.ok(!ids("await fetch(`https://api.github.com/users/${name}`);").includes("SSRF_REQUEST"));
});

test("innerHTML with a plain literal is not XSS; with data it is", () => {
  const ids = (line: string) =>
    runSastRules(parseUnifiedDiff(diffFor("a.js", [line])).addedLines).map((f) => f.ruleId);
  assert.ok(!ids("el.innerHTML = '';").includes("XSS_INNERHTML"));
  assert.ok(!ids("d.innerHTML = 'NO FEES<em>✦</em>';").includes("XSS_INNERHTML"));
  assert.ok(!ids("d.innerHTML = `<b>static</b>`;").includes("XSS_INNERHTML"));
  assert.ok(!ids("ref.current.innerHTML = HTML;").includes("XSS_INNERHTML"));
  assert.ok(!ids("<div dangerouslySetInnerHTML={{ __html: HTML }} />").includes("XSS_INNERHTML"));
  assert.ok(ids("<div dangerouslySetInnerHTML={{ __html: post.body }} />").includes("XSS_INNERHTML"));
  assert.ok(ids("el.innerHTML = userInput;").includes("XSS_INNERHTML"));
  assert.ok(ids("el.innerHTML = `<b>${name}</b>`;").includes("XSS_INNERHTML"));
  assert.ok(ids("el.innerHTML = 'x' + name;").includes("XSS_INNERHTML"));
});

test("sast rules carry CWE / OWASP / confidence references", () => {
  const findings = runSastRules(
    parseUnifiedDiff(diffFor("db.ts", ['const q = "SELECT * FROM t WHERE id = " + id;'])).addedLines,
  );
  const sql = findings.find((f) => f.ruleId === "SQL_STRING_CONCAT");
  assert.ok(sql);
  assert.equal(sql!.cwe, "CWE-89");
  assert.match(sql!.owasp!, /Injection/);
  assert.ok(sql!.confidence);
});

test("sast ignores vulnerable-looking code inside comments", () => {
  assert.equal(isCommentLine("  // eval(userInput) is dangerous"), true);
  const findings = runSastRules(
    parseUnifiedDiff(diffFor("h.ts", ["// never do eval(userInput);", "const ok = 1;"])).addedLines,
  );
  assert.equal(findings.length, 0);
});

test("secret scanner: placeholders and sample files do not block", () => {
  // Obvious placeholder value → not flagged.
  const placeholder = scanSecrets(
    parseUnifiedDiff(diffFor("a.ts", ['const apiKey = "your-api-key-here";'])).addedLines,
  );
  assert.equal(placeholder.length, 0);

  // A provider-shaped key in a sample file → flagged but only low confidence.
  assert.equal(isTestOrExampleFile(".env.example"), true);
  const sample = scanSecrets(
    parseUnifiedDiff(diffFor(".env.example", ["AWS=AKIA" + "Q3ZR7TPLM2XN4VWB"])).addedLines,
  );
  assert.equal(sample.length, 1);
  assert.equal(sample[0]!.confidence, "low");
  // Low-confidence secret warns but never blocks on its own.
  const d = decide({ findings: [], secrets: sample, dependencies: [] });
  assert.notEqual(d.decision, "block");
});

test("score: repeats of one rule have diminishing weight; distinct rules add up", () => {
  const f = (ruleId: string) => ({
    type: "sast" as const,
    severity: "medium" as const,
    title: ruleId,
    description: "",
    ruleId,
  });
  // 8 × the same medium hygiene rule: one fix, not a block.
  const repeated = decide({
    findings: Array.from({ length: 8 }, () => f("github-actions-mutable-action-tag")),
    secrets: [],
    dependencies: [],
  });
  assert.equal(repeated.riskScore, 16); // 8 × min(1 + 0.25·7, 2)
  assert.notEqual(repeated.decision, "block");
  // Distinct medium rules still accumulate.
  const distinct = decide({
    findings: ["a", "b", "c", "d", "e", "f", "g", "h", "i"].map(f),
    secrets: [],
    dependencies: [],
  });
  assert.equal(distinct.riskScore, 72);
  assert.equal(distinct.decision, "block");
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
