import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSemgrep, type SemgrepRunner } from "./semgrep.js";
import { analyzeDiffWithIntel } from "./analyzer.js";

/** A fake Semgrep runner returning canned JSON, so tests never shell out. */
function fakeSemgrep(output: unknown): { runner: SemgrepRunner; calls: string[][] } {
  const calls: string[][] = [];
  const runner: SemgrepRunner = async (files) => {
    calls.push(files);
    return JSON.stringify(output);
  };
  return { runner, calls };
}

/** A runner that finds nothing — used for baselines, so no test shells out. */
const emptyRunner: SemgrepRunner = async () => JSON.stringify({ results: [] });

const SQLI_RESULT = {
  results: [
    {
      check_id: "javascript.express.security.audit.sqli.node-mysql-sqli",
      path: "src/db.js",
      start: { line: 42 },
      extra: {
        message: "Detected SQL statement built from user input.",
        severity: "ERROR",
        metadata: {
          cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
          owasp: ["A03:2021 - Injection"],
          confidence: "HIGH",
          references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
        },
      },
    },
  ],
};

test("scanSemgrep maps severity, CWE, OWASP and confidence", async () => {
  const { runner, calls } = fakeSemgrep(SQLI_RESULT);
  const findings = await scanSemgrep(["src/db.js"], { runner });

  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.type, "sast");
  assert.equal(f.severity, "high"); // ERROR → high
  assert.equal(f.cwe, "CWE-89"); // normalized from the long label
  assert.equal(f.owasp, "A03:2021 - Injection");
  assert.equal(f.confidence, "high");
  assert.equal(f.ruleId, "javascript.express.security.audit.sqli.node-mysql-sqli");
  assert.equal(f.filePath, "src/db.js");
  assert.equal(f.line, 42);
  // references → remediation; message → description.
  assert.match(f.remediation ?? "", /owasp\.org/);
  assert.match(f.description, /SQL statement/);
  // The modified file was passed to the runner.
  assert.deepEqual(calls[0], ["src/db.js"]);
});

test("scanSemgrep maps WARNING/INFO and a metadata CRITICAL severity", async () => {
  const { runner } = fakeSemgrep({
    results: [
      { check_id: "a", path: "a.js", start: { line: 1 }, extra: { severity: "WARNING" } },
      { check_id: "b", path: "b.js", start: { line: 2 }, extra: { severity: "INFO" } },
      {
        check_id: "c",
        path: "c.js",
        start: { line: 3 },
        extra: { severity: "ERROR", metadata: { severity: "CRITICAL" } },
      },
    ],
  });
  const [warn, info, crit] = await scanSemgrep(["a.js", "b.js", "c.js"], { runner });
  assert.equal(warn!.severity, "medium");
  assert.equal(info!.severity, "low");
  assert.equal(crit!.severity, "critical"); // metadata overrides extra.severity
});

test("scanSemgrep handles string (not array) metadata and scalar refs", async () => {
  const { runner } = fakeSemgrep({
    results: [
      {
        check_id: "python.lang.security.eval",
        path: "app.py",
        start: { line: 7 },
        extra: {
          message: "eval on untrusted input",
          severity: "ERROR",
          metadata: { cwe: "CWE-95", owasp: "A03:2021-Injection", confidence: "MEDIUM" },
        },
      },
    ],
  });
  const [f] = await scanSemgrep(["app.py"], { runner });
  assert.equal(f!.cwe, "CWE-95");
  assert.equal(f!.owasp, "A03:2021-Injection");
  assert.equal(f!.confidence, "medium");
});

test("scanSemgrep fails open when the binary is missing", async () => {
  const runner: SemgrepRunner = async () => {
    const err = new Error("spawn semgrep ENOENT") as Error & { code?: string };
    err.code = "ENOENT";
    throw err;
  };
  const findings = await scanSemgrep(["src/db.js"], { runner });
  assert.deepEqual(findings, []);
});

test("scanSemgrep fails open on malformed JSON output", async () => {
  const runner: SemgrepRunner = async () => "not json at all";
  const findings = await scanSemgrep(["src/db.js"], { runner });
  assert.deepEqual(findings, []);
});

test("scanSemgrep returns [] without invoking the runner for an empty file set", async () => {
  let invoked = false;
  const runner: SemgrepRunner = async () => {
    invoked = true;
    return "{}";
  };
  const findings = await scanSemgrep([], { runner });
  assert.deepEqual(findings, []);
  assert.equal(invoked, false);
});

test("analyzeDiffWithIntel merges Semgrep findings and recomputes the decision", async () => {
  const { runner } = fakeSemgrep(SQLI_RESULT);
  const diff = [
    "diff --git a/src/db.js b/src/db.js",
    "--- a/src/db.js",
    "+++ b/src/db.js",
    "@@ -0,0 +1,1 @@",
    "+const ok = 1;",
  ].join("\n");

  const base = await analyzeDiffWithIntel(diff, { semgrep: { runner: emptyRunner } });
  const withSemgrep = await analyzeDiffWithIntel(diff, { semgrep: { runner } });

  assert.equal(withSemgrep.findings.length, base.findings.length + 1);
  const added = withSemgrep.findings.find((f) => f.ruleId?.includes("node-mysql-sqli"));
  assert.ok(added, "Semgrep finding should be merged in");
  // A high-severity SAST finding must move the risk score above the clean base.
  assert.ok(withSemgrep.riskScore > base.riskScore);
});

test("analyzeDiffWithIntel deduplicates a finding already flagged by the regex rules", async () => {
  // A line the regex rule SQL_STRING_CONCAT (CWE-89) already catches.
  const vulnLine = 'const q = "SELECT * FROM users WHERE id = " + req.params.id;';
  const diff = [
    "diff --git a/src/db.js b/src/db.js",
    "--- a/src/db.js",
    "+++ b/src/db.js",
    "@@ -0,0 +1,1 @@",
    `+${vulnLine}`,
  ].join("\n");

  // Semgrep reports the SAME file+line+CWE under its own rule id.
  const { runner } = fakeSemgrep({
    results: [
      {
        check_id: "javascript.express.security.audit.sqli",
        path: "src/db.js",
        start: { line: 1 },
        extra: { message: "SQLi", severity: "ERROR", metadata: { cwe: "CWE-89" } },
      },
    ],
  });

  const baseline = await analyzeDiffWithIntel(diff, { semgrep: { runner: emptyRunner } });
  const merged = await analyzeDiffWithIntel(diff, { semgrep: { runner } });

  const regexHits = baseline.findings.filter((f) => f.cwe === "CWE-89" && f.line === 1);
  assert.equal(regexHits.length, 1, "regex rule should flag the line");
  // Dedup: the Semgrep duplicate on the same (CWE, file, line) is dropped.
  assert.equal(merged.findings.length, baseline.findings.length);
});

test("analyzeDiffWithIntel hands Semgrep the PR's added code on disk, never outside it", async () => {
  const { readFile, access } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const diff = [
    "diff --git a/app/api.py b/app/api.py",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/app/api.py",
    "@@ -0,0 +1,2 @@",
    "+import os",
    "+os.system(cmd)",
    "diff --git a/../escape.py b/../escape.py",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/../escape.py",
    "@@ -0,0 +1,1 @@",
    "+print('x')",
  ].join("\n");

  let seenCwd = "";
  let seenFiles: string[] = [];
  let content = "";
  const runner = async (files: string[], o: { cwd?: string }) => {
    seenCwd = o.cwd ?? "";
    seenFiles = files;
    content = await readFile(join(seenCwd, "app/api.py"), "utf8");
    return JSON.stringify({ results: [] });
  };
  await analyzeDiffWithIntel(diff, { semgrep: { runner }, rust: { enabled: false } });

  assert.ok(seenCwd, "Semgrep must run inside a scratch directory");
  // The scratch dir is scanned as a whole (no per-file argv to overflow), and
  // the traversal path was never written into it.
  assert.deepEqual(seenFiles, ["."]);
  await assert.rejects(access(join(seenCwd, "..", "escape.py")));
  assert.equal(content, "import os\nos.system(cmd)");
  // The scratch directory is cleaned up afterwards.
  await assert.rejects(access(seenCwd));
});

test("analyzeDiffWithIntel reports which passes ran, were skipped or failed", async () => {
  const { buildPrComment } = await import("./explainer.js");
  const diff = [
    "diff --git a/app.py b/app.py",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/app.py",
    "@@ -0,0 +1,1 @@",
    "+print('ok')",
  ].join("\n");
  const missing = Object.assign(new Error("spawn semgrep ENOENT"), { code: "ENOENT" });
  const r = await analyzeDiffWithIntel(diff, {
    semgrep: { runner: async () => Promise.reject(missing) },
    rust: { enabled: false },
  });
  assert.deepEqual(r.engines?.semgrep, { status: "failed", detail: "binaire absent" });
  assert.deepEqual(r.engines?.rust, { status: "skipped", detail: "désactivé" });
  assert.equal(r.engines?.osv?.status, "skipped"); // no dependency in the diff
  assert.equal(r.engines?.sca?.status, "skipped"); // no checkout to scan

  // The PR comment must not read as "checked and clean".
  const comment = buildPrComment(r);
  assert.match(comment, /Analyse partielle/);
  assert.match(comment, /Semgrep\) : binaire absent/);
  assert.doesNotMatch(comment, /Aucun risque détecté\. ✅/);

  // All passes fine → no warning.
  const ok = await analyzeDiffWithIntel(diff, {
    semgrep: { runner: async () => JSON.stringify({ results: [] }) },
    rust: { runner: async () => "[]" },
  });
  assert.equal(ok.engines?.semgrep?.status, "ok");
  assert.equal(ok.engines?.rust?.status, "ok");
  assert.doesNotMatch(buildPrComment(ok), /Analyse partielle/);
});
