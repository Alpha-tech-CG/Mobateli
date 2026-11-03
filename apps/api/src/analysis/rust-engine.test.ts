import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff } from "./diff.js";
import {
  runRustEngine,
  filesFromDiff,
  mergeRustFindings,
  type EngineRunner,
} from "./rust-engine.js";
import type { FindingResult } from "./types.js";

/** A canned engine finding as the Rust binary would emit it. */
const sqliJson = {
  type: "sast",
  severity: "high",
  title: "Injection SQL : entrée utilisateur dans une requête",
  description: "…",
  filePath: "src/db.ts",
  line: 12,
  ruleId: "RUST-JS-SQLI-TAINT",
  cwe: "CWE-89",
  owasp: "A03:2021-Injection",
  confidence: "high",
};

/** A runner that returns a fixed stdout, ignoring the manifest. */
const runnerReturning = (stdout: string): EngineRunner => async () => stdout;

test("parses engine JSON into FindingResult[] with cwe/owasp/confidence", async () => {
  const findings = await runRustEngine([{ path: "src/db.ts", content: "x" }], {
    runner: runnerReturning(JSON.stringify([sqliJson])),
  });
  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.ruleId, "RUST-JS-SQLI-TAINT");
  assert.equal(f.cwe, "CWE-89");
  assert.equal(f.owasp, "A03:2021-Injection");
  assert.equal(f.confidence, "high");
  assert.equal(f.type, "sast");
});

test("fails open to [] on invalid JSON", async () => {
  const findings = await runRustEngine([{ path: "a.js", content: "x" }], {
    runner: runnerReturning("not json"),
  });
  assert.deepEqual(findings, []);
});

test("fails open to [] when the runner throws (e.g. binary missing)", async () => {
  const throwingRunner: EngineRunner = async () => {
    throw new Error("spawn ENOENT");
  };
  const findings = await runRustEngine([{ path: "a.js", content: "x" }], {
    runner: throwingRunner,
  });
  assert.deepEqual(findings, []);
});

test("returns [] with no files, without invoking the runner", async () => {
  let called = false;
  const findings = await runRustEngine([], {
    runner: async () => {
      called = true;
      return "[]";
    },
  });
  assert.deepEqual(findings, []);
  assert.equal(called, false);
});

test("respects enabled: false (never runs)", async () => {
  let called = false;
  const findings = await runRustEngine([{ path: "a.js", content: "x" }], {
    enabled: false,
    runner: async () => {
      called = true;
      return JSON.stringify([sqliJson]);
    },
  });
  assert.deepEqual(findings, []);
  assert.equal(called, false);
});

test("drops malformed findings but keeps valid ones", async () => {
  const mixed = JSON.stringify([
    sqliJson,
    { title: "no severity" }, // invalid
    { severity: "nonsense", title: "bad sev", description: "d" }, // invalid severity
  ]);
  const findings = await runRustEngine([{ path: "a.js", content: "x" }], {
    runner: runnerReturning(mixed),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "RUST-JS-SQLI-TAINT");
});

test("the manifest sent to the runner is valid JSON with files", async () => {
  let seen = "";
  await runRustEngine([{ path: "a.js", content: "db.query(x)" }], {
    runner: async (manifest) => {
      seen = manifest;
      return "[]";
    },
  });
  const parsed = JSON.parse(seen) as { files: { path: string; content: string }[] };
  assert.equal(parsed.files.length, 1);
  assert.equal(parsed.files[0]!.path, "a.js");
});

test("filesFromDiff places added lines at their real line numbers", () => {
  const diff = [
    "diff --git a/src/x.js b/src/x.js",
    "--- a/src/x.js",
    "+++ b/src/x.js",
    "@@ -0,0 +3,2 @@",
    "+const id = req.query.id;",
    "+db.query(id);",
  ].join("\n");
  const files = filesFromDiff(parseUnifiedDiff(diff));
  assert.equal(files.length, 1);
  const lines = files[0]!.content.split("\n");
  // Lines 3 and 4 hold the added code; 1–2 are blank padding.
  assert.equal(lines[0], "");
  assert.equal(lines[2], "const id = req.query.id;");
  assert.equal(lines[3], "db.query(id);");
});

test("mergeRustFindings lets the engine finding supersede the regex one on the same line/family", () => {
  const base: FindingResult[] = [
    {
      type: "sast",
      severity: "high",
      title: "Requête SQL construite par concaténation",
      description: "regex rule",
      filePath: "src/db.ts",
      line: 12,
      ruleId: "SQL_STRING_CONCAT",
    },
  ];
  const engine: FindingResult[] = [sqliJson as unknown as FindingResult];
  const merged = mergeRustFindings(base, engine);
  assert.equal(merged.length, 1);
  assert.equal(merged[0]!.ruleId, "RUST-JS-SQLI-TAINT");
  assert.equal(merged[0]!.cwe, "CWE-89");
});

test("mergeRustFindings keeps base findings that have no engine equivalent", () => {
  const base: FindingResult[] = [
    {
      type: "secret",
      severity: "high",
      title: "Clé API",
      description: "d",
      filePath: "src/x.ts",
      line: 1,
      ruleId: "SECRET",
    },
  ];
  const merged = mergeRustFindings(base, [sqliJson as unknown as FindingResult]);
  assert.equal(merged.length, 2);
});
