import { test } from "node:test";
import assert from "node:assert/strict";
import { engineAvailable, scanWithEngine } from "./index.js";
import { analyzeDiff } from "../analyzer.js";

const diff = (file: string, lines: string[]) =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");

test("the Rust engine is built and loads", () => {
  assert.equal(engineAvailable(), true, "run services/scan-engine/build-wasm.sh");
  const out = scanWithEngine([{ file: "a.ts", line: 1, content: "eval(x)" }])!;
  assert.equal(out.engine, "codegate-scan");
  assert.deepEqual(out.findings.map((f) => f.ruleId), ["DANGEROUS_EVAL"]);
});

test("syntax tree removes line-rule false positives on JS/TS", () => {
  const r = analyzeDiff(diff("src/a.ts", ["// eval(x) is forbidden here", "const s = 'el.innerHTML = x';", "const q = sql`SELECT * FROM t WHERE id = ${id}`;"]));
  assert.match(r.engine, /^rust-wasm/);
  assert.deepEqual(r.findings.filter((f) => f.type === "sast"), []);
});

test("other languages and unparseable hunks still use the line rules", () => {
  const py = analyzeDiff(diff("app.py", ["result = eval(user_input)"]));
  assert.ok(py.findings.some((f) => f.ruleId === "DANGEROUS_EVAL"));
  const cut = analyzeDiff(diff("src/b.ts", ["  });", "}, [", "eval(payload)"]));
  assert.ok(cut.findings.some((f) => f.ruleId === "DANGEROUS_EVAL"));
});

test("secrets from the Rust engine match the TypeScript scanner", () => {
  const key = ["AKIA", "IOSFODNN7EXAMPLE"].concat().join("");
  const r = analyzeDiff(diff("cfg.ts", [`const id = "${key}";`]));
  assert.deepEqual(r.secrets.map((s) => [s.secretType, s.location, s.maskedPreview]), [
    ["aws_access_key_id", "cfg.ts:1", "AKIA…MPLE (20 chars)"],
  ]);
});
