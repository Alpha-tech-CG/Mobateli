import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIgnoreFile } from "./ignore.js";
import { analyzeDiff } from "./analyzer.js";

function diffFor(files: Record<string, string[]>): string {
  return Object.entries(files)
    .map(([file, lines]) =>
      [
        `diff --git a/${file} b/${file}`,
        "--- /dev/null",
        `+++ b/${file}`,
        `@@ -0,0 +1,${lines.length} @@`,
        ...lines.map((l) => `+${l}`),
      ].join("\n"),
    )
    .join("\n");
}

test("ignore: directory, anchored and unanchored patterns", () => {
  const ignored = parseIgnoreFile(
    ["# corpus", "apps/api/bench/golden/", "vendor", "*.min.js", "docs/**/*.md", ""].join("\n"),
  );
  assert.ok(ignored("apps/api/bench/golden/js/injection.ts"));
  assert.ok(!ignored("apps/api/bench/run.ts"));
  assert.ok(!ignored("other/apps/api/bench/golden/x.ts"), "slash pattern is anchored at root");
  assert.ok(ignored("vendor/lib.js"));
  assert.ok(ignored("packages/x/vendor/lib.js"), "bare name matches at any depth");
  assert.ok(!ignored("src/vendors.ts"));
  assert.ok(ignored("public/app.min.js"));
  assert.ok(ignored("docs/a/b/c.md"));
  assert.ok(ignored("docs/c.md"), "**/ matches zero directories");
  assert.ok(!ignored("docs/c.txt"));
});

test("ignore: negation re-includes, last match wins", () => {
  const ignored = parseIgnoreFile("generated/\n!generated/keep.ts\n");
  assert.ok(ignored("generated/a.ts"));
  assert.ok(!ignored("generated/keep.ts"));
});

test("ignore: empty or comment-only file ignores nothing", () => {
  assert.ok(!parseIgnoreFile("\n# nothing\n")("src/app.ts"));
});

test("ignore: special characters are literal, not regex", () => {
  const ignored = parseIgnoreFile("a+b(1).ts");
  assert.ok(ignored("a+b(1).ts"));
  assert.ok(!ignored("aab1.ts"));
});

test("analyzeDiff: ignored paths skip SAST and dependencies but not secrets", () => {
  const diff = diffFor({
    "corpus/vuln.ts": [
      'db.query("SELECT * FROM users WHERE id = " + req.params.id);',
      // Split so the fixture isn't a contiguous secret literal.
      'const k = "AKIA' + 'Z7Q3MLD2KXW5PRT4";',
    ],
    "corpus/package.json": ['    "expresss": "4.19.2",'],
    "src/app.ts": ['db.query("SELECT * FROM users WHERE id = " + req.params.id);'],
  });
  const isIgnored = parseIgnoreFile("corpus/\n");

  const without = analyzeDiff(diff);
  assert.equal(without.findings.filter((f) => f.ruleId === "SQL_STRING_CONCAT").length, 2);

  const res = analyzeDiff(diff, new Set(), undefined, isIgnored);
  const sql = res.findings.filter((f) => f.ruleId === "SQL_STRING_CONCAT");
  assert.deepEqual(sql.map((f) => f.filePath), ["src/app.ts"]);
  assert.equal(res.dependencies.length, 0, "dependencies under an ignored path are skipped");
  assert.ok(
    res.secrets.some((s) => s.location === "corpus/vuln.ts:2"),
    "a secret under an ignored path is still reported",
  );
});

test("analyzeDiff: editing .codegateignore is flagged as a sensitive change", () => {
  const res = analyzeDiff(diffFor({ ".codegateignore": ["**"] }));
  assert.ok(res.findings.some((f) => f.ruleId === "SENSITIVE_FILE_CHANGED" && f.filePath === ".codegateignore"));
});
