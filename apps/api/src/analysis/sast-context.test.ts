import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff } from "./diff.js";
import { isMinified, runSastRules } from "./sast.js";

function rules(file: string, lines: string[]): string[] {
  const diff = [`diff --git a/${file} b/${file}`, "--- /dev/null", `+++ b/${file}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");
  return runSastRules(parseUnifiedDiff(diff).addedLines).map((f) => `${f.line}:${f.ruleId}`);
}

test("sast: code inside a /* … */ block (a commented-out fix) is not live", () => {
  const found = rules("dao.js", [
    "/*",
    "return {$where: `this.x > ${a}`};",
    "*/",
    "return {$where: `this.x > '${b}'`};",
    'const s = "/* not a comment";',
    "return {$where: `this.y > ${c}`};",
  ]);
  assert.deepEqual(found, ["4:NOSQL_WHERE_INJECTION", "6:NOSQL_WHERE_INJECTION"]);
});

test("sast: template autoescape disabled", () => {
  assert.deepEqual(rules("server.js", ["swig.setDefaults({ autoescape: false });"]), ["1:TEMPLATE_AUTOESCAPE_DISABLED"]);
  assert.deepEqual(rules("app.py", ["env = Environment(autoescape=False)"]), ["1:TEMPLATE_AUTOESCAPE_DISABLED"]);
  assert.deepEqual(rules("server.js", ["swig.setDefaults({ autoescape: true });"]), []);
});

test("sast: vendored and minified files are skipped", () => {
  for (const f of ["a.min.js", "raphael-min.js", "app.bundle.js", "app/assets/vendor/html5shiv.js", "third_party/x.js"]) {
    assert.ok(isMinified(f), f);
  }
  for (const f of ["src/admin.js", "src/minify.js", "src/vendors-api.ts"]) assert.ok(!isMinified(f), f);
});

test("secrets: standard password-hash formats are not credentials", async () => {
  const { scanSecrets } = await import("./secret-scanner.js");
  const lines = [
    '"password" : "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba",',
    "password = 'pbkdf2_sha256$600000$abcdefgh$Zm9vYmFyYmF6cXV4'",
    'password = "S3cure!Pass#2024xyz"',
  ].map((content, i) => ({ file: "seed.js", line: i + 1, content }));
  assert.deepEqual(scanSecrets(lines).map((s) => s.location), ["seed.js:3"]);
});
