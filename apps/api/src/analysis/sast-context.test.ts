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
    // Split so the fixture is not a contiguous hash literal (secret scanners flag it).
    '"password" : "$2a$10$' + '8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba",',
    "password = 'pbkdf2_sha256$600000$abcdefgh$Zm9vYmFyYmF6cXV4'",
    'password = "S3cure!Pass#2024xyz"',
  ].map((content, i) => ({ file: "seed.js", line: i + 1, content }));
  assert.deepEqual(scanSecrets(lines).map((s) => s.location), ["seed.js:3"]);
});

// ---- Pilot on Alpha's projects (2026-11) -------------------------------------

test("sast: tagged SQL templates bind their ${…} as parameters", () => {
  const found = rules("repo.ts", [
    "await db.$queryRaw`SELECT id FROM invoices WHERE id = ${invoiceId} FOR UPDATE`;",
    "const lock = await tx.$queryRaw<{ id: string }[]>`",
    "  SELECT id FROM t WHERE token_hash = ${tokenHash} FOR UPDATE",
    "`;",
    "await db.execute(sql`update ai_knowledge set hits = hits + 1 where id = ${id}`);",
    "const rows = await db.execute(sql`",
    "  insert into ai_usage (user_id, day) values (${userId}, current_date)",
    "`);",
    // Still flagged: the Unsafe variant, raw splices, plain templates.
    "await db.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${name}'`);",
    "await db.execute(sql`SELECT * FROM t WHERE n = ${sql.raw(name)}`);",
    "db.query(`SELECT * FROM t WHERE n = '${name}'`);",
  ]);
  assert.deepEqual(found, ["9:SQL_STRING_CONCAT", "10:SQL_STRING_CONCAT", "11:SQL_STRING_CONCAT"]);
});

test("sast: innerHTML with a constant, a static template or copied markup is inert", () => {
  const found = rules("page.tsx", [
    "if (ref.current) ref.current.innerHTML = HTML;",
    "return <div ref={ref} dangerouslySetInnerHTML={{ __html: HTML }} />;",
    "<svg dangerouslySetInnerHTML={{ __html: ICONS[name] }} />",
    "<script nonce={nonce} dangerouslySetInnerHTML={{",
    "  __html: `if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}`,",
    "}} />",
    "sm.innerHTML = el.innerHTML;",
    // Still flagged: input-bearing values.
    "el.innerHTML = msg;",
    "<div dangerouslySetInnerHTML={{ __html: post.body }} />",
    "<div dangerouslySetInnerHTML={{",
    "  __html: `<p>${name}</p>`,",
    "}} />",
    "el.innerHTML = '<b>' + name + '</b>';",
  ]);
  assert.deepEqual(found, ["8:XSS_INNERHTML", "9:XSS_INNERHTML", "10:XSS_INNERHTML", "13:XSS_INNERHTML"]);
});

test("sast: Math.random for a password or token is medium confidence, a sort key stays low", () => {
  const diff = (lines: string[]) =>
    [`diff --git a/a.ts b/a.ts`, "--- /dev/null", `+++ b/a.ts`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");
  const conf = (lines: string[]) =>
    runSastRules(parseUnifiedDiff(diff(lines)).addedLines)
      .filter((f) => f.ruleId === "WEAK_RANDOM")
      .map((f) => `${f.line}:${f.confidence}`);
  assert.deepEqual(
    conf([
      "function tempPassword(): string {",
      "  for (let i = 0; i < 12; i++) out += chars[Math.floor(Math.random() * chars.length)];",
      "}",
      "const resetToken = Math.random().toString(36);",
      "function weightedSample(xs) {",
      "  const items = xs.map((x) => ({ x, key: Math.pow(Math.random(), 1 / x.w) }));",
      "  const secret = Math.floor(Math.random() * 100); // a guessing game",
      "  const clientSecret = Math.random().toString(36);",
    ]),
    ["2:medium", "4:medium", "6:low", "7:low", "8:medium"],
  );
});

test("secrets: truncated values, UI labels and local database URLs", async () => {
  const { scanSecrets } = await import("./secret-scanner.js");
  const scan = (content: string, file = "src/a.ts") => scanSecrets([{ file, line: 1, content }]);
  assert.deepEqual(scan("  secret: 'whsec_4Kd9…f21a',"), []);
  assert.deepEqual(scan("    'dev.hookSecret': 'Secret de signature :',"), []);
  // A random value is still a secret.
  assert.equal(scan("  secret: 'q8Zr2LwPx7Tn4VbK9mYc',").length, 1);
  const pg = (url: string) => scan(`DATABASE_URL: ${url}`, ".github/workflows/ci.yml").map((s) => s.confidence);
  assert.deepEqual(pg("postgres://ci:ci@localhost:5432/app"), ["low"]);
  assert.deepEqual(pg("postgresql://app:app@postgres:5432/app"), ["low"]);
  assert.deepEqual(pg("postgresql://USER:PASS@HOST:5432/db"), ["low"]);
  assert.deepEqual(pg("postgresql://admin:Zx81kQp2@db.prod-eu.example.net:5432/app"), ["high"]);
});

test("sast: innerHTML literals with entities, and several statements on a line", () => {
  assert.deepEqual(rules("a.ts", ["cancelButton.innerHTML = '<div>&times;</div>'"]), []);
  assert.deepEqual(rules("a.js", ["h.innerHTML = dd.firstChild.innerHTML; c.appendChild(h);"]), []);
  assert.deepEqual(rules("a.js", ["a.innerHTML = ''; b.innerHTML = name;"]), ["1:XSS_INNERHTML"]);
  assert.deepEqual(rules("a.js", ["a.innerHTML = 'x;' + name;"]), ["1:XSS_INNERHTML"]);
});
