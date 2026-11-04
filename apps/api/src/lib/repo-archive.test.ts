import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { extractTarGz, shouldKeep } from "./repo-archive.js";
import { analyzeFiles } from "../analysis/analyzer.js";

/** Minimal ustar writer (+ optional pax path record), enough for tests. */
function tarEntry(name: string, content: string | Buffer, type = "0", pax?: string): Buffer {
  const chunks: Buffer[] = [];
  if (pax) {
    const rec = (len: number) => `${len} path=${pax}\n`;
    let len = rec(0).length;
    while (rec(len).length !== len) len = rec(len).length;
    chunks.push(tarEntry("PaxHeader", rec(len), "x"));
  }
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 99), 0, "utf8");
  header.write("0000644\0", 100);
  header.write("0000000\0", 108);
  header.write("0000000\0", 116);
  header.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
  header.write("00000000000\0", 136);
  header.write(type, 156);
  header.write("ustar\0", 257);
  header.write("00", 263);
  header.fill(" ", 148, 156);
  let sum = 0;
  for (const b of header) sum += b;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  chunks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  return Buffer.concat(chunks);
}

function tarGz(entries: Buffer[]): Buffer {
  return gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
}

test("archive: strips the top folder, keeps code, skips vendored/binary/lock files", () => {
  const longPath = `owner-repo-abc123/${"deep/".repeat(25)}file.ts`;
  const archive = tarGz([
    tarEntry("owner-repo-abc123/", "", "5"),
    tarEntry("owner-repo-abc123/src/app.ts", "export const a = 1;\n"),
    tarEntry("owner-repo-abc123/node_modules/x/index.js", "eval(x)"),
    tarEntry("owner-repo-abc123/package-lock.json", "{}"),
    tarEntry("owner-repo-abc123/logo.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0])),
    tarEntry("owner-repo-abc123/data.bin.txt", Buffer.from([1, 0, 2])),
    tarEntry("ignored-name", "const deep = true;\n", "0", longPath),
  ]);
  const { files, lockfiles, skipped, truncated } = extractTarGz(archive);
  assert.deepEqual(files.map((f) => f.path).sort(), [`${"deep/".repeat(25)}file.ts`, "src/app.ts"]);
  // Lockfiles are kept apart (installed versions), never analysed as code.
  assert.deepEqual(lockfiles.map((f) => f.path), ["package-lock.json"]);
  assert.equal(skipped, 3);
  assert.equal(truncated, false);
});

test("archive: limits stop extraction and flag truncation", () => {
  const archive = tarGz([1, 2, 3].map((i) => tarEntry(`r/f${i}.ts`, `const x${i} = ${i};\n`)));
  const out = extractTarGz(archive, { maxFiles: 2, maxFileBytes: 1024, maxTotalBytes: 1 << 20 });
  assert.equal(out.files.length, 2);
  assert.equal(out.truncated, true);
});

test("shouldKeep filters by directory and type", () => {
  assert.equal(shouldKeep("src/index.ts"), true);
  assert.equal(shouldKeep("dist/index.js"), false);
  assert.equal(shouldKeep("web/vendor/lib.min.js"), false);
  assert.equal(shouldKeep("yarn.lock"), false);
});

test("analyzeFiles: whole files are analysed like added lines", () => {
  const key = ["AKIA", "Z7Q3LMNPRT5VWX2Y"].join("");
  const r = analyzeFiles([
    { path: "src/config.ts", content: `export const id = "${key}";\n` },
    { path: "src/run.ts", content: "import { exec } from 'node:child_process';\nexec(`git clone ${url}`);\n" },
    { path: "package.json", content: '{\n  "dependencies": {\n    "react-router-domm": "^6.0.0"\n  }\n}\n' },
  ]);
  assert.deepEqual(r.secrets.map((s) => s.location), ["src/config.ts:1"]);
  assert.ok(r.findings.some((f) => f.ruleId === "CHILD_PROCESS_INJECTION" && f.line === 2));
  assert.equal(r.dependencies[0]?.riskLevel, "critical");
  assert.equal(r.status, "blocked");
});
