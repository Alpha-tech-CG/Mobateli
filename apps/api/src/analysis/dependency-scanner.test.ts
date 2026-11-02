import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUnifiedDiff } from "./diff.js";
import { scanDependencies } from "./dependency-scanner.js";

const diffOf = (file: string, lines: string[]) =>
  parseUnifiedDiff(
    [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n"),
  );

test("requirements.txt: pinned, ranged, extras; comments and options skipped", () => {
  const deps = scanDependencies(
    diffOf("requirements.txt", ["requests==2.31.0", "uvicorn[standard]>=0.30", "# comment", "-r base.txt", "reqeusts"]),
  );
  assert.deepEqual(deps.map((d) => [d.ecosystem, d.name, d.version]), [
    ["PyPI", "requests", "2.31.0"],
    ["PyPI", "uvicorn", "0.30"],
    ["PyPI", "reqeusts", "*"],
  ]);
  assert.equal(deps[2]!.riskLevel, "critical", "typosquat of requests");
});

test("pyproject.toml: PEP 621 and Poetry entries, metadata keys ignored", () => {
  const deps = scanDependencies(
    diffOf("pyproject.toml", ['  "httpx>=0.27",', 'name = "my-app"', 'python = "^3.12"', 'pydantic = "^2.7"']),
  );
  assert.deepEqual(deps.map((d) => d.name), ["httpx", "pydantic"]);
});

test("go.mod: require lines and block entries", () => {
  const deps = scanDependencies(
    diffOf("go.mod", ["require github.com/gin-gonic/gin v1.10.0", "\tgolang.org/x/crypto v0.24.0 // indirect"]),
  );
  assert.deepEqual(deps.map((d) => [d.ecosystem, d.name, d.version]), [
    ["Go", "github.com/gin-gonic/gin", "v1.10.0"],
    ["Go", "golang.org/x/crypto", "v0.24.0"],
  ]);
});
