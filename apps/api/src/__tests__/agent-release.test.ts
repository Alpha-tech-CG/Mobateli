import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const agentDir = fileURLToPath(new URL("../../../web/public/agent/", import.meta.url));
const release = readFileSync(fileURLToPath(new URL("../../../web/src/lib/agent-release.ts", import.meta.url)), "utf8");

/** The installer verifies these checksums: a changed file needs a new pin (P2-5). */
for (const file of ["codegate-agent.py", "codegate-backup.py"]) {
  test(`installer pins the SHA-256 of ${file}`, () => {
    const sha = createHash("sha256").update(readFileSync(agentDir + file)).digest("hex");
    const block = release.slice(release.indexOf(`file: "${file}"`));
    const pinned = /sha256: "([0-9a-f]{64})"/.exec(block)?.[1];
    assert.equal(pinned, sha, `update apps/web/src/lib/agent-release.ts for ${file}`);
  });
}

test("agent version matches the pinned release", () => {
  const code = readFileSync(agentDir + "codegate-agent.py", "utf8");
  const version = /^VERSION = "([^"]+)"/m.exec(code)?.[1];
  assert.match(release, new RegExp(`version: "${version}"`));
});

const python = ["python3", "python"].find((bin) => spawnSync(bin, ["--version"]).status === 0);

test("agent parsing helpers (Traefik routes, secrets, no TLS warnings)", { skip: !python && "python not installed" }, () => {
  const fixture = fileURLToPath(new URL("./fixtures/agent_check.py", import.meta.url));
  const res = spawnSync(python!, ["-I", fixture, agentDir + "codegate-agent.py"], { encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr || res.stdout);
  assert.match(res.stdout, /agent helpers ok/);
});
