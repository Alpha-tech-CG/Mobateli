import { test } from "node:test";
import assert from "node:assert/strict";
import { baseVersion, enrichDependencies } from "./dependency-intel.js";
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

test("non-existent package (hallucinated name) is critical", async () => {
  const out = await enrichDependencies(
    [dep("react-super-auth-helperz")],
    fakeFetch({ querybatch: () => json({ results: [{}] }) }),
    now,
  );
  assert.equal(out[0]!.riskLevel, "critical");
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

test("network failure leaves the deterministic result unchanged", async () => {
  const boom = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  const input = [dep("express")];
  assert.deepEqual(await enrichDependencies(input, boom, now), input);
});
