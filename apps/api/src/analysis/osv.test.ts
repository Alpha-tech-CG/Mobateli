import { test } from "node:test";
import assert from "node:assert/strict";
import { queryOsv, enrichDependenciesWithOsv } from "./osv.js";
import { analyzeDiffWithIntel } from "./analyzer.js";

/** Keep these unit tests hermetic: no real Semgrep or Rust subprocess. */
const OFFLINE = {
  semgrep: { runner: async () => JSON.stringify({ results: [] }) },
  rust: { enabled: false },
};
import type { DependencyResult } from "./types.js";

/** A fake OSV endpoint returning a canned response, so tests never hit network. */
function fakeOsv(response: unknown, opts: { ok?: boolean } = {}) {
  const calls: { url: string; body: unknown }[] = [];
  const fetchImpl = async (url: string, init: { body: string }) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return { ok: opts.ok ?? true, status: 200, json: async () => response };
  };
  return { fetchImpl, calls };
}

const GHSA = {
  vulns: [
    {
      id: "GHSA-xxxx-yyyy-zzzz",
      summary: "Prototype pollution in example",
      database_specific: { severity: "HIGH" },
      affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
    },
  ],
};

test("queryOsv maps a GHSA advisory to a vulnerability", async () => {
  const { fetchImpl, calls } = fakeOsv(GHSA);
  const vulns = await queryOsv("npm", "lodash", "4.17.11", { fetchImpl });
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0]!.id, "GHSA-xxxx-yyyy-zzzz");
  assert.equal(vulns[0]!.severity, "high");
  assert.equal(vulns[0]!.fixedVersion, "4.17.21");
  // Sent the right ecosystem + concrete version.
  assert.deepEqual(calls[0]!.body, { version: "4.17.11", package: { name: "lodash", ecosystem: "npm" } });
});

test("queryOsv strips a version range prefix and skips non-versions", async () => {
  const { fetchImpl, calls } = fakeOsv(GHSA);
  await queryOsv("npm", "lodash", "^4.17.11", { fetchImpl });
  assert.equal((calls[0]!.body as { version: string }).version, "4.17.11");

  // A git/url spec has no concrete version → no query made.
  const none = await queryOsv("npm", "x", "github:user/repo", { fetchImpl });
  assert.equal(none.length, 0);
});

test("queryOsv fails open on a network error", async () => {
  const fetchImpl = async () => {
    throw new Error("ECONNREFUSED");
  };
  const vulns = await queryOsv("npm", "lodash", "4.17.11", { fetchImpl });
  assert.deepEqual(vulns, []);
});

test("enrich bumps risk and lowers trust for a vulnerable dependency", async () => {
  const { fetchImpl } = fakeOsv(GHSA);
  const deps: DependencyResult[] = [
    { ecosystem: "npm", name: "lodash", version: "4.17.11", trustScore: 80, riskLevel: "low" },
  ];
  const [enriched] = await enrichDependenciesWithOsv(deps, { fetchImpl });
  assert.equal(enriched!.riskLevel, "high");
  assert.ok(enriched!.trustScore <= 20);
  assert.equal(enriched!.vulnerabilities?.length, 1);
  assert.match(enriched!.reason ?? "", /GHSA-xxxx/);
});

test("enrich leaves dependencies untouched when OSV returns nothing", async () => {
  const { fetchImpl } = fakeOsv({ vulns: [] });
  const deps: DependencyResult[] = [
    { ecosystem: "npm", name: "left-pad", version: "1.3.0", trustScore: 80, riskLevel: "low" },
  ];
  const [out] = await enrichDependenciesWithOsv(deps, { fetchImpl });
  assert.equal(out!.riskLevel, "low");
  assert.equal(out!.vulnerabilities, undefined);
});

test("analyzeDiffWithIntel escalates the decision when a CVE is found", async () => {
  const { fetchImpl } = fakeOsv(GHSA);
  const diff = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -0,0 +1,1 @@",
    '+    "lodash": "4.17.11",',
  ].join("\n");
  const r = await analyzeDiffWithIntel(diff, { fetchImpl, ...OFFLINE });
  assert.ok(r.dependencies[0]!.vulnerabilities?.length);
  assert.equal(r.dependencies[0]!.riskLevel, "high");
  assert.ok(r.riskScore > 0);
});
