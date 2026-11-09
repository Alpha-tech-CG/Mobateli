import { test } from "node:test";
import assert from "node:assert/strict";
import { dedupeDependencies, lockedNpmVersions, resolveInstalledVersions, satisfies } from "./lockfiles.js";
import { refineSecrets } from "./secret-scanner.js";
import { ofSubject } from "../lib/expert.js";
import type { DependencyResult, SecretResult } from "./types.js";

const dep = (name: string, version: string): DependencyResult => ({
  ecosystem: "npm",
  name,
  version,
  trustScore: 80,
  riskLevel: "low",
});

test("npm ranges", () => {
  assert.ok(satisfies("5.12.7", "^5.2.1"));
  assert.ok(!satisfies("6.0.0", "^5.2.1"));
  assert.ok(!satisfies("5.2.0", "^5.2.1"));
  assert.ok(satisfies("0.3.9", "^0.3.1") && !satisfies("0.4.0", "^0.3.1"));
  assert.ok(satisfies("1.2.9", "~1.2.3") && !satisfies("1.3.0", "~1.2.3"));
  assert.ok(satisfies("3.25.76", ">=3.0.0 <4"));
  assert.ok(satisfies("2.0.0", "^1.0.0 || ^2.0.0"));
  assert.ok(satisfies("4.1.0", "*") && satisfies("1.2.3", "1.2.3") && satisfies("1.9.0", "1.x"));
});

test("pnpm, npm and yarn lockfiles give the installed version", () => {
  const pnpm = `lockfileVersion: '9.0'

importers:

  apps/api:
    dependencies:
      fastify:
        specifier: ^5.2.1
        version: 5.12.7
      '@node-saml/node-saml':
        specifier: ^5.0.1
        version: 5.2.0
      '@codegate/db':
        specifier: workspace:*
        version: link:../../packages/db

packages:

  fastify@5.12.7:
    resolution: {integrity: sha512-abc}

  '@node-saml/node-saml@5.2.0':
    resolution: {integrity: sha512-def}

  zod@3.25.76:
    resolution: {integrity: sha512-ghi}

  react-dom@19.0.0(react@19.0.0):
    resolution: {integrity: sha512-jkl}
`;
  const npm = JSON.stringify({ packages: { "": {}, "node_modules/express": { version: "4.21.2" } } });
  const yarn = `"lodash@^4.17.0", "lodash@^4.17.15":\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash"\n`;
  const locked = lockedNpmVersions([
    { path: "pnpm-lock.yaml", content: pnpm },
    { path: "web/package-lock.json", content: npm },
    { path: "legacy/yarn.lock", content: yarn },
  ]);
  const resolved = resolveInstalledVersions(
    [dep("fastify", "^5.2.1"), dep("@node-saml/node-saml", "^5.0.1"), dep("zod", "^3.24.1"), dep("express", "^4.18.0"), dep("lodash", "^4.17.0"), dep("left-pad", "^1.0.0")],
    locked,
  );
  assert.deepEqual(
    resolved.map((d) => d.resolvedVersion),
    ["5.12.7", "5.2.0", "3.25.76", "4.21.2", "4.17.21", undefined],
  );
  assert.ok(locked.get("react-dom")?.has("19.0.0"), "pnpm peer suffix stripped");
  assert.ok(!locked.has("@codegate/db"), "workspace links are not versions");
});

test("a lockfile version outside the declared range is not used", () => {
  const locked = new Map([["fastify", new Set(["4.28.0"])]]);
  assert.equal(resolveInstalledVersions([dep("fastify", "^5.2.1")], locked)[0]!.resolvedVersion, undefined);
});

test("monorepo duplicates are evaluated once", () => {
  const out = dedupeDependencies([
    { ...dep("zod", "^3.24.1"), resolvedVersion: "3.25.76" },
    { ...dep("zod", "^3.24.1"), resolvedVersion: "3.25.76" },
    { ...dep("zod", "^4.0.0"), resolvedVersion: "4.6.7" },
  ]);
  assert.equal(out.length, 2);
});

test("secrets from any engine: examples dropped, test files become notes, live keys stay", () => {
  // Built at runtime so this test file never contains a live-shaped key.
  const live = ["sk", "live", "51HxYzAbCdEfGhIjKlMnOpQr"].join("_");
  const awsKey = ["AKIA", "Z7Q3LMNPRT5VWX2Y"].join("");
  const lines: Record<string, string> = {
    "src/a.ts:1": 'const k = "AKIAIOSFODNN7EXAMPLE";',
    "src/a.ts:2": 'const db = "postgres://user:pw@localhost:5432/app";',
    "src/a.ts:3": 'const token = "changeme";',
    "src/b.ts:1": `const k = "${awsKey}";`,
    "src/x.test.ts:1": `const k = "${awsKey}";`,
    "src/x.test.ts:2": 'const t = "aG7xK2pQ9rT4vW8yB3nB8d";',
    "test/stripe.ts:1": `const live = "${live}";`,
  };
  const s = (secretType: string, location: string): SecretResult => ({
    secretType,
    location,
    maskedPreview: "…",
    severity: "critical",
  });
  const { secrets, samples } = refineSecrets(
    [
      s("aws_access_key_id", "src/a.ts:1"),
      s("postgres_url", "src/a.ts:2"),
      s("generic_token", "src/a.ts:3"),
      s("aws_access_key_id", "src/b.ts:1"),
      s("aws_access_key_id", "src/x.test.ts:1"),
      s("generic_apikey", "src/x.test.ts:2"),
      s("stripe_secret_key", "test/stripe.ts:1"),
    ],
    (file, line) => lines[`${file}:${line}`],
  );
  assert.deepEqual(
    secrets.map((x) => x.location),
    ["src/b.ts:1", "test/stripe.ts:1"],
    "a real key stays, and a live key stays even in a test file",
  );
  assert.deepEqual(samples, [{ file: "src/x.test.ts", count: 2, types: ["aws_access_key_id", "generic_apikey"] }]);
});

test("report French: du dépôt, du serveur", () => {
  assert.equal(ofSubject("le dépôt acme/api"), "du dépôt acme/api");
  assert.equal(ofSubject("les serveurs"), "des serveurs");
  assert.equal(ofSubject("acme/api #12"), "de acme/api #12");
});
