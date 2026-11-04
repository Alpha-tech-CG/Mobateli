import { test } from "node:test";
import assert from "node:assert/strict";
import { runSca, mergeScaIntoDependencies, type ScaProcessResult } from "./sca.js";
import { analyzeDiffWithIntel } from "./analyzer.js";

/** Keep these unit tests hermetic: no real Semgrep or Rust subprocess. */
const OFFLINE = {
  semgrep: { runner: async () => JSON.stringify({ results: [] }) },
  rust: { enabled: false },
};
import type { DependencyResult } from "./types.js";

/**
 * A fake subprocess runner returning canned CLI output, so tests never depend
 * on a real Trivy/Grype binary. It records the calls for argument assertions.
 */
function fakeRunner(stdout: string, opts: { code?: number } = {}) {
  const calls: { bin: string; args: string[] }[] = [];
  const runner = async (bin: string, args: string[]): Promise<ScaProcessResult> => {
    calls.push({ bin, args });
    return { code: opts.code ?? 0, stdout, stderr: "" };
  };
  return { runner, calls };
}

const TRIVY_JSON = JSON.stringify({
  Results: [
    {
      Target: "package-lock.json",
      Class: "lang-pkgs",
      Type: "npm",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2021-23337",
          PkgName: "lodash",
          InstalledVersion: "4.17.20",
          FixedVersion: "4.17.21",
          Severity: "HIGH",
          Title: "Command injection in lodash",
        },
      ],
    },
    {
      Target: "package-lock.json",
      Class: "license",
      Type: "npm",
      Licenses: [
        { PkgName: "lodash", Name: "MIT", Severity: "LOW" },
        { PkgName: "copyleft-lib", Name: "GPL-3.0", Severity: "HIGH" },
        { PkgName: "safe-lib", Name: "MIT", Severity: "LOW" },
      ],
    },
  ],
});

test("runSca parses Trivy output: CVEs, license, and risk", async () => {
  const { runner, calls } = fakeRunner(TRIVY_JSON);
  const deps = await runSca({ runner, workspaceDir: "/repo" });

  // lodash (vuln + license) and copyleft-lib (restrictive license) surface;
  // safe-lib (permissive, no vuln) is dropped.
  const names = deps.map((d) => d.name).sort();
  assert.deepEqual(names, ["copyleft-lib", "lodash"]);

  const lodash = deps.find((d) => d.name === "lodash")!;
  assert.equal(lodash.riskLevel, "high");
  assert.equal(lodash.version, "4.17.20");
  assert.equal(lodash.license, "MIT");
  assert.equal(lodash.vulnerabilities?.length, 1);
  assert.equal(lodash.vulnerabilities![0]!.id, "CVE-2021-23337");
  assert.equal(lodash.vulnerabilities![0]!.fixedVersion, "4.17.21");
  assert.ok(lodash.trustScore <= 20);

  const copyleft = deps.find((d) => d.name === "copyleft-lib")!;
  assert.equal(copyleft.license, "GPL-3.0");
  assert.equal(copyleft.riskLevel, "high");
  assert.match(copyleft.reason ?? "", /restreint/);

  // Correct filesystem invocation with JSON output + both scanners.
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.bin, "trivy");
  assert.deepEqual(calls[0]!.args, [
    "fs",
    "--quiet",
    "--format",
    "json",
    "--scanners",
    "vuln,license",
    "/repo",
  ]);
});

test("runSca scans a container image when one is given", async () => {
  const { runner, calls } = fakeRunner(TRIVY_JSON);
  await runSca({ runner, image: "myapp:latest" });
  assert.equal(calls[0]!.args[0], "image");
  assert.ok(calls[0]!.args.includes("myapp:latest"));
});

test("runSca parses Grype output", async () => {
  const grype = JSON.stringify({
    matches: [
      {
        vulnerability: {
          id: "CVE-2022-0001",
          severity: "Critical",
          description: "Remote code execution",
          fix: { versions: ["2.0.0"], state: "fixed" },
        },
        artifact: { name: "pkgx", version: "1.0.0", type: "npm", language: "javascript" },
      },
    ],
  });
  const { runner, calls } = fakeRunner(grype);
  const deps = await runSca({ runner, tool: "grype", workspaceDir: "/repo" });

  assert.equal(deps.length, 1);
  assert.equal(deps[0]!.name, "pkgx");
  assert.equal(deps[0]!.riskLevel, "critical");
  assert.equal(deps[0]!.vulnerabilities![0]!.fixedVersion, "2.0.0");
  // Grype uses `dir:` for a filesystem scan.
  assert.equal(calls[0]!.args[0], "dir:/repo");
});

test("runSca returns [] and never calls the tool when no target is set", async () => {
  const { runner, calls } = fakeRunner(TRIVY_JSON);
  const deps = await runSca({ runner });
  assert.deepEqual(deps, []);
  assert.equal(calls.length, 0);
});

test("runSca fails open when the binary is missing", async () => {
  const runner = async () => {
    const err = new Error("spawn trivy ENOENT") as NodeJS.ErrnoException;
    err.code = "ENOENT";
    throw err;
  };
  const deps = await runSca({ runner, workspaceDir: "/repo" });
  assert.deepEqual(deps, []);
});

test("runSca fails open on malformed JSON", async () => {
  const { runner } = fakeRunner("not json at all");
  const deps = await runSca({ runner, workspaceDir: "/repo" });
  assert.deepEqual(deps, []);
});

test("mergeScaIntoDependencies dedups a shared CVE by id and raises risk", () => {
  const base: DependencyResult[] = [
    {
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.11",
      trustScore: 80,
      riskLevel: "low",
      vulnerabilities: [{ id: "CVE-2021-23337", severity: "medium", summary: "x" }],
    },
  ];
  const sca: DependencyResult[] = [
    {
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.20",
      trustScore: 20,
      riskLevel: "high",
      license: "MIT",
      vulnerabilities: [
        { id: "CVE-2021-23337", severity: "high", summary: "x" },
        { id: "CVE-2020-8203", severity: "high", summary: "proto pollution" },
      ],
    },
  ];
  const merged = mergeScaIntoDependencies(base, sca);
  assert.equal(merged.length, 1);
  const lodash = merged[0]!;
  // CVE-2021-23337 appears in both → counted once.
  assert.equal(lodash.vulnerabilities?.length, 2);
  assert.equal(lodash.riskLevel, "high");
  assert.equal(lodash.trustScore, 20);
  assert.equal(lodash.license, "MIT");
});

test("mergeScaIntoDependencies appends a new full-tree package", () => {
  const base: DependencyResult[] = [
    { ecosystem: "npm", name: "react", version: "18.0.0", trustScore: 90, riskLevel: "low" },
  ];
  const sca: DependencyResult[] = [
    {
      ecosystem: "npm",
      name: "transitive-dep",
      version: "0.1.0",
      trustScore: 5,
      riskLevel: "critical",
      vulnerabilities: [{ id: "CVE-X", severity: "critical", summary: "boom" }],
    },
  ];
  const merged = mergeScaIntoDependencies(base, sca);
  assert.equal(merged.length, 2);
  assert.ok(merged.some((d) => d.name === "transitive-dep" && d.riskLevel === "critical"));
});

test("analyzeDiffWithIntel merges SCA findings and escalates the decision", async () => {
  // OSV finds nothing; the SCA scan of the full tree finds a critical CVE.
  const osvFetch = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const critical = JSON.stringify({
    Results: [
      {
        Target: "pnpm-lock.yaml",
        Type: "npm",
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2099-9999",
            PkgName: "evil-transitive",
            InstalledVersion: "1.2.3",
            Severity: "CRITICAL",
            Title: "RCE",
          },
        ],
      },
    ],
  });
  const { runner } = fakeRunner(critical);
  const diff = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -0,0 +1,1 @@",
    '+    "left-pad": "1.3.0",',
  ].join("\n");

  const r = await analyzeDiffWithIntel(diff, {
    fetchImpl: osvFetch,
    sca: { runner, workspaceDir: "/repo" },
    ...OFFLINE,
  });

  const evil = r.dependencies.find((d) => d.name === "evil-transitive");
  assert.ok(evil, "SCA dependency should be present");
  assert.equal(evil!.riskLevel, "critical");
  assert.equal(r.decision, "block");
  assert.equal(r.status, "blocked");
});

test("analyzeDiffWithIntel without SCA options equals the OSV-only pipeline", async () => {
  const osvFetch = async () => ({ ok: true, status: 200, json: async () => ({ vulns: [] }) });
  const diff = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -0,0 +1,1 @@",
    '+    "left-pad": "1.3.0",',
  ].join("\n");
  const r = await analyzeDiffWithIntel(diff, { fetchImpl: osvFetch, ...OFFLINE });
  // No SCA target → no extra dependencies, clean decision.
  assert.equal(r.dependencies.length, 1);
  assert.equal(r.dependencies[0]!.name, "left-pad");
});
