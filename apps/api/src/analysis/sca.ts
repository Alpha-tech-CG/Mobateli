import { execFile } from "node:child_process";
import type { DependencyRisk } from "@codegate/shared";
import {
  describeFailure,
  type DependencyResult,
  type DependencyVulnerability,
  type EngineStatusFn,
} from "./types.js";

/**
 * Software Composition Analysis (cahier §5.3, §9.3 — Trivy/Grype).
 *
 * OSV (`osv.ts`) only covers the dependencies *added* in a PR's `package.json`.
 * This pass completes it by scanning the FULL dependency tree (from lockfiles)
 * and, when a `Dockerfile` is present, the container image — through Trivy (or
 * Grype) run as a subprocess with `--format json`. It extracts both known
 * vulnerabilities (CVE/GHSA) and licenses.
 *
 * Same discipline as `osv.ts`: it is kept out of the synchronous core, it
 * **fails open** (a missing binary, a crash, a timeout or malformed JSON never
 * blocks a PR), and the subprocess runner is injectable so tests never depend
 * on a real Trivy/Grype binary.
 */

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024; // scans of a full tree can be large

export type ScaTool = "trivy" | "grype";

export interface ScaProcessResult {
  /** Process exit code (0 when unknown). */
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Injectable subprocess runner. The default shells out to the real binary; it
 * MUST reject when the binary is absent (ENOENT) so the scan fails open.
 */
export type ScaRunner = (
  bin: string,
  args: string[],
  opts: { timeoutMs: number },
) => Promise<ScaProcessResult>;

export interface ScaOptions {
  runner?: ScaRunner;
  /** Which tool's CLI/JSON schema to use. Defaults to "trivy". */
  tool?: ScaTool;
  /** Executable name or path. Defaults to the tool name. */
  binary?: string;
  /** Scan this working directory's lockfiles (pnpm-lock.yaml, package-lock.json…). */
  workspaceDir?: string;
  /** Scan this container image reference (set when a Dockerfile is present). */
  image?: string;
  timeoutMs?: number;
  /** Receives whether the scan ran, was skipped, or failed (and why). */
  onStatus?: EngineStatusFn;
}

/** Default runner: `execFile` the real binary, rejecting only when it is absent. */
const defaultRunner: ScaRunner = (bin, args, opts) =>
  new Promise((resolve, reject) => {
    execFile(
      bin,
      args,
      { timeout: opts.timeoutMs, maxBuffer: MAX_OUTPUT_BYTES, windowsHide: true },
      (err, stdout, stderr) => {
        const code = (err as (NodeJS.ErrnoException & { code?: unknown }) | null)?.code;
        // Binary not installed → reject so the caller fails open.
        if (code === "ENOENT") {
          reject(err ?? new Error("ENOENT"));
          return;
        }
        // Trivy/Grype may exit non-zero when findings exist; the JSON on stdout
        // is still valid, so resolve and let the parser decide.
        resolve({
          code: typeof code === "number" ? code : 0,
          stdout: stdout ?? "",
          stderr: stderr ?? "",
        });
      },
    );
  });

// ── Severity / risk helpers ────────────────────────────────────────────────

const RISK_RANK: Record<DependencyRisk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function worstRisk(a: DependencyRisk, b: DependencyRisk): DependencyRisk {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b;
}

/** Map a Trivy/Grype severity label ("HIGH", "High"…) to our internal scale. */
function mapSeverity(label: string | undefined): DependencyRisk {
  switch ((label ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
    case "MODERATE":
      return "medium";
    default:
      // LOW, UNKNOWN, NEGLIGIBLE, or missing.
      return "low";
  }
}

/** A dependency with a known CVE is not trustworthy regardless of its name. */
function trustForRisk(risk: DependencyRisk): number {
  switch (risk) {
    case "critical":
      return 5;
    case "high":
      return 20;
    case "medium":
      return 45;
    default:
      return 70;
  }
}

/** Normalise a package-manager/OS type to our ecosystem naming. */
function normalizeEcosystem(type: string | undefined): string {
  const t = (type ?? "").toLowerCase();
  if (["npm", "yarn", "pnpm", "node-pkg", "nodejs"].includes(t)) return "npm";
  if (["pip", "pipenv", "poetry", "python-pkg", "python"].includes(t)) return "pypi";
  if (["gomod", "gobinary", "go-module", "golang", "go"].includes(t)) return "go";
  if (["cargo", "rust-crate", "rust"].includes(t)) return "cargo";
  if (["bundler", "gemspec", "gem"].includes(t)) return "rubygems";
  if (["pom", "gradle", "jar", "java-archive", "maven"].includes(t)) return "maven";
  if (["composer", "php-composer"].includes(t)) return "packagist";
  if (["nuget", "dotnet-core"].includes(t)) return "nuget";
  // OS packages (deb, rpm, apk, debian, alpine…) and anything else pass through.
  return t || "unknown";
}

// ── Internal accumulation ───────────────────────────────────────────────────

interface ScaPackage {
  ecosystem: string;
  name: string;
  version: string;
  vulnerabilities: DependencyVulnerability[];
  license?: string;
  /** Risk derived from a restrictive license, independent of any CVE. */
  licenseRisk?: DependencyRisk;
}

function pkgKey(ecosystem: string, name: string): string {
  return `${ecosystem}\u0000${name}`;
}

function dedupeVulns(vulns: DependencyVulnerability[]): DependencyVulnerability[] {
  const byId = new Map<string, DependencyVulnerability>();
  for (const v of vulns) {
    const existing = byId.get(v.id);
    // Keep the worst severity / the entry that carries a fix version.
    if (!existing) {
      byId.set(v.id, v);
    } else {
      byId.set(v.id, {
        id: v.id,
        severity: worstRisk(existing.severity, v.severity),
        summary: existing.summary || v.summary,
        ...(existing.fixedVersion ?? v.fixedVersion
          ? { fixedVersion: existing.fixedVersion ?? v.fixedVersion }
          : {}),
      });
    }
  }
  return [...byId.values()];
}

/** Merge SCA packages that refer to the same ecosystem+name into one record. */
function accumulate(target: Map<string, ScaPackage>, pkg: ScaPackage): void {
  const key = pkgKey(pkg.ecosystem, pkg.name);
  const existing = target.get(key);
  if (!existing) {
    target.set(key, { ...pkg, vulnerabilities: [...pkg.vulnerabilities] });
    return;
  }
  existing.vulnerabilities = dedupeVulns([...existing.vulnerabilities, ...pkg.vulnerabilities]);
  if (!existing.version && pkg.version) existing.version = pkg.version;
  if (!existing.license && pkg.license) existing.license = pkg.license;
  if (pkg.licenseRisk) {
    existing.licenseRisk = existing.licenseRisk
      ? worstRisk(existing.licenseRisk, pkg.licenseRisk)
      : pkg.licenseRisk;
  }
}

// ── Trivy JSON parsing ──────────────────────────────────────────────────────

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
}
interface TrivyLicense {
  PkgName?: string;
  Name?: string;
  Severity?: string;
}
interface TrivyResult {
  Type?: string;
  Class?: string;
  Vulnerabilities?: TrivyVuln[] | null;
  Licenses?: TrivyLicense[] | null;
}
interface TrivyReport {
  Results?: TrivyResult[] | null;
}

function parseTrivy(stdout: string): ScaPackage[] {
  const report = JSON.parse(stdout) as TrivyReport;
  const acc = new Map<string, ScaPackage>();

  for (const result of report.Results ?? []) {
    const ecosystem = normalizeEcosystem(result.Type);

    for (const v of result.Vulnerabilities ?? []) {
      if (!v.PkgName) continue;
      const vuln: DependencyVulnerability = {
        id: v.VulnerabilityID ?? "UNKNOWN",
        severity: mapSeverity(v.Severity),
        summary: (v.Title ?? v.Description ?? "Vulnérabilité connue").slice(0, 300),
        ...(v.FixedVersion ? { fixedVersion: v.FixedVersion } : {}),
      };
      accumulate(acc, {
        ecosystem,
        name: v.PkgName,
        version: v.InstalledVersion ?? "",
        vulnerabilities: [vuln],
      });
    }

    for (const l of result.Licenses ?? []) {
      if (!l.PkgName || !l.Name) continue;
      const risk = mapSeverity(l.Severity);
      accumulate(acc, {
        ecosystem,
        name: l.PkgName,
        version: "",
        vulnerabilities: [],
        license: l.Name,
        // Only treat a license as a *risk* when Trivy flags it (restricted/
        // reciprocal → high/medium); permissive licenses stay informational.
        ...(risk !== "low" ? { licenseRisk: risk } : {}),
      });
    }
  }

  return [...acc.values()];
}

// ── Grype JSON parsing ──────────────────────────────────────────────────────

interface GrypeMatch {
  vulnerability?: {
    id?: string;
    severity?: string;
    description?: string;
    fix?: { versions?: string[]; state?: string };
  };
  artifact?: { name?: string; version?: string; type?: string; language?: string };
}
interface GrypeReport {
  matches?: GrypeMatch[] | null;
}

function parseGrype(stdout: string): ScaPackage[] {
  const report = JSON.parse(stdout) as GrypeReport;
  const acc = new Map<string, ScaPackage>();

  for (const m of report.matches ?? []) {
    const name = m.artifact?.name;
    if (!name) continue;
    const ecosystem = normalizeEcosystem(m.artifact?.type ?? m.artifact?.language);
    const fixed = m.vulnerability?.fix?.versions?.find((f) => Boolean(f));
    const vuln: DependencyVulnerability = {
      id: m.vulnerability?.id ?? "UNKNOWN",
      severity: mapSeverity(m.vulnerability?.severity),
      summary: (m.vulnerability?.description ?? "Vulnérabilité connue").slice(0, 300),
      ...(fixed ? { fixedVersion: fixed } : {}),
    };
    accumulate(acc, {
      ecosystem,
      name,
      version: m.artifact?.version ?? "",
      vulnerabilities: [vuln],
    });
  }

  return [...acc.values()];
}

// ── Conversion + public API ─────────────────────────────────────────────────

/** Restrictive/copyleft licenses worth surfacing even without Trivy severity. */
const RESTRICTIVE_LICENSE =
  /\b(AGPL|GPL-2|GPL-3|GPLv2|GPLv3|SSPL|BUSL|CC-BY-NC|OSL|EUPL|CDDL)\b/i;

function licenseIsRestrictive(license: string | undefined): boolean {
  return Boolean(license && RESTRICTIVE_LICENSE.test(license));
}

/** Should this scanned package be surfaced as a dependency finding? */
function isNotable(pkg: ScaPackage): boolean {
  return (
    pkg.vulnerabilities.length > 0 ||
    (pkg.licenseRisk != null && pkg.licenseRisk !== "low") ||
    licenseIsRestrictive(pkg.license)
  );
}

function toDependencyResult(pkg: ScaPackage): DependencyResult {
  const vulns = dedupeVulns(pkg.vulnerabilities);
  let risk: DependencyRisk = "low";
  for (const v of vulns) risk = worstRisk(risk, v.severity);

  const licenseRisky = licenseIsRestrictive(pkg.license) || (pkg.licenseRisk != null && pkg.licenseRisk !== "low");
  if (pkg.licenseRisk) risk = worstRisk(risk, pkg.licenseRisk);
  else if (licenseIsRestrictive(pkg.license)) risk = worstRisk(risk, "medium");

  const reasons: string[] = [];
  if (vulns.length) {
    const ids = vulns.map((v) => v.id).join(", ");
    reasons.push(`${vulns.length} vulnérabilité(s) connue(s) via SCA (${ids}).`);
  }
  if (licenseRisky && pkg.license) {
    reasons.push(`Licence « ${pkg.license} » à usage restreint (copyleft / non permissive).`);
  }

  return {
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    version: pkg.version,
    trustScore: trustForRisk(risk),
    riskLevel: risk,
    ...(vulns.length ? { vulnerabilities: vulns } : {}),
    ...(pkg.license ? { license: pkg.license } : {}),
    ...(reasons.length ? { reason: reasons.join(" ") } : {}),
  };
}

function buildTrivyArgs(target: { kind: "fs" | "image"; value: string }): string[] {
  const common = ["--quiet", "--format", "json", "--scanners", "vuln,license"];
  return target.kind === "fs"
    ? ["fs", ...common, target.value]
    : ["image", ...common, target.value];
}

function buildGrypeArgs(target: { kind: "fs" | "image"; value: string }): string[] {
  // Grype takes `dir:<path>` for a filesystem scan and a bare ref for an image.
  const source = target.kind === "fs" ? `dir:${target.value}` : target.value;
  return [source, "-o", "json", "-q"];
}

/**
 * Run the SCA tool over the configured targets (workspace lockfiles and/or a
 * container image) and return the notable dependencies (those with a known
 * vulnerability or a restrictive license), deduplicated by ecosystem+name.
 * Returns `[]` on any failure — a missing tool never blocks a PR.
 */
export async function runSca(opts: ScaOptions = {}): Promise<DependencyResult[]> {
  const tool: ScaTool = opts.tool ?? "trivy";
  const runner = opts.runner ?? defaultRunner;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const binary = opts.binary ?? tool;

  const targets: { kind: "fs" | "image"; value: string }[] = [];
  if (opts.workspaceDir) targets.push({ kind: "fs", value: opts.workspaceDir });
  if (opts.image) targets.push({ kind: "image", value: opts.image });
  if (!targets.length) {
    opts.onStatus?.("skipped", "pas de copie du dépôt à scanner");
    return [];
  }

  const merged = new Map<string, ScaPackage>();
  const failures: string[] = [];
  for (const target of targets) {
    try {
      const args = tool === "trivy" ? buildTrivyArgs(target) : buildGrypeArgs(target);
      const res = await runner(binary, args, { timeoutMs });
      if (!res.stdout.trim()) {
        failures.push("sortie vide");
        continue;
      }
      const packages = tool === "trivy" ? parseTrivy(res.stdout) : parseGrype(res.stdout);
      for (const pkg of packages) accumulate(merged, pkg);
    } catch (err) {
      // Missing binary, timeout, crash, malformed JSON — fail open for this target.
      failures.push(describeFailure(err));
    }
  }
  if (failures.length === targets.length) opts.onStatus?.("failed", failures[0]);
  else if (failures.length) opts.onStatus?.("failed", `partiel : ${failures[0]}`);
  else opts.onStatus?.("ok");

  return [...merged.values()].filter(isNotable).map(toDependencyResult);
}

/**
 * Merge SCA-discovered dependencies into the existing (OSV-enriched) list.
 * A dependency already present (same ecosystem+name) is enriched in place:
 * vulnerabilities are concatenated and deduplicated **by id**, the risk is
 * raised to the worst of the two, trust lowered to the minimum, and the
 * license filled in. New packages from the full-tree scan are appended.
 */
export function mergeScaIntoDependencies(
  base: DependencyResult[],
  sca: DependencyResult[],
): DependencyResult[] {
  const out: DependencyResult[] = base.map((d) => ({ ...d }));
  const indexByKey = new Map<string, number>();
  out.forEach((d, i) => indexByKey.set(pkgKey(d.ecosystem, d.name), i));

  for (const s of sca) {
    const key = pkgKey(s.ecosystem, s.name);
    const idx = indexByKey.get(key);
    if (idx === undefined) {
      indexByKey.set(key, out.length);
      out.push(s);
      continue;
    }
    const existing = out[idx]!;
    const vulns = dedupeVulns([...(existing.vulnerabilities ?? []), ...(s.vulnerabilities ?? [])]);
    const risk = worstRisk(existing.riskLevel, s.riskLevel);
    const reason = [existing.reason, s.reason].filter(Boolean).join(" ") || undefined;
    out[idx] = {
      ...existing,
      riskLevel: risk,
      trustScore: Math.min(existing.trustScore, s.trustScore),
      ...(vulns.length ? { vulnerabilities: vulns } : {}),
      ...(existing.license ?? s.license ? { license: existing.license ?? s.license } : {}),
      ...(reason ? { reason } : {}),
    };
  }

  return out;
}
