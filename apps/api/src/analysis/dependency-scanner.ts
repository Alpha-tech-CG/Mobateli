import type { ParsedDiff } from "./diff.js";
import type { DependencyResult } from "./types.js";

/**
 * Dependency Trust Score (cahier §5.3). Deterministic first pass:
 * typosquatting against popular packages, suspicious-name heuristics, and a
 * trust score, for npm, PyPI and Go. Network lookups (OSV, registries) live in
 * dependency-intel.ts, outside this synchronous, offline-testable path.
 */

// A small curated set of very popular npm packages for typosquat detection.
const POPULAR_NPM = [
  "react", "react-dom", "react-router-dom", "next", "vue", "svelte",
  "lodash", "axios", "express", "fastify", "chalk", "commander", "dotenv",
  "zod", "prisma", "@prisma/client", "typescript", "eslint", "jest", "vitest",
  "webpack", "vite", "rollup", "babel", "moment", "dayjs", "uuid", "bcrypt",
  "jsonwebtoken", "cors", "body-parser", "mongoose", "pg", "redis", "ioredis",
];

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j]!;
  }
  return prev[n]!;
}

/** Closest popular package within a small edit distance (a typosquat target). */
export function nearestPopular(
  name: string,
  ecosystem: DepEntry["ecosystem"] = "npm",
): { target: string; distance: number } | null {
  if (ecosystem === "Go") return null; // module paths are host-qualified
  const popular = ecosystem === "PyPI" ? POPULAR_PYPI : POPULAR_NPM;
  const normalized = ecosystem === "PyPI" ? name.toLowerCase().replace(/[_.]/g, "-") : name;
  let best: { target: string; distance: number } | null = null;
  for (const pkg of popular) {
    if (pkg === normalized) return null; // exact match ⇒ legitimate, not a squat
    const d = levenshtein(normalized, pkg);
    if (d >= 1 && d <= 2 && (!best || d < best.distance)) {
      best = { target: pkg, distance: d };
    }
  }
  return best;
}

// Popular PyPI packages: the usual typosquatting targets (requests → reqeusts).
const POPULAR_PYPI = [
  "requests", "numpy", "pandas", "django", "flask", "fastapi", "pydantic", "urllib3",
  "boto3", "setuptools", "pytest", "sqlalchemy", "cryptography", "pillow", "scipy",
  "matplotlib", "openai", "anthropic", "langchain", "httpx", "uvicorn", "celery", "redis",
];

interface DepEntry {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI" | "Go";
}

const NOT_DEPENDENCIES = new Set([
  "name", "version", "description", "license", "main", "module", "type", "python",
  "readme", "authors", "homepage", "repository", "documentation", "requires-python",
]);

/**
 * Dependencies added in the diff, per manifest: package.json (npm),
 * requirements*.txt / pyproject.toml (PyPI), go.mod (Go).
 */
export function extractAddedDependencies(diff: ParsedDiff): DepEntry[] {
  const deps: DepEntry[] = [];
  const npmEntry = /^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*,?\s*$/;
  const reqEntry = /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(?:(==|>=|~=|<=|>|<|!=)\s*([^\s;#,]+))?\s*(?:[;#].*)?$/;
  const pepEntry = /^\s*"([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(?:(==|>=|~=|<=|>|<|!=)\s*([^";,]+))?[^"]*"\s*,?\s*$/;
  const poetryEntry = /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*=\s*"([^"]+)"\s*$/;
  const goEntry = /^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+(v[0-9][^\s]*)/;

  for (const { file, content } of diff.addedLines) {
    const base = file.split("/").pop() ?? file;
    if (base === "package.json") {
      const m = content.match(npmEntry);
      if (m && !NOT_DEPENDENCIES.has(m[1]!)) deps.push({ name: m[1]!, version: m[2]!, ecosystem: "npm" });
    } else if (/^requirements.*\.txt$/.test(base)) {
      if (/^\s*(-|#|$)/.test(content) || content.includes("://")) continue;
      const m = content.match(reqEntry);
      if (m) deps.push({ name: m[1]!, version: m[3] ?? "*", ecosystem: "PyPI" });
    } else if (base === "pyproject.toml") {
      const pep = content.match(pepEntry);
      const poetry = pep ? null : content.match(poetryEntry);
      if (pep && !NOT_DEPENDENCIES.has(pep[1]!.toLowerCase())) {
        deps.push({ name: pep[1]!, version: pep[3]?.trim() ?? "*", ecosystem: "PyPI" });
      } else if (poetry && !NOT_DEPENDENCIES.has(poetry[1]!.toLowerCase())) {
        deps.push({ name: poetry[1]!, version: poetry[2]!, ecosystem: "PyPI" });
      }
    } else if (base === "go.mod") {
      const m = content.match(goEntry);
      if (m) deps.push({ name: m[1]!, version: m[2]!, ecosystem: "Go" });
    }
  }
  return deps;
}

export function scoreDependency(dep: DepEntry): DependencyResult {
  const reasons: string[] = [];
  let trust = 80;
  let risk: DependencyResult["riskLevel"] = "low";

  const squat = nearestPopular(dep.name, dep.ecosystem);
  if (squat) {
    trust -= 60;
    risk = "critical";
    reasons.push(
      `Nom très proche de "${squat.target}" (distance ${squat.distance}) — typosquatting probable.`,
    );
  }

  // Pinned to a brand-new-looking 0.0.x or using a URL/git spec.
  if (/^(git\+|https?:|file:|github:)/.test(dep.version)) {
    trust -= 25;
    if (risk === "low") risk = "medium";
    reasons.push("Source non-registre (git/url) — contenu non vérifié par le registre.");
  }

  // Suspicious name shapes (install-script bait, random suffixes).
  if (/(preinstall|postinstall|setup|bootstrap)/i.test(dep.name)) {
    trust -= 15;
    if (risk === "low") risk = "medium";
    reasons.push("Nom évoquant un script d'installation.");
  }

  trust = Math.max(0, Math.min(100, trust));
  if (risk === "low" && trust < 50) risk = "medium";

  return {
    ecosystem: dep.ecosystem,
    name: dep.name,
    version: dep.version,
    trustScore: trust,
    riskLevel: risk,
    ...(reasons.length ? { reason: reasons.join(" ") } : {}),
  };
}

export function scanDependencies(diff: ParsedDiff): DependencyResult[] {
  return extractAddedDependencies(diff).map(scoreDependency);
}
