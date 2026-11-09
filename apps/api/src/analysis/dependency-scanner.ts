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
  // Frequent typosquatting targets (names ≥ 6 chars to keep short-name
  // collisions out — see the length rule in nearestPopular).
  "cross-env", "request", "node-fetch", "nodemon", "rimraf", "mkdirp", "semver",
  "yargs", "inquirer", "minimist", "underscore", "jquery", "socket.io", "mysql2",
  "sequelize", "typeorm", "graphql", "nodemailer", "multer", "passport", "helmet",
  "cookie-parser", "express-session", "tailwindcss", "postcss", "autoprefixer",
  "prettier", "ts-node", "electron", "puppeteer", "playwright", "cheerio",
  "coffee-script", "event-stream", "discord.js", "web3", "ethers",
];

// Well-known, legitimate packages whose names happen to sit a short edit
// distance from a popular one (preact≈react, redux≈redis, knex≈next…). Without
// this list a pure edit-distance check flags them as critical typosquats and
// blocks the PR — the dominant source of false positives. Exact matches here
// are never treated as suspicious.
const KNOWN_LEGIT = new Set([
  "preact", "redux", "@reduxjs/toolkit", "react-redux", "bootstrap",
  "knex", "yup", "joi", "jose", "got", "ky", "ora", "zx", "chai", "mocha",
  "nanoid", "esbuild", "tslib", "clsx", "swr", "mobx", "luxon", "undici",
  "pino", "cosmiconfig", "picocolors", "date-fns",
]);

/**
 * Edit distance where swapping two adjacent letters counts as one typo
 * (optimal string alignment): "lodahs" is 1 away from "lodash".
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...new Array<number>(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return d[m]![n]!;
}

/** Same edit distance under main's name (benchmarks and tests use it). */
export const editDistance = levenshtein;

/** Name with separators dropped: `crossenv` and `cross-env` collide. */
const squash = (name: string) => name.replace(/[-_.]/g, "");

/** Closest popular package within a small edit distance (a typosquat target). */
export function nearestPopular(
  name: string,
  ecosystem: DepEntry["ecosystem"] = "npm",
): { target: string; distance: number } | null {
  if (ecosystem === "Go") return null; // module paths are host-qualified
  if (ecosystem === "npm" && KNOWN_LEGIT.has(name)) return null; // preact, redux, knex…
  const popular = ecosystem === "PyPI" ? POPULAR_PYPI : POPULAR_NPM;
  const normalized = ecosystem === "PyPI" ? name.toLowerCase().replace(/[_.]/g, "-") : name;
  let best: { target: string; distance: number } | null = null;
  for (const pkg of popular) {
    if (pkg === normalized) return null; // exact match ⇒ legitimate, not a squat
  }
  for (const pkg of popular) {
    // Same name once separators are dropped (`crossenv` vs `cross-env`): the
    // classic squat of a hyphenated package — one edit, whatever the length.
    if (squash(pkg) === squash(normalized) && pkg.length >= 5) {
      return { target: pkg, distance: 1 };
    }
    const d = levenshtein(normalized, pkg);
    const shortest = Math.min(normalized.length, pkg.length);
    // ≤ 4 letters: any two names are a couple of edits apart — no signal.
    const allowed = shortest <= 4 ? 0 : shortest <= 7 ? 1 : 2;
    if (d >= 1 && d <= allowed && (!best || d < best.distance)) {
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
  // package.json keys whose values look like versions but are not packages.
  "node", "npm", "pnpm", "yarn", "bun", "packageManager", "url", "funding", "bugs", "types",
]);

const NPM_SECTIONS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

/** "^1.2.3", ">= 2 < 3", "*", "latest", "workspace:*", "npm:x@1", git/url/file specs. */
export function looksLikeVersionSpec(v: string): boolean {
  const t = v.trim();
  if (/^(workspace:|npm:|git\+|git:|github:|https?:|file:|link:)/.test(t)) return true;
  if (t === "*" || t === "latest" || t === "next" || t === "x") return true;
  return /^[\^~<>=v]*\s*\d/.test(t) && /^[\w\s.^~<>=|*+-]+$/.test(t) && !/\s[a-z]{3,}/i.test(t);
}

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

  // Whole package.json available (repository scans): read the real sections.
  const parsedManifests = new Set<string>();
  for (const [file, text] of diff.addedByFile) {
    if ((file.split("/").pop() ?? file) !== "package.json") continue;
    try {
      const pkg = JSON.parse(text) as Record<string, unknown>;
      for (const section of NPM_SECTIONS) {
        const block = pkg[section];
        if (!block || typeof block !== "object") continue;
        for (const [name, version] of Object.entries(block as Record<string, unknown>)) {
          if (typeof version === "string") deps.push({ name, version, ecosystem: "npm" });
        }
      }
      parsedManifests.add(file);
    } catch {
      /* only added lines (a PR diff): fall back to the line heuristic */
    }
  }

  for (const { file, content } of diff.addedLines) {
    const base = file.split("/").pop() ?? file;
    if (base === "package.json") {
      if (parsedManifests.has(file)) continue;
      const m = content.match(npmEntry);
      // Scripts ("test": "mocha …"), engines and URLs are not dependencies:
      // keep entries whose value looks like a version specifier.
      if (m && !NOT_DEPENDENCIES.has(m[1]!) && looksLikeVersionSpec(m[2]!)) {
        deps.push({ name: m[1]!, version: m[2]!, ecosystem: "npm" });
      }
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

  // Known-legitimate npm packages skip every name heuristic (e.g. "bootstrap"
  // read as an install-script bait, "preact" as a squat of "react").
  if (dep.ecosystem === "npm" && KNOWN_LEGIT.has(dep.name)) {
    return { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, trustScore: trust, riskLevel: "low" };
  }

  const squat = nearestPopular(dep.name, dep.ecosystem);
  if (squat) {
    trust -= 60;
    risk = "critical";
    reasons.push(
      `Nom très proche de "${squat.target}" (distance ${squat.distance}) — typosquatting probable.`,
    );
  }

  // Pinned to a brand-new-looking 0.0.x or using a URL/git spec.
  // Remote, unpinned sources (git / URL); local file: paths are the user's own code.
  if (/^(git\+|git:|https?:|github:)/.test(dep.version)) {
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
