import type { ParsedDiff } from "./diff.js";
import type { DependencyResult } from "./types.js";

/**
 * Dependency Trust Score (cahier §5.3). Deterministic first pass:
 * typosquatting against popular packages, suspicious-name heuristics, and a
 * trust score. OSV / registry-age lookups (network) plug in later via
 * `enrichWithOsv` — kept out of the synchronous path so analysis stays fast
 * and offline-testable.
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
export function nearestPopular(name: string): { target: string; distance: number } | null {
  let best: { target: string; distance: number } | null = null;
  for (const pkg of POPULAR_NPM) {
    if (pkg === name) return null; // exact match ⇒ legitimate, not a squat
    const d = levenshtein(name, pkg);
    if (d >= 1 && d <= 2 && (!best || d < best.distance)) {
      best = { target: pkg, distance: d };
    }
  }
  return best;
}

interface DepEntry {
  name: string;
  version: string;
}

/** Extract dependency entries from the added lines of any package.json. */
export function extractAddedDependencies(diff: ParsedDiff): DepEntry[] {
  const deps: DepEntry[] = [];
  const entry = /^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*,?\s*$/;
  for (const line of diff.addedLines) {
    if (!line.file.endsWith("package.json")) continue;
    const m = line.content.match(entry);
    if (!m) continue;
    const name = m[1]!;
    const version = m[2]!;
    // Skip non-dependency fields that also look like "k": "v".
    if (["name", "version", "description", "license", "main", "module", "type"].includes(name)) {
      continue;
    }
    deps.push({ name, version });
  }
  return deps;
}

export function scoreDependency(dep: DepEntry): DependencyResult {
  const reasons: string[] = [];
  let trust = 80;
  let risk: DependencyResult["riskLevel"] = "low";

  const squat = nearestPopular(dep.name);
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
    ecosystem: "npm",
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
