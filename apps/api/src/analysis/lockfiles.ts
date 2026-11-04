import type { DependencyResult } from "./types.js";

/**
 * Installed versions from lockfiles (npm, pnpm, Yarn).
 *
 * A manifest declares a range ("fastify": "^5.2.1"); what runs is the version
 * the lockfile pins (5.12.7). Checking vulnerabilities against the lowest
 * version of the range reports flaws long fixed in the installed version, so
 * when a lockfile is present we evaluate the version it actually resolved.
 */

export const LOCKFILE_NAMES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]);

export function isLockfile(path: string): boolean {
  return LOCKFILE_NAMES.has(path.split("/").pop() ?? path);
}

/** Every version pinned for each npm package name, across all lockfiles. */
export function lockedNpmVersions(files: { path: string; content: string }[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (name: string, version: string) => {
    const v = version.trim().replace(/^v/, "").replace(/\(.*$/, ""); // pnpm peer suffix "1.2.3(react@19)"
    if (!/^\d+\.\d+\.\d+/.test(v)) return; // link:, workspace:, git urls…
    let set = out.get(name);
    if (!set) out.set(name, (set = new Set()));
    set.add(v);
  };
  for (const f of files) {
    const base = f.path.split("/").pop() ?? f.path;
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      try {
        const lock = JSON.parse(f.content) as {
          packages?: Record<string, { version?: string }>;
          dependencies?: Record<string, { version?: string }>;
        };
        for (const [key, pkg] of Object.entries(lock.packages ?? {})) {
          const i = key.lastIndexOf("node_modules/");
          if (i !== -1 && pkg.version) add(key.slice(i + "node_modules/".length), pkg.version);
        }
        for (const [name, pkg] of Object.entries(lock.dependencies ?? {})) if (pkg.version) add(name, pkg.version);
      } catch {
        /* malformed lockfile: ignore */
      }
    } else if (base === "pnpm-lock.yaml") {
      // packages / snapshots keys: "  fastify@5.12.7:" or "  '@scope/x@1.2.3':"
      for (const m of f.content.matchAll(/^ {2}'?((?:@[^@\s/']+\/)?[^@\s/']+)@(\d[^:'\s]*)'?:\s*$/gm)) add(m[1]!, m[2]!);
      // importers: "      fastify:\n        specifier: ^5.2.1\n        version: 5.12.7"
      for (const m of f.content.matchAll(/^ {6}'?((?:@[^@\s/']+\/)?[^@\s/':]+)'?:\n {8}specifier: .*\n {8}version: (\S+)/gm)) {
        add(m[1]!, m[2]!);
      }
    } else if (base === "yarn.lock") {
      // "fastify@^5.2.1", "fastify@^5.0.0":\n  version "5.12.7"
      for (const m of f.content.matchAll(/^"?((?:@[^@\s/"]+\/)?[^@\s/"]+)@[^\n]*:\n {2}version:? "?([^"\n]+)"?/gm)) {
        add(m[1]!, m[2]!);
      }
    }
  }
  return out;
}

type Triple = [number, number, number];
const parse = (v: string): Triple | null => {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
};
const cmp = (a: Triple, b: Triple) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/** Does `version` satisfy a simple npm range (^, ~, exact, >=, *, x)? */
export function satisfies(version: string, range: string): boolean {
  const v = parse(version);
  if (!v) return false;
  const r = range.trim();
  if (r === "" || r === "*" || r === "latest" || /^x$/i.test(r)) return true;
  return r.split("||").some((part) =>
    part
      .trim()
      .split(/\s+/)
      .every((c) => {
        const m = /^(\^|~|>=|<=|>|<|=)?v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?/.exec(c);
        if (!m) return true;
        const op = m[1] ?? "";
        const major = Number(m[2]);
        const minorWild = m[3] === undefined || m[3] === "x" || m[3] === "*";
        const patchWild = m[4] === undefined || m[4] === "x" || m[4] === "*";
        const base: Triple = [major, minorWild ? 0 : Number(m[3]), patchWild ? 0 : Number(m[4])];
        const c0 = cmp(v, base);
        switch (op) {
          case "^": {
            if (c0 < 0) return false;
            if (base[0] > 0 || minorWild) return v[0] === base[0];
            if (base[1] > 0 || patchWild) return v[0] === 0 && v[1] === base[1];
            return v[0] === 0 && v[1] === 0 && v[2] === base[2];
          }
          case "~":
            return c0 >= 0 && v[0] === base[0] && (minorWild || v[1] === base[1]);
          case ">=":
            return c0 >= 0;
          case ">":
            return c0 > 0;
          case "<=":
            return c0 <= 0;
          case "<":
            return c0 < 0;
          default:
            // "1.2.3" exact, "1.2" / "1.x" partial.
            if (minorWild) return v[0] === base[0];
            if (patchWild) return v[0] === base[0] && v[1] === base[1];
            return c0 === 0;
        }
      }),
  );
}

/**
 * Attach the installed version to each npm dependency: the highest locked
 * version that satisfies its declared range. Unresolvable ones are untouched
 * (they keep being evaluated on the range's lowest version).
 */
export function resolveInstalledVersions(
  deps: DependencyResult[],
  locked: Map<string, Set<string>>,
): DependencyResult[] {
  if (!locked.size) return deps;
  return deps.map((d) => {
    if (d.ecosystem !== "npm") return d;
    const candidates = [...(locked.get(d.name) ?? [])]
      .filter((v) => satisfies(v, d.version))
      .map((v) => [v, parse(v)!] as const)
      .sort((a, b) => cmp(b[1], a[1]));
    return candidates.length ? { ...d, resolvedVersion: candidates[0]![0] } : d;
  });
}

/** One entry per package and evaluated version (monorepos repeat dependencies). */
export function dedupeDependencies(deps: DependencyResult[]): DependencyResult[] {
  const seen = new Set<string>();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}@${d.resolvedVersion ?? d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
