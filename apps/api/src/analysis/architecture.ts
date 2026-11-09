import { posix } from "node:path";
import type { Severity } from "@codegate/shared";
import type { FindingResult, SecretResult } from "./types.js";

/**
 * Architecture analysis of a repository snapshot.
 *
 * 1. Build the internal import graph (JS/TS and Python) between source files.
 * 2. Classify each file by its role in the architecture (entry point, service,
 *    data access, authentication, configuration, UI).
 * 3. Measure how fragile the structure is — import cycles, unstable hubs,
 *    layer violations, tangled modules, oversized files, and how far the
 *    detected vulnerabilities spread — as an explained 0–100 score.
 * 4. For every vulnerability, compute its blast radius: what depends on the
 *    vulnerable code, through which entry points it can be reached, and which
 *    sensitive assets (data, auth, config) it gives access to.
 * 5. Turn the weaknesses into a prioritised, structured improvement plan with
 *    the expected gain of each step.
 *
 * Everything is static and deterministic: no code is executed, nothing leaves
 * the process. Only the summary below is stored (never the source).
 */

export type ArchRole = "entry" | "ui" | "service" | "data" | "auth" | "config";

export interface ArchModule {
  id: string;
  label: string;
  role: ArchRole;
  files: number;
  loc: number;
  /** Distinct modules that import this one / that this one imports. */
  fanIn: number;
  fanOut: number;
  /** Ce / (Ca + Ce): 0 = stable foundation, 1 = depends on everything. */
  instability: number;
  inCycle: boolean;
  sensitive: ("data" | "auth" | "config")[];
  issues: { critical: number; high: number; medium: number; low: number };
}

export interface ArchEdge {
  from: string;
  to: string;
  /** Number of file-level imports behind this module edge. */
  weight: number;
  /** Carries a file-level import cycle. */
  cycle: boolean;
  /** The two modules import each other (blurred boundary). */
  mutual: boolean;
  /** A lower layer imports a higher one (e.g. data access importing a route). */
  violation: boolean;
}

export type ImpactLevel = "critique" | "élevé" | "modéré" | "limité";

export interface BlastRadius {
  /** Stable key: fingerprint-like `kind|title|location`. */
  key: string;
  kind: "finding" | "secret";
  title: string;
  severity: Severity;
  location: string;
  module: string | null;
  /** 0–100: how much of the system an exploitation compromises. */
  impactScore: number;
  level: ImpactLevel;
  /** Files whose behaviour depends on the vulnerable code (transitively). */
  dependents: number;
  /** Share of the project's source files affected, in %. */
  reachPercent: number;
  /** Entry points (routes, pages, handlers) through which it is reachable. */
  entryPoints: string[];
  /** Sensitive files the vulnerable code can reach. */
  assets: { file: string; kind: "data" | "auth" | "config" }[];
  /** Modules to highlight on the graph. */
  impactedModules: string[];
  exposedModules: string[];
  assetModules: string[];
  narrative: string;
}

export interface FragilityFactor {
  id: "cycles" | "hubs" | "layers" | "tangles" | "exposure" | "size";
  label: string;
  points: number;
  max: number;
  detail: string;
}

export interface Proposal {
  id: string;
  priority: 1 | 2 | 3;
  title: string;
  problem: string;
  actions: string[];
  advantage: string;
  effort: "faible" | "moyen" | "élevé";
  /** Fragility points this step is expected to remove. */
  gain: number;
  targets: string[];
}

export interface ArchitectureReport {
  version: 1;
  stats: {
    sourceFiles: number;
    imports: number;
    externalPackages: number;
    entryPoints: number;
    filesInCycles: number;
    cycles: number;
    layerViolations: number;
    orphanFiles: number;
    languages: string[];
  };
  fragility: {
    score: number;
    grade: "solide" | "correcte" | "fragile" | "très fragile";
    factors: FragilityFactor[];
    summary: string;
    /** Score expected once the proposals are applied. */
    projectedScore: number;
  };
  modules: ArchModule[];
  edges: ArchEdge[];
  blast: BlastRadius[];
  proposals: Proposal[];
}

// ─── Source files & imports ────────────────────────────────────────────────

const JS_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const CODE_FILE = /\.(m?[jt]sx?|c[jt]s|py)$/i;
const TEST_FILE = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?)\/|[._-](test|spec|itest|stories)\.[a-z]+$/i;
const DECLARATION = /\.d\.[cm]?ts$/i;

export function isArchitectureSource(path: string): boolean {
  return CODE_FILE.test(path) && !TEST_FILE.test(path) && !DECLARATION.test(path);
}

const JS_IMPORT =
  /(?:^|[^\w$.])(?:import|export)\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?["']([^"'\n]+)["']|(?:^|[^\w$.])require\(\s*["']([^"'\n]+)["']\s*\)|(?:^|[^\w$.])import\(\s*["']([^"'\n]+)["']\s*\)/g;
const PY_FROM = /^[ \t]*from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+\(?([\w*, \t]+)/gm;
const PY_IMPORT = /^[ \t]*import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)/gm;

/** Remove comments so commented-out imports are not counted (strings kept). */
function stripJsComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

interface FileInfo {
  path: string;
  loc: number;
  lang: "js" | "py";
  role: ArchRole;
  entry: boolean;
  sensitive: Set<"data" | "auth" | "config">;
}

const seg = (words: string) => new RegExp(`(^|[/._-])(${words})([/._-]|$)`, "i");
const AUTH_PATH = seg("auth|authn|authz|session|sessions|jwt|password|passwords|login|oauth|crypto|token|tokens|permissions?|rbac|mfa|totp|acl");
const DATA_PATH = seg("prisma|db|database|models?|repositor(?:y|ies)|dao|orm|migrations?|entities|entity|queries|sql|store|stores|persistence");
const CONFIG_PATH = seg("config|configs|configuration|settings|env|environment");
const ENTRY_PATH =
  /(^|\/)(routes?|controllers?|handlers?|endpoints?|webhooks?|views|pages|resolvers|commands|lambdas?)\/|(^|\/)app\/(.*\/)?(page|route|layout)\.[jt]sx?$|(^|\/)(main|server|manage|wsgi|asgi|cli)\.(m?[jt]s|py)$/i;
const UI_PATH = /(^|\/)(components?|ui|widgets|hooks|layouts?)\//i;

const ENTRY_CODE =
  /\b(app|router|server|fastify|bp|blueprint)\.(get|post|put|patch|delete|route|all)\s*\(|@(app|router|bp|blueprint|api)\.(route|get|post|put|patch|delete)\(|export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|\.listen\s*\(/;
const DATA_CODE =
  /\bprisma\.\w+\.(find\w*|create\w*|update\w*|delete\w*|upsert|count|aggregate)\(|\$queryRaw|\.query\(\s*[`"']\s*(select|insert|update|delete)\b|\b(SELECT\s[\s\S]{1,80}?\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b|\bsqlalchemy\b|\bmongoose\.|\bknex\(|\bsession\.(query|execute)\(|\bcursor\.execute\(/;
const AUTH_CODE = /\b(jwt\.(sign|verify)|bcrypt|argon2|scrypt|verifyPassword|hashPassword|passport\.|createHmac|timingSafeEqual)\b/;
const ENV_READ = /process\.env\b|os\.environ|os\.getenv\(|import\.meta\.env\b/g;

function classify(path: string, content: string): Omit<FileInfo, "loc" | "lang"> {
  const sensitive = new Set<"data" | "auth" | "config">();
  if (DATA_PATH.test(path) || DATA_CODE.test(content)) sensitive.add("data");
  if (AUTH_PATH.test(path) || AUTH_CODE.test(content)) sensitive.add("auth");
  if (CONFIG_PATH.test(path) || (content.match(ENV_READ)?.length ?? 0) >= 3) sensitive.add("config");
  const entry = ENTRY_PATH.test(path) || ENTRY_CODE.test(content);
  let role: ArchRole;
  if (entry) role = "entry";
  else if (sensitive.has("auth") && AUTH_PATH.test(path)) role = "auth";
  else if (sensitive.has("data") && DATA_PATH.test(path)) role = "data";
  else if (sensitive.has("config") && CONFIG_PATH.test(path)) role = "config";
  else if (sensitive.has("auth")) role = "auth";
  else if (sensitive.has("data")) role = "data";
  else if (UI_PATH.test(path) || /\.[jt]sx$/i.test(path)) role = "ui";
  else if (sensitive.has("config")) role = "config";
  else role = "service";
  return { path, role, entry, sensitive };
}

/** Layer rank: higher layers may depend on lower ones, never the reverse. */
const RANK: Record<ArchRole, number> = { entry: 3, ui: 3, service: 2, auth: 1, data: 1, config: 1 };

class Resolver {
  private readonly set: Set<string>;
  private readonly packages = new Map<string, { dir: string; main: string | undefined }>();
  private readonly pyIndex = new Map<string, string[]>();

  constructor(paths: string[], packageJsons: { path: string; content: string }[]) {
    this.set = new Set(paths);
    for (const p of packageJsons) {
      try {
        const pkg = JSON.parse(p.content) as { name?: string; main?: string; module?: string };
        if (pkg.name) this.packages.set(pkg.name, { dir: posix.dirname(p.path), main: pkg.module ?? pkg.main });
      } catch {
        /* not JSON — ignore */
      }
    }
    for (const path of paths) {
      if (!/\.py$/i.test(path)) continue;
      const mod = path.replace(/\.py$/i, "").replace(/\/__init__$/, "").split("/");
      for (let i = 0; i < mod.length; i++) {
        const key = mod.slice(i).join(".");
        const list = this.pyIndex.get(key) ?? [];
        list.push(path);
        this.pyIndex.set(key, list);
      }
    }
  }

  private file(candidate: string): string | null {
    const c = posix.normalize(candidate).replace(/^\.\//, "");
    if (c.startsWith("..")) return null;
    if (this.set.has(c)) return c;
    const noJs = c.replace(/\.(m|c)?jsx?$/i, "");
    for (const base of noJs === c ? [c] : [noJs, c]) {
      for (const ext of JS_EXT) if (this.set.has(base + ext)) return base + ext;
      for (const ext of JS_EXT) if (this.set.has(`${base}/index${ext}`)) return `${base}/index${ext}`;
    }
    return null;
  }

  /** Resolve a JS/TS specifier; `null` = external package (or unresolvable). */
  js(from: string, spec: string): string | null {
    const dir = posix.dirname(from);
    if (spec.startsWith(".")) return this.file(posix.join(dir, spec));
    if (spec.startsWith("@/") || spec.startsWith("~/")) {
      const rest = spec.slice(2);
      // Closest ancestor that has a matching src/ (or root) path.
      for (let d = dir; ; d = posix.dirname(d)) {
        const base = d === "." ? "" : `${d}/`;
        const hit = this.file(`${base}src/${rest}`) ?? this.file(`${base}${rest}`);
        if (hit) return hit;
        if (d === "." || d === "/" || d === "") break;
      }
      return null;
    }
    // Workspace package (monorepo): "@scope/name" or "@scope/name/sub".
    const parts = spec.split("/");
    const name = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0]!;
    const pkg = this.packages.get(name);
    if (!pkg) return null;
    const sub = parts.slice(spec.startsWith("@") ? 2 : 1).join("/");
    const root = pkg.dir === "." ? "" : `${pkg.dir}/`;
    if (sub) return this.file(`${root}src/${sub}`) ?? this.file(`${root}${sub}`);
    return (
      this.file(`${root}src/index`) ??
      (pkg.main ? this.file(`${root}${pkg.main.replace(/^dist\//, "src/")}`) ?? this.file(`${root}${pkg.main}`) : null) ??
      this.file(`${root}index`)
    );
  }

  /** Resolve a Python module; `null` = external/stdlib. */
  py(from: string, module: string, names: string[]): string[] {
    const out: string[] = [];
    const lookup = (dotted: string): string | null => {
      const hits = this.pyIndex.get(dotted);
      if (!hits?.length) return null;
      if (hits.length === 1) return hits[0]!;
      // Ambiguous suffix: prefer the file sharing the longest prefix with the importer.
      const common = (a: string) => {
        let i = 0;
        while (i < a.length && i < from.length && a[i] === from[i]) i++;
        return i;
      };
      return [...hits].sort((a, b) => common(b) - common(a))[0]!;
    };
    let base = module;
    if (module.startsWith(".")) {
      const dots = module.match(/^\.+/)![0].length;
      let dir = posix.dirname(from);
      for (let i = 1; i < dots; i++) dir = posix.dirname(dir);
      const rest = module.slice(dots);
      const rel = [dir === "." ? "" : dir, rest.replace(/\./g, "/")].filter(Boolean).join("/");
      for (const n of names) {
        const sub = this.file(`${rel}/${n}.py`) ?? this.file(`${rel}/${n}/__init__.py`);
        if (sub) out.push(sub);
      }
      const self = rel ? this.file(`${rel}.py`) ?? this.file(`${rel}/__init__.py`) : null;
      if (self) out.push(self);
      return out;
    }
    for (const n of names) {
      const sub = lookup(`${base}.${n}`);
      if (sub) out.push(sub);
    }
    if (!out.length) {
      // `import a.b.c` / `from a.b import x` where only a parent is local.
      while (base) {
        const hit = lookup(base);
        if (hit) {
          out.push(hit);
          break;
        }
        base = base.includes(".") ? base.slice(0, base.lastIndexOf(".")) : "";
      }
    }
    return out;
  }
}

function extractImports(file: FileInfo, content: string, resolver: Resolver, external: Set<string>): string[] {
  const targets = new Set<string>();
  if (file.lang === "js") {
    const src = stripJsComments(content);
    for (const m of src.matchAll(JS_IMPORT)) {
      const spec = (m[1] ?? m[2] ?? m[3])!;
      const hit = resolver.js(file.path, spec);
      if (hit) targets.add(hit);
      else if (!spec.startsWith(".") && !spec.startsWith("@/") && !spec.startsWith("~/") && !spec.startsWith("node:")) {
        external.add(spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]!);
      }
    }
  } else {
    for (const m of content.matchAll(PY_FROM)) {
      const names = m[2]!.split(",").map((s) => s.trim().split(/\s+/)[0]!).filter((s) => s && s !== "*");
      const hits = resolver.py(file.path, m[1]!, names);
      hits.forEach((h) => targets.add(h));
      if (!hits.length && !m[1]!.startsWith(".")) external.add(m[1]!.split(".")[0]!);
    }
    for (const m of content.matchAll(PY_IMPORT)) {
      for (const mod of m[1]!.split(",").map((s) => s.trim())) {
        const hits = resolver.py(file.path, mod, []);
        hits.forEach((h) => targets.add(h));
        if (!hits.length) external.add(mod.split(".")[0]!);
      }
    }
  }
  targets.delete(file.path);
  return [...targets];
}

// ─── Graph algorithms ──────────────────────────────────────────────────────

/** Strongly connected components (iterative Tarjan). */
function stronglyConnected(nodes: string[], out: Map<string, string[]>): string[][] {
  let index = 0;
  const idx = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const result: string[][] = [];
  for (const start of nodes) {
    if (idx.has(start)) continue;
    const work: { v: string; i: number }[] = [{ v: start, i: 0 }];
    idx.set(start, index);
    low.set(start, index++);
    stack.push(start);
    onStack.add(start);
    while (work.length) {
      const frame = work[work.length - 1]!;
      const next = out.get(frame.v) ?? [];
      if (frame.i < next.length) {
        const w = next[frame.i++]!;
        if (!idx.has(w)) {
          idx.set(w, index);
          low.set(w, index++);
          stack.push(w);
          onStack.add(w);
          work.push({ v: w, i: 0 });
        } else if (onStack.has(w)) {
          low.set(frame.v, Math.min(low.get(frame.v)!, idx.get(w)!));
        }
      } else {
        work.pop();
        const parent = work[work.length - 1];
        if (parent) low.set(parent.v, Math.min(low.get(parent.v)!, low.get(frame.v)!));
        if (low.get(frame.v) === idx.get(frame.v)) {
          const comp: string[] = [];
          let w: string;
          do {
            w = stack.pop()!;
            onStack.delete(w);
            comp.push(w);
          } while (w !== frame.v);
          result.push(comp);
        }
      }
    }
  }
  return result;
}

function reach(start: string, adj: Map<string, string[]>): Set<string> {
  const seen = new Set<string>();
  const queue = [...(adj.get(start) ?? [])];
  while (queue.length) {
    const v = queue.pop()!;
    if (seen.has(v) || v === start) continue;
    seen.add(v);
    for (const w of adj.get(v) ?? []) if (!seen.has(w)) queue.push(w);
  }
  return seen;
}

/**
 * Group files into at most `max` display modules: start from the whole tree
 * and keep splitting the largest folder into its sub-folders while the total
 * stays readable.
 */
function groupModules(paths: string[], max = 36): Map<string, string> {
  type Group = { prefix: string[]; files: string[] };
  const dirs = new Map(paths.map((p) => [p, posix.dirname(p) === "." ? [] : posix.dirname(p).split("/")]));
  let groups: Group[] = [{ prefix: [], files: paths }];
  const splittable = (g: Group) => g.files.some((f) => dirs.get(f)!.length > g.prefix.length);
  for (;;) {
    let changed = false;
    const order = [...groups].filter(splittable).sort((a, b) => b.files.length - a.files.length);
    for (const g of order) {
      const children = new Map<string, string[]>();
      for (const f of g.files) {
        const d = dirs.get(f)!;
        const key = d.length > g.prefix.length ? d[g.prefix.length]! : "";
        children.set(key, [...(children.get(key) ?? []), f]);
      }
      if (groups.length - 1 + children.size > max) continue;
      groups = groups.filter((x) => x !== g);
      for (const [key, files] of children) groups.push({ prefix: key ? [...g.prefix, key] : g.prefix, files });
      changed = true;
      break;
    }
    if (!changed) break;
  }
  const byFile = new Map<string, string>();
  for (const g of groups) {
    const id = g.prefix.length ? g.prefix.join("/") : "(racine)";
    for (const f of g.files) byFile.set(f, id);
  }
  return byFile;
}

// ─── Report ────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 1, high: 0.8, medium: 0.5, low: 0.25, info: 0 };
const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ASSET_LABEL = { data: "données", auth: "authentification", config: "configuration" } as const;

const pct = (n: number) => Math.round(n * 100);
const clamp = (n: number, max: number) => Math.max(0, Math.min(max, Math.round(n)));
const short = (path: string) => path.split("/").slice(-2).join("/");

function secretFile(location: string): string {
  return location.replace(/:\d+(:\d+)?$/, "");
}

export function analyzeArchitecture(
  allFiles: { path: string; content: string }[],
  issues: { findings: FindingResult[]; secrets: SecretResult[] },
): ArchitectureReport {
  const sources = allFiles.filter((f) => isArchitectureSource(f.path));
  const infos = new Map<string, FileInfo>();
  for (const f of sources) {
    infos.set(f.path, {
      ...classify(f.path, f.content),
      loc: f.content.split("\n").length,
      lang: /\.py$/i.test(f.path) ? "py" : "js",
    });
  }
  const resolver = new Resolver(
    [...infos.keys()],
    allFiles.filter((f) => /(^|\/)package\.json$/.test(f.path)),
  );
  const external = new Set<string>();
  const out = new Map<string, string[]>();
  const inc = new Map<string, string[]>();
  let imports = 0;
  let deepRelative = 0;
  for (const f of sources) {
    const info = infos.get(f.path)!;
    const targets = extractImports(info, f.content, resolver, external);
    out.set(f.path, targets);
    imports += targets.length;
    deepRelative += (f.content.match(/["']\.\.\/\.\.\/\.\.\//g) ?? []).length;
    for (const t of targets) inc.set(t, [...(inc.get(t) ?? []), f.path]);
  }
  const paths = [...infos.keys()];
  const N = Math.max(1, paths.length);

  // Composition roots (app.ts, server bootstrap…) wire several entry points
  // together and are only used by entry code: they belong to the top layer.
  for (const p of paths) {
    const info = infos.get(p)!;
    if (info.entry) continue;
    const wired = (out.get(p) ?? []).filter((t) => infos.get(t)!.entry).length;
    // Imported only by entry code or by bootstrap files nobody imports
    // (index.ts / vercel.ts handlers wrapping the app).
    const onlyTop = (inc.get(p) ?? []).every((i) => infos.get(i)!.entry || !(inc.get(i)?.length));
    // A router/bootstrap wiring 3+ pages or routes is top-layer whoever imports it.
    if (wired >= 3 || (wired >= 2 && onlyTop)) {
      info.entry = true;
      info.role = "entry";
    }
  }

  // Cycles.
  const sccs = stronglyConnected(paths, out).filter((c) => c.length > 1);
  const inCycle = new Set(sccs.flat());

  // Layer violations: a lower layer importing a higher one.
  const violations: [string, string][] = [];
  for (const [from, tos] of out) {
    for (const to of tos) {
      const a = infos.get(from)!;
      const b = infos.get(to)!;
      // Only the meaningful inversion is flagged: core code (services, data,
      // auth, config) importing an entry point or UI. Data importing a helper
      // is normal.
      // A bootstrap file nobody imports sits on top by definition.
      const bootstrap = !(inc.get(from)?.length);
      if (RANK[b.role] === 3 && RANK[a.role] < 3 && !bootstrap && !(inCycle.has(from) && inCycle.has(to))) {
        violations.push([from, to]);
      }
    }
  }

  // Hubs: depended upon by many AND depending on many — changes ripple both ways.
  const hubIn = Math.max(6, Math.ceil(N * 0.1));
  const hubs = paths
    .filter((p) => (inc.get(p)?.length ?? 0) >= hubIn && (out.get(p)?.length ?? 0) >= 8)
    .sort((a, b) => (inc.get(b)!.length + out.get(b)!.length) - (inc.get(a)!.length + out.get(a)!.length));

  const godFiles = paths
    .filter((p) => infos.get(p)!.loc > 800 || (out.get(p)?.length ?? 0) >= 20)
    .sort((a, b) => infos.get(b)!.loc - infos.get(a)!.loc);

  const orphans = paths.filter(
    (p) => !(inc.get(p)?.length) && !(out.get(p)?.length) && !infos.get(p)!.entry,
  );

  // Modules for display.
  const moduleOf = groupModules(paths);
  const modIds = [...new Set(moduleOf.values())];
  const modEdges = new Map<string, ArchEdge>();
  for (const [from, tos] of out) {
    for (const to of tos) {
      const a = moduleOf.get(from)!;
      const b = moduleOf.get(to)!;
      if (a === b) continue;
      const key = `${a}→${b}`;
      const e = modEdges.get(key) ?? { from: a, to: b, weight: 0, cycle: false, mutual: false, violation: false };
      e.weight++;
      modEdges.set(key, e);
    }
  }
  for (const [from, to] of violations) {
    const e = modEdges.get(`${moduleOf.get(from)}→${moduleOf.get(to)}`);
    if (e) e.violation = true;
  }
  const sccOf = new Map<string, number>();
  sccs.forEach((c, i) => c.forEach((f) => sccOf.set(f, i)));
  for (const [from, tos] of out) {
    for (const to of tos) {
      if (!sccOf.has(from) || sccOf.get(from) !== sccOf.get(to)) continue;
      const e = modEdges.get(`${moduleOf.get(from)}→${moduleOf.get(to)}`);
      if (e) e.cycle = true;
    }
  }
  const cycleModules = new Set([...inCycle].map((f) => moduleOf.get(f)!));
  for (const e of modEdges.values()) e.mutual = modEdges.has(`${e.to}→${e.from}`);
  // A folder and its own sub-folder importing each other is often just
  // root-level files (bootstrap + config) sitting next to sub-modules: it
  // weighs less than two unrelated modules entangled.
  const nested = (a: string, b: string) => a === "(racine)" || b === "(racine)" || b.startsWith(`${a}/`) || a.startsWith(`${b}/`);
  const tangles = [...modEdges.values()].filter((e) => e.mutual && e.from < e.to);
  const tangleWeight = tangles.reduce((s, e) => s + (nested(e.from, e.to) ? 1 : 3), 0);

  // Issues per file.
  type Issue = { kind: "finding" | "secret"; title: string; severity: Severity; file: string; location: string };
  const allIssues: Issue[] = [
    ...issues.secrets.map((s) => ({
      kind: "secret" as const,
      title: `Secret exposé : ${s.secretType}`,
      severity: s.severity,
      file: secretFile(s.location),
      location: s.location,
    })),
    ...issues.findings
      .filter((f) => f.filePath && f.severity !== "info")
      .map((f) => ({
        kind: "finding" as const,
        title: f.title,
        severity: f.severity,
        file: f.filePath!,
        location: f.line ? `${f.filePath}:${f.line}` : f.filePath!,
      })),
  ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const modules: ArchModule[] = modIds.map((id) => {
    const files = paths.filter((p) => moduleOf.get(p) === id);
    const roles = new Map<ArchRole, number>();
    const sensitive = new Set<"data" | "auth" | "config">();
    for (const p of files) {
      const i = infos.get(p)!;
      roles.set(i.role, (roles.get(i.role) ?? 0) + 1);
      i.sensitive.forEach((s) => sensitive.add(s));
    }
    const priority: ArchRole[] = ["entry", "auth", "data", "config", "service", "ui"];
    const role = [...roles.entries()].sort(
      (a, b) => b[1] - a[1] || priority.indexOf(a[0]) - priority.indexOf(b[0]),
    )[0]![0];
    const fanIn = [...modEdges.values()].filter((e) => e.to === id).length;
    const fanOut = [...modEdges.values()].filter((e) => e.from === id).length;
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const iss of allIssues) {
      if (moduleOf.get(iss.file) === id && iss.severity !== "info") counts[iss.severity]++;
    }
    return {
      id,
      label: id === "(racine)" ? "(racine)" : short(id),
      role,
      files: files.length,
      loc: files.reduce((s, p) => s + infos.get(p)!.loc, 0),
      fanIn,
      fanOut,
      instability: fanIn + fanOut ? Math.round((fanOut / (fanIn + fanOut)) * 100) / 100 : 0,
      inCycle: cycleModules.has(id),
      sensitive: [...sensitive],
      issues: counts,
    };
  });

  // Blast radius of each vulnerability.
  const reverseCache = new Map<string, Set<string>>();
  const forwardCache = new Map<string, Set<string>>();
  const blast: BlastRadius[] = [];
  const seenKeys = new Set<string>();
  for (const iss of allIssues) {
    const key = `${iss.kind}|${iss.title}|${iss.location}`;
    if (seenKeys.has(key) || blast.length >= 40) continue;
    seenKeys.add(key);
    const inGraph = infos.has(iss.file);
    const up = inGraph ? reverseCache.get(iss.file) ?? reach(iss.file, inc) : new Set<string>();
    const down = inGraph ? forwardCache.get(iss.file) ?? reach(iss.file, out) : new Set<string>();
    if (inGraph) {
      reverseCache.set(iss.file, up);
      forwardCache.set(iss.file, down);
    }
    const touched = inGraph ? [iss.file, ...up] : [];
    const entryPoints = touched.filter((p) => infos.get(p)!.entry);
    const assets: BlastRadius["assets"] = [];
    for (const p of inGraph ? [iss.file, ...down] : []) {
      for (const k of infos.get(p)!.sensitive) assets.push({ file: p, kind: k });
    }
    const reachFraction = inGraph ? (up.size + 1) / N : 0;
    const assetKinds = new Set(assets.map((a) => a.kind));
    let score: number;
    if (iss.kind === "secret") {
      // A leaked credential gives direct access to the service it unlocks,
      // whatever the code structure: impact is driven by severity.
      score = SEVERITY_WEIGHT[iss.severity] * 90 + Math.min(10, entryPoints.length * 2);
    } else {
      score =
        SEVERITY_WEIGHT[iss.severity] *
        (35 * Math.min(1, reachFraction * 2.5) + 35 * (entryPoints.length ? 1 : 0.3) + 30 * Math.min(1, assetKinds.size / 2));
    }
    const impactScore = clamp(score, 100);
    const level: ImpactLevel =
      impactScore >= 70 ? "critique" : impactScore >= 45 ? "élevé" : impactScore >= 20 ? "modéré" : "limité";

    const parts: string[] = [];
    if (iss.kind === "secret") {
      parts.push(
        "Un secret exposé donne un accès direct au service qu'il protège, sans passer par le code : quiconque lit le dépôt peut l'utiliser.",
      );
      if (inGraph && up.size) {
        parts.push(`Il se trouve dans ${short(iss.file)}, embarqué par ${up.size} autre(s) fichier(s) : il sera déployé partout où ce code l'est.`);
      }
    } else if (inGraph) {
      parts.push(
        up.size
          ? `Exploitée, cette faille compromet ${up.size + 1} fichier(s) qui dépendent de ce code (${pct(reachFraction)} % du projet).`
          : "Le code vulnérable n'est importé par aucun autre fichier : la propagation interne est limitée.",
      );
      parts.push(
        entryPoints.length
          ? `Elle est atteignable depuis ${entryPoints.length} point(s) d'entrée (ex. ${short(entryPoints[0]!)}) : un attaquant externe peut la déclencher.`
          : "Aucun point d'entrée (route, page, handler) n'y mène directement : l'exploitation demande un accès interne.",
      );
      if (assetKinds.size) {
        parts.push(
          `Elle ouvre l'accès à : ${[...assetKinds].map((k) => `${ASSET_LABEL[k]} (${assets.filter((a) => a.kind === k).length})`).join(", ")}.`,
        );
      }
    } else {
      parts.push("Fichier hors du graphe de code (configuration, script, infra) : son impact dépend de l'environnement qui l'utilise.");
    }

    const mods = (list: Iterable<string>) => [...new Set([...list].map((p) => moduleOf.get(p)!).filter(Boolean))];
    blast.push({
      key,
      kind: iss.kind,
      title: iss.title,
      severity: iss.severity,
      location: iss.location,
      module: inGraph ? moduleOf.get(iss.file)! : null,
      impactScore,
      level,
      dependents: up.size,
      reachPercent: pct(reachFraction),
      entryPoints: entryPoints.slice(0, 15),
      assets: assets.slice(0, 20),
      impactedModules: mods(up),
      exposedModules: mods(entryPoints),
      assetModules: mods(assets.map((a) => a.file)),
      narrative: parts.join(" "),
    });
  }
  blast.sort((a, b) => b.impactScore - a.impactScore);

  // Fragility score.
  const cycleRatio = inCycle.size / N;
  const layerRatio = imports ? violations.length / imports : 0;
  const maxExposure = blast.reduce(
    (m, b) => Math.max(m, b.kind === "finding" ? (b.impactScore / 100) : 0),
    0,
  );
  const factors: FragilityFactor[] = [
    {
      id: "cycles",
      label: "Dépendances circulaires",
      max: 25,
      points: sccs.length ? Math.max(5, clamp(25 * Math.min(1, cycleRatio * 4), 25)) : 0,
      detail: sccs.length
        ? `${inCycle.size} fichier(s) pris dans ${sccs.length} cycle(s) d'imports (${pct(cycleRatio)} % du code) : ils ne peuvent être ni testés, ni modifiés, ni déployés séparément.`
        : "Aucun cycle d'imports.",
    },
    {
      id: "hubs",
      label: "Points de rupture (hubs)",
      max: 15,
      points: clamp(hubs.length * 5, 15),
      detail: hubs.length
        ? `${hubs.length} fichier(s) très importés qui importent aussi beaucoup (ex. ${short(hubs[0]!)}) : chaque modification s'y propage dans les deux sens.`
        : "Aucun fichier central instable.",
    },
    {
      id: "layers",
      label: "Couches non respectées",
      max: 15,
      points: violations.length ? Math.max(3, clamp(15 * Math.min(1, layerRatio * 10), 15)) : 0,
      detail: violations.length
        ? `${violations.length} import(s) vont à contre-sens (une couche basse — données, auth, config — dépend d'une couche haute — routes, pages, services).`
        : "Les dépendances suivent le sens des couches.",
    },
    {
      id: "tangles",
      label: "Désordre entre modules",
      max: 15,
      points: clamp(tangleWeight + Math.min(5, deepRelative / 10), 15),
      detail:
        tangles.length || deepRelative
          ? `${tangles.length} paire(s) de modules qui dépendent l'un de l'autre${deepRelative ? `, ${deepRelative} import(s) relatifs profonds (../../../)` : ""} : les frontières entre modules ne sont pas claires.`
          : "Les modules ont des frontières nettes.",
    },
    {
      id: "exposure",
      label: "Propagation des failles",
      max: 20,
      points: clamp(20 * maxExposure, 20),
      detail: blast.length
        ? `La faille la plus propagée a un impact de ${blast.filter((b) => b.kind === "finding")[0]?.impactScore ?? 0}/100 sur l'architecture.`
        : "Aucune faille de code à propager.",
    },
    {
      id: "size",
      label: "Fichiers surdimensionnés",
      max: 10,
      points: clamp(godFiles.length * 2.5, 10),
      detail: godFiles.length
        ? `${godFiles.length} fichier(s) de plus de 800 lignes ou 20 imports (ex. ${short(godFiles[0]!)}, ${infos.get(godFiles[0]!)!.loc} lignes) : difficiles à relire et à sécuriser.`
        : "Taille des fichiers raisonnable.",
    },
  ];
  const score = clamp(factors.reduce((s, f) => s + f.points, 0), 100);
  const grade = score < 20 ? "solide" : score < 40 ? "correcte" : score < 60 ? "fragile" : "très fragile";

  // Structured improvement plan.
  const proposals: Proposal[] = [];
  const factor = (id: FragilityFactor["id"]) => factors.find((f) => f.id === id)!;
  for (const [i, comp] of sccs.sort((a, b) => b.length - a.length).slice(0, 3).entries()) {
    const share = comp.length / Math.max(1, inCycle.size);
    proposals.push({
      id: `cycle-${i}`,
      priority: 1,
      title: `Casser le cycle entre ${comp.slice(0, 3).map(short).join(", ")}${comp.length > 3 ? ` (+${comp.length - 3})` : ""}`,
      problem: `${comp.length} fichiers s'importent mutuellement : une modification ou une faille dans l'un se répercute sur tous, et aucun ne peut être testé isolément.`,
      actions: [
        "Extraire les types et fonctions partagés dans un module commun dont les autres dépendent (sans qu'il dépende d'eux).",
        "Inverser la dépendance restante par une interface ou une injection (le module bas niveau reçoit ce dont il a besoin).",
        "Empêcher le retour du cycle en CI (règle import/no-cycle ou équivalent).",
      ],
      advantage: "Les modules deviennent testables et déployables séparément ; une faille reste confinée au lieu de contaminer tout le cycle.",
      effort: comp.length > 6 ? "élevé" : "moyen",
      gain: Math.round(factor("cycles").points * share),
      targets: comp.slice(0, 10),
    });
  }
  const exposed = blast.filter((b) => b.kind === "finding" && b.impactScore >= 45).slice(0, 3);
  for (const [i, b] of exposed.entries()) {
    proposals.push({
      id: `exposure-${i}`,
      priority: 1,
      title: `Corriger d'abord « ${b.title} » (${short(b.location)})`,
      problem: b.narrative,
      actions: [
        "Appliquer le correctif indiqué dans la liste des problèmes de code.",
        b.entryPoints.length
          ? "Valider et filtrer les entrées au niveau des points d'entrée qui y mènent."
          : "Vérifier qu'aucun chemin externe ne peut y mener.",
        "Ajouter un test de non-régression sur ce cas précis.",
      ],
      advantage: [
        b.entryPoints.length ? `Ferme ${b.entryPoints.length} chemin(s) d'attaque depuis l'extérieur` : "Supprime un risque interne",
        `, protège ${b.dependents + 1} fichier(s) qui en dépendent`,
        b.assets.length ? ` et l'accès aux ${[...new Set(b.assets.map((a) => ASSET_LABEL[a.kind]))].join(", ")}` : "",
        ".",
      ].join(""),
      effort: "faible",
      gain: i === 0 ? factor("exposure").points : 0,
      targets: [b.location],
    });
  }
  const secrets = blast.filter((b) => b.kind === "secret");
  if (secrets.length) {
    proposals.push({
      id: "secrets",
      priority: 1,
      title: `Sortir ${secrets.length} secret(s) du code`,
      problem: "Des identifiants sont écrits dans le dépôt : toute personne y ayant accès (ou toute fuite du dépôt) obtient l'accès aux services correspondants.",
      actions: [
        "Révoquer et régénérer chaque secret détecté (il doit être considéré comme compromis).",
        "Le lire depuis une variable d'environnement ou un coffre de secrets (Vault, Doppler, secrets du fournisseur cloud).",
        "Centraliser la lecture de la configuration dans un seul module validé au démarrage.",
      ],
      advantage: "Un dépôt qui fuit ne donne plus accès à la production ; la rotation des clés se fait sans toucher au code.",
      effort: "faible",
      gain: 0,
      targets: secrets.slice(0, 10).map((s) => s.location),
    });
  }
  for (const [i, h] of hubs.slice(0, 2).entries()) {
    proposals.push({
      id: `hub-${i}`,
      priority: 2,
      title: `Découper ${short(h)}`,
      problem: `Importé par ${inc.get(h)!.length} fichiers et dépendant de ${out.get(h)!.length} autres : c'est un point de rupture — une erreur ou une faille ici touche tout le système.`,
      actions: [
        "Séparer ses responsabilités en plusieurs modules ciblés (une raison de changer chacun).",
        "Faire dépendre les appelants du seul sous-module dont ils ont besoin.",
        "Réduire ses propres imports : il doit être une fondation stable, pas un carrefour.",
      ],
      advantage: "Les changements deviennent locaux, les revues plus courtes, et une faille n'a plus de point de propagation central.",
      effort: "moyen",
      gain: 5,
      targets: [h],
    });
  }
  if (violations.length) {
    const sample = violations.slice(0, 5);
    proposals.push({
      id: "layers",
      priority: 2,
      title: "Remettre les dépendances dans le bon sens",
      problem: `${violations.length} import(s) où une couche basse dépend d'une couche haute (ex. ${short(sample[0]![0])} → ${short(sample[0]![1])}) : le cœur du système dépend de son interface, il casse dès qu'elle change.`,
      actions: [
        "Déplacer le code partagé vers la couche basse (services, données) au lieu de l'importer depuis les routes ou pages.",
        "Faire passer l'information par paramètre ou par événement plutôt que par import.",
        "Documenter les couches autorisées et les vérifier en CI (dependency-cruiser, import-linter).",
      ],
      advantage: "Une architecture en couches nettes : on peut changer l'interface sans risquer le cœur métier et la sécurité.",
      effort: "moyen",
      gain: factor("layers").points,
      targets: sample.map(([a, b]) => `${a} → ${b}`),
    });
  }
  if (tangles.length) {
    proposals.push({
      id: "tangles",
      priority: 2,
      title: "Clarifier les frontières entre modules",
      problem: `${tangles.length} paire(s) de modules dépendent l'une de l'autre (ex. ${tangles[0]!.from} ⇄ ${tangles[0]!.to}) : le code est rangé par dossier mais pas organisé par responsabilité.`,
      actions: [
        "Donner à chaque module une API publique (fichier index) et n'importer que celle-ci.",
        "Regrouper ce qui change ensemble dans le même module.",
        deepRelative ? "Remplacer les imports ../../../ par des alias de chemin (@/…)." : "Fixer un sens de dépendance unique par paire de modules.",
      ],
      advantage: "Chaque équipe (ou agent IA) peut travailler sur un module sans casser les autres ; l'audit de sécurité se fait module par module.",
      effort: "moyen",
      gain: factor("tangles").points,
      targets: tangles.slice(0, 6).map((e) => `${e.from} ⇄ ${e.to}`),
    });
  }
  if (godFiles.length) {
    proposals.push({
      id: "size",
      priority: 3,
      title: `Scinder les ${godFiles.length} fichier(s) les plus volumineux`,
      problem: `Des fichiers de ${infos.get(godFiles[0]!)!.loc} lignes ou plus concentrent trop de logique : les failles y passent inaperçues en revue.`,
      actions: ["Extraire les sous-fonctions cohérentes dans des fichiers dédiés.", "Viser moins de 400 lignes par fichier."],
      advantage: "Des revues de code (humaines et IA) plus fiables, et des correctifs plus sûrs.",
      effort: "moyen",
      gain: factor("size").points,
      targets: godFiles.slice(0, 6),
    });
  }
  proposals.sort((a, b) => a.priority - b.priority || b.gain - a.gain);
  // Conservative: a plan is rarely applied perfectly, so only 80 % of the
  // announced gains are counted, and some residual fragility always remains.
  const totalGain = proposals.slice(0, 10).reduce((s, p) => s + p.gain, 0);
  const projectedScore = Math.max(Math.round(score * 0.2), score - Math.round(totalGain * 0.8));

  const worst = [...factors].sort((a, b) => b.points - a.points).filter((f) => f.points > 0);
  const summary =
    grade === "solide"
      ? "L'architecture est saine : dépendances ordonnées, peu de couplage, failles bien contenues."
      : `Architecture ${grade} (${score}/100). Principales causes : ${worst
          .slice(0, 3)
          .map((f) => f.label.toLowerCase())
          .join(", ")}.`;

  return {
    version: 1,
    stats: {
      sourceFiles: paths.length,
      imports,
      externalPackages: external.size,
      entryPoints: paths.filter((p) => infos.get(p)!.entry).length,
      filesInCycles: inCycle.size,
      cycles: sccs.length,
      layerViolations: violations.length,
      orphanFiles: orphans.length,
      languages: [...new Set([...infos.values()].map((i) => (i.lang === "py" ? "Python" : "JavaScript/TypeScript")))],
    },
    fragility: { score, grade, factors, summary, projectedScore },
    modules,
    edges: [...modEdges.values()].sort((a, b) => b.weight - a.weight).slice(0, 250),
    blast,
    proposals: proposals.slice(0, 10),
  };
}
