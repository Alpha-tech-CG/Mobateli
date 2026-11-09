import type { DependencyRisk } from "@codegate/shared";
import type { DependencyResult } from "./types.js";

/**
 * Network enrichment of the Dependency Trust Score (cahier §5.3, US04):
 * known vulnerabilities (OSV), package age, maintainers, popularity, licence,
 * install scripts — and packages that do not exist at all (names hallucinated
 * by an AI agent, a squatting target). Best effort: any network failure
 * leaves the deterministic score untouched.
 */

const TIMEOUT_MS = 5_000;
const MAX_PACKAGES = 20;
const DAY = 86_400_000;
const RANK: Record<DependencyRisk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const raise = (a: DependencyRisk, b: DependencyRisk): DependencyRisk => (RANK[b] > RANK[a] ? b : a);

/** "^1.2.3" / "~1.2" / ">=2.0.0" → "1.2.3" (lowest version the range admits). */
export function baseVersion(spec: string): string | null {
  const m = spec.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return `${m[1]}.${m[2] ?? "0"}.${m[3] ?? "0"}`;
}

interface OsvVuln {
  id: string;
  summary?: string;
  database_specific?: { severity?: string };
}

function osvSeverity(v: OsvVuln): DependencyRisk {
  switch ((v.database_specific?.severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    default:
      return "medium"; // unknown severity: still a known vulnerability
  }
}

async function getJson<T>(fetchImpl: typeof fetch, url: string, init?: RequestInit): Promise<{ status: number; body: T | null }> {
  try {
    const res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) return { status: res.status, body: null };
    return { status: res.status, body: (await res.json()) as T };
  } catch {
    return { status: 0, body: null };
  }
}

interface NpmDoc {
  time?: Record<string, string>;
  maintainers?: unknown[];
  license?: string | { type?: string };
  versions?: Record<string, { scripts?: Record<string, string> }>;
  "dist-tags"?: { latest?: string };
}

/** workspace:/link:/file:/portal: — resolved locally, not from a registry. */
export function isLocalSpec(version: string): boolean {
  return /^(workspace|link|file|portal):/.test(version.trim());
}

const REGISTRY_NAME: Record<string, string> = { npm: "npm", PyPI: "PyPI", Go: "le proxy Go" };

interface RegistryFacts {
  missing: boolean;
  created?: Date;
  maintainers?: number;
  /** null = no licence declared; undefined = unknown. */
  license?: string | null;
  installHooks: string[];
  weeklyDownloads?: number;
}

interface PypiDoc {
  info?: { license?: string | null; license_expression?: string | null; classifiers?: string[] };
  releases?: Record<string, { upload_time_iso_8601?: string }[]>;
}

/** Go module paths escape capitals as "!x" on the module proxy. */
const goEscape = (path: string) => path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

/**
 * An install script that runs nothing: `echo '…'`, `true`, `exit 0`, `:`,
 * or a chain of those (e.g. @google/genai's "echo 'preinstall: no-op'").
 */
export function isNoOpScript(script: string): boolean {
  return script
    .split(/&&|;|\|\|/)
    .map((part) => part.trim())
    .every((part) => part === "" || /^(echo(\s.*)?|true|:|exit\s+0|node\s+-e\s+(['"])\s*\3)$/.test(part));
}

async function registryFacts(fetchImpl: typeof fetch, dep: DependencyResult): Promise<RegistryFacts> {
  if (dep.ecosystem === "npm") {
    const [doc, downloads] = await Promise.all([
      getJson<NpmDoc>(fetchImpl, `https://registry.npmjs.org/${encodeURIComponent(dep.name).replace("%40", "@")}`),
      getJson<{ downloads?: number }>(fetchImpl, `https://api.npmjs.org/downloads/point/last-week/${dep.name}`),
    ]);
    if (doc.status === 404) return { missing: true, installHooks: [] };
    const body = doc.body;
    const license = body ? (typeof body.license === "string" ? body.license : body.license?.type) ?? null : undefined;
    // The installed version's scripts when the lockfile told us, else latest.
    const latest = body?.["dist-tags"]?.latest;
    const version = dep.resolvedVersion && body?.versions?.[dep.resolvedVersion] ? dep.resolvedVersion : latest;
    const scripts = version ? body?.versions?.[version]?.scripts : undefined;
    return {
      missing: false,
      ...(body?.time?.created ? { created: new Date(body.time.created) } : {}),
      ...(body ? { maintainers: body.maintainers?.length ?? 0 } : {}),
      ...(license !== undefined ? { license } : {}),
      installHooks: ["preinstall", "install", "postinstall"].filter((h) => {
        const script = scripts?.[h];
        return typeof script === "string" && !isNoOpScript(script);
      }),
      ...(downloads.body?.downloads !== undefined ? { weeklyDownloads: downloads.body.downloads } : {}),
    };
  }
  if (dep.ecosystem === "PyPI") {
    const doc = await getJson<PypiDoc>(fetchImpl, `https://pypi.org/pypi/${encodeURIComponent(dep.name)}/json`);
    if (doc.status === 404) return { missing: true, installHooks: [] };
    const uploads = Object.values(doc.body?.releases ?? {})
      .flat()
      .map((f) => f.upload_time_iso_8601)
      .filter((t): t is string => Boolean(t))
      .sort();
    const info = doc.body?.info;
    const license = info
      ? (info.license_expression || info.license || (info.classifiers ?? []).find((c) => c.startsWith("License ::")) || null)
      : undefined;
    return {
      missing: false,
      ...(uploads[0] ? { created: new Date(uploads[0]) } : {}),
      ...(license !== undefined ? { license } : {}),
      installHooks: [],
    };
  }
  if (dep.ecosystem === "Go") {
    const list = await getJson<unknown>(fetchImpl, `https://proxy.golang.org/${goEscape(dep.name)}/@v/list`);
    return { missing: list.status === 404 || list.status === 410, installHooks: [] };
  }
  return { missing: false, installHooks: [] };
}

export async function enrichDependencies(
  deps: DependencyResult[],
  fetchImpl: typeof fetch = fetch,
  now = new Date(),
): Promise<DependencyResult[]> {
  const npm = deps
    .filter((d) => d.ecosystem === "npm" || d.ecosystem === "PyPI" || d.ecosystem === "Go")
    // Local monorepo / path packages are never fetched from a registry.
    .filter((d) => !isLocalSpec(d.version))
    .slice(0, MAX_PACKAGES);
  if (!npm.length) return deps;

  // One OSV batch call for all packages.
  // The installed version when a lockfile told us, else the range's floor.
  const versions = npm.map((d) => d.resolvedVersion ?? baseVersion(d.version));
  const osv = await getJson<{ results: { vulns?: { id: string }[] }[] }>(
    fetchImpl,
    "https://api.osv.dev/v1/querybatch",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: npm.map((d, i) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          ...(versions[i] ? { version: versions[i] } : {}),
        })),
      }),
    },
  );

  const enriched = await Promise.all(
    npm.map(async (dep, i) => {
      const reasons: string[] = dep.reason ? [dep.reason] : [];
      let trust = dep.trustScore;
      let risk = dep.riskLevel;

      // ── Known vulnerabilities ──
      const ids = (osv.body?.results?.[i]?.vulns ?? []).map((v) => v.id);
      if (ids.length) {
        const details = await Promise.all(
          ids.slice(0, 5).map((id) => getJson<OsvVuln>(fetchImpl, `https://api.osv.dev/v1/vulns/${id}`)),
        );
        let worst: DependencyRisk = "medium";
        for (const d of details) if (d.body) worst = raise(worst, osvSeverity(d.body));
        // A development dependency is not shipped: its known vulnerabilities
        // are not a production risk (observation). Malicious-package signals
        // below still count — install scripts run on CI and dev machines.
        risk = raise(risk, dep.dev ? "medium" : worst);
        trust -= worst === "critical" ? 50 : worst === "high" ? 35 : 20;
        reasons.push(
          `${ids.length} vulnérabilité(s) connue(s) pour ${dep.name}@${versions[i] ?? dep.version} : ${ids
            .slice(0, 3)
            .join(", ")}${ids.length > 3 ? "…" : "."}`,
        );
      }

      // ── Registry metadata ──
      const registry = await registryFacts(fetchImpl, dep);
      if (registry.missing) {
        // Unknown to the registry: probably a name invented by an AI agent,
        // which an attacker could publish. Not proven malicious — a human
        // checks it before anyone installs it.
        return {
          ...dep,
          trustScore: 0,
          riskLevel: "high" as const,
          reason: [
            ...reasons,
            `Ce paquet n'existe pas sur ${REGISTRY_NAME[dep.ecosystem] ?? dep.ecosystem} : nom probablement inventé par l'IA (un attaquant peut le publier).`,
          ].join(" "),
        };
      }
      // A long-lived, massively used package: one maintainer or a native
      // install step (node-gyp) are normal, not risk signals. Known
      // vulnerabilities above still count.
      const established =
        registry.created !== undefined &&
        now.getTime() - registry.created.getTime() > 2 * 365 * DAY &&
        (registry.weeklyDownloads ?? 0) >= 50_000;
      if (registry.created && now.getTime() - registry.created.getTime() < 30 * DAY) {
        trust -= 25;
        risk = raise(risk, "medium");
        const days = Math.max(0, Math.round((now.getTime() - registry.created.getTime()) / DAY));
        reasons.push(`Publié il y a ${days} jour(s).`);
      }
      if (registry.maintainers === 1 && !established) {
        trust -= 5;
        reasons.push("Un seul mainteneur.");
      }
      if (registry.license === null) reasons.push("Aucune licence déclarée.");
      if (registry.installHooks.length && !established) {
        trust -= 15;
        risk = raise(risk, "medium");
        reasons.push(`Exécute du code à l'installation (${registry.installHooks.join(", ")}).`);
      }
      if (registry.weeklyDownloads !== undefined && registry.weeklyDownloads < 100) {
        trust -= 15;
        risk = raise(risk, "medium");
        reasons.push(`Très peu utilisé (${registry.weeklyDownloads} téléchargements / semaine).`);
      }
      // Several critical signals together: a name imitating a popular
      // package AND code run at install time, or AND a brand-new / barely
      // used package. Each alone only warns; together they block.
      const fresh = registry.created !== undefined && now.getTime() - registry.created.getTime() < 30 * DAY;
      const unused = registry.weeklyDownloads !== undefined && registry.weeklyDownloads < 100;
      if (dep.typosquatOf && (registry.installHooks.length > 0 || fresh || unused)) {
        risk = "critical";
        reasons.push(`Plusieurs signaux critiques réunis : imitation de "${dep.typosquatOf}" et paquet ${registry.installHooks.length ? "exécutant du code à l'installation" : fresh ? "publié très récemment" : "presque inutilisé"}.`);
      }

      trust = Math.max(0, Math.min(100, trust));
      return { ...dep, trustScore: trust, riskLevel: risk, ...(reasons.length ? { reason: reasons.join(" ") } : {}) };
    }),
  );

  const byKey = new Map(enriched.map((d) => [`${d.name}@${d.version}`, d]));
  return deps.map((d) => byKey.get(`${d.name}@${d.version}`) ?? d);
}
