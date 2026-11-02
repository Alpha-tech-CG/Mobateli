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

export async function enrichDependencies(
  deps: DependencyResult[],
  fetchImpl: typeof fetch = fetch,
  now = new Date(),
): Promise<DependencyResult[]> {
  const npm = deps.filter((d) => d.ecosystem === "npm").slice(0, MAX_PACKAGES);
  if (!npm.length) return deps;

  // One OSV batch call for all packages.
  const versions = npm.map((d) => baseVersion(d.version));
  const osv = await getJson<{ results: { vulns?: { id: string }[] }[] }>(
    fetchImpl,
    "https://api.osv.dev/v1/querybatch",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: npm.map((d, i) => ({
          package: { name: d.name, ecosystem: "npm" },
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
        risk = raise(risk, worst);
        trust -= worst === "critical" ? 50 : worst === "high" ? 35 : 20;
        reasons.push(
          `${ids.length} vulnérabilité(s) connue(s) pour ${dep.name}@${versions[i] ?? dep.version} : ${ids
            .slice(0, 3)
            .join(", ")}${ids.length > 3 ? "…" : "."}`,
        );
      }

      // ── Registry metadata ──
      const [doc, downloads] = await Promise.all([
        getJson<NpmDoc>(fetchImpl, `https://registry.npmjs.org/${encodeURIComponent(dep.name).replace("%40", "@")}`),
        getJson<{ downloads?: number }>(
          fetchImpl,
          `https://api.npmjs.org/downloads/point/last-week/${dep.name}`,
        ),
      ]);
      if (doc.status === 404) {
        return {
          ...dep,
          trustScore: 0,
          riskLevel: "critical" as const,
          reason: [
            ...reasons,
            "Ce paquet n'existe pas sur npm : nom probablement inventé par l'IA (un attaquant peut le publier).",
          ].join(" "),
        };
      }
      if (doc.body) {
        const created = doc.body.time?.created ? new Date(doc.body.time.created) : null;
        if (created && now.getTime() - created.getTime() < 30 * DAY) {
          trust -= 25;
          risk = raise(risk, "medium");
          const days = Math.max(0, Math.round((now.getTime() - created.getTime()) / DAY));
          reasons.push(`Publié il y a ${days} jour(s).`);
        }
        const maintainers = doc.body.maintainers?.length ?? 0;
        if (maintainers === 1) {
          trust -= 5;
          reasons.push("Un seul mainteneur.");
        }
        const license =
          typeof doc.body.license === "string" ? doc.body.license : doc.body.license?.type;
        if (!license) reasons.push("Aucune licence déclarée.");
        const latest = doc.body["dist-tags"]?.latest;
        const scripts = latest ? doc.body.versions?.[latest]?.scripts : undefined;
        const hooks = ["preinstall", "install", "postinstall"].filter((h) => scripts?.[h]);
        if (hooks.length) {
          trust -= 15;
          risk = raise(risk, "medium");
          reasons.push(`Exécute du code à l'installation (${hooks.join(", ")}).`);
        }
      }
      const weekly = downloads.body?.downloads;
      if (weekly !== undefined && weekly < 100) {
        trust -= 15;
        risk = raise(risk, "medium");
        reasons.push(`Très peu utilisé (${weekly} téléchargements / semaine).`);
      }

      trust = Math.max(0, Math.min(100, trust));
      return { ...dep, trustScore: trust, riskLevel: risk, ...(reasons.length ? { reason: reasons.join(" ") } : {}) };
    }),
  );

  const byKey = new Map(enriched.map((d) => [`${d.name}@${d.version}`, d]));
  return deps.map((d) => byKey.get(`${d.name}@${d.version}`) ?? d);
}
