import type { DependencyRisk } from "@codegate/shared";
import type { DependencyResult, DependencyVulnerability, EngineStatusFn } from "./types.js";

/**
 * OSV enrichment (cahier §5.3, §9.3 — base de vulnérabilités OSV).
 *
 * Turns the deterministic dependency pass into a real audit by checking each
 * added dependency against the public OSV database (https://osv.dev), which
 * aggregates CVE / GHSA advisories for npm and other ecosystems. This is the
 * single biggest step from heuristic to professional-grade dependency review.
 *
 * It is kept out of the synchronous analysis core on purpose: it does network
 * I/O, so the worker calls it explicitly, it fails open (an OSV outage never
 * blocks a PR on a false premise), and it is fully mockable in tests via the
 * injectable `fetchImpl`.
 */

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const DEFAULT_TIMEOUT_MS = 4000;

/** OSV ecosystem names differ from our internal ones in casing/spelling. */
const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  pip: "PyPI",
  cargo: "crates.io",
  go: "Go",
  maven: "Maven",
  rubygems: "RubyGems",
};

type FetchImpl = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

export interface OsvOptions {
  fetchImpl?: FetchImpl;
  timeoutMs?: number;
  /** Receives whether the lookup ran, was skipped, or (partly) failed. */
  onStatus?: EngineStatusFn;
  /** Called by `queryOsv` when one query could not be answered. */
  onQueryFailure?: (detail: string) => void;
}

interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  severity?: { type?: string; score?: string }[];
  affected?: {
    database_specific?: { severity?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
}

/** Map a GHSA/OSV severity label to our internal risk scale. */
function mapSeverityLabel(label: string | undefined): DependencyRisk {
  switch ((label ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      // A confirmed advisory with no label is still at least "high" — the
      // presence of a known vulnerability is itself a strong signal.
      return "high";
  }
}

const RISK_RANK: Record<DependencyRisk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function worstRisk(a: DependencyRisk, b: DependencyRisk): DependencyRisk {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b;
}

function parseVuln(v: OsvVuln): DependencyVulnerability {
  const label =
    v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  const fixed = v.affected
    ?.flatMap((a) => a.ranges ?? [])
    .flatMap((r) => r.events ?? [])
    .map((e) => e.fixed)
    .find((f): f is string => Boolean(f));
  return {
    id: v.id ?? "UNKNOWN",
    severity: mapSeverityLabel(label),
    summary: (v.summary ?? v.details ?? "Vulnérabilité connue").slice(0, 300),
    ...(fixed ? { fixedVersion: fixed } : {}),
  };
}

/** Query OSV for a single package@version. Returns [] on any failure. */
export async function queryOsv(
  ecosystem: string,
  name: string,
  version: string,
  opts: OsvOptions = {},
): Promise<DependencyVulnerability[]> {
  const osvEcosystem = ECOSYSTEM_MAP[ecosystem.toLowerCase()];
  // Only query for a concrete version in a known ecosystem (ranges/URLs skip).
  if (!osvEcosystem || !/^\d/.test(version.replace(/^[\^~>=<\s]*/, ""))) return [];
  const cleanVersion = version.replace(/^[\^~>=<\s]*/, "").trim();

  const fetchImpl = (opts.fetchImpl ?? (globalThis.fetch as unknown as FetchImpl));
  if (!fetchImpl) return [];

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetchImpl(OSV_QUERY_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: cleanVersion, package: { name, ecosystem: osvEcosystem } }),
      signal: controller.signal,
    });
    if (!res.ok) {
      opts.onQueryFailure?.(`HTTP ${res.status}`);
      return [];
    }
    const data = (await res.json()) as { vulns?: OsvVuln[] };
    if (!data.vulns?.length) return [];
    return data.vulns.map(parseVuln);
  } catch (err) {
    // Timeout, network error, malformed response — fail open.
    opts.onQueryFailure?.(
      (err as { name?: string })?.name === "AbortError" ? "délai dépassé" : "réseau indisponible",
    );
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Enrich a list of dependency results with known vulnerabilities from OSV.
 * Returns a new list; dependencies are left untouched when OSV is unreachable.
 * Queries run concurrently (bounded by the small number of deps in a PR).
 */
export async function enrichDependenciesWithOsv(
  deps: DependencyResult[],
  opts: OsvOptions = {},
): Promise<DependencyResult[]> {
  if (!deps.length) {
    opts.onStatus?.("skipped", "aucune dépendance ajoutée");
    return deps;
  }
  const failures: string[] = [];
  const queryOpts = { ...opts, onQueryFailure: (d: string) => failures.push(d) };
  const enriched = await Promise.all(
    deps.map(async (dep) => {
      const vulns = await queryOsv(dep.ecosystem, dep.name, dep.version, queryOpts);
      if (!vulns.length) return dep;

      const worst = vulns.reduce<DependencyRisk>((acc, v) => worstRisk(acc, v.severity), "low");
      const ids = vulns.map((v) => v.id).join(", ");
      const cveReason = `${vulns.length} vulnérabilité(s) connue(s) (${ids}).`;
      return {
        ...dep,
        riskLevel: worstRisk(dep.riskLevel, worst),
        // A package with a known CVE is not trustworthy regardless of its name.
        trustScore: Math.min(dep.trustScore, worst === "critical" ? 5 : worst === "high" ? 20 : 45),
        reason: dep.reason ? `${dep.reason} ${cveReason}` : cveReason,
        vulnerabilities: vulns,
      };
    }),
  );
  if (!failures.length) opts.onStatus?.("ok");
  else {
    opts.onStatus?.(
      "failed",
      failures.length === deps.length
        ? failures[0]
        : `${failures.length}/${deps.length} requêtes : ${failures[0]}`,
    );
  }
  return enriched;
}
