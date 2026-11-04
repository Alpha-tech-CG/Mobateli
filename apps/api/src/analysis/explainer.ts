import { ENGINE_CATALOG } from "@codegate/shared";
import type {
  AnalysisResult,
  DependencyResult,
  EngineName,
  EngineReport,
  FindingResult,
  SecretResult,
} from "./types.js";

/** Hidden HTML marker identifying CodeGate's own PR comment, for upserts. */
export const CODEGATE_COMMENT_MARKER = "<!-- codegate:report -->";

/**
 * Risk Explainer (cahier §5.6). Turns technical findings into plain-language
 * guidance. Deterministic and offline — the Python AI engine can enrich these
 * later, but the product never depends on an LLM to explain a risk.
 */

export function explainSecret(s: SecretResult): string {
  return (
    `Un secret de type « ${s.secretType} » a été détecté dans ${s.location} ` +
    `(valeur masquée : ${s.maskedPreview}). ` +
    `Un secret exposé dans le code peut être lu par quiconque a accès au dépôt ou à l'historique. ` +
    `Révoquez immédiatement cette clé, régénérez-en une nouvelle, et déplacez-la dans une variable ` +
    `d'environnement ou un gestionnaire de secrets.`
  );
}

export function explainDependency(d: DependencyResult): string {
  const base = `La dépendance « ${d.name}@${d.version} » a un score de confiance de ${d.trustScore}/100 (risque : ${d.riskLevel}).`;
  let out = d.reason ? `${base} ${d.reason}` : base;
  if (d.vulnerabilities?.length) {
    const cves = d.vulnerabilities
      .slice(0, 5)
      .map((v) => `${v.id} (${v.severity}${v.fixedVersion ? `, corrigé en ${v.fixedVersion}` : ""})`)
      .join(", ");
    out += ` Vulnérabilités : ${cves}.`;
  }
  return out;
}

/** Compact reference tag, e.g. "[CWE-89 · A03:2021-Injection · confiance: medium]". */
function findingTags(f: FindingResult): string {
  const tags: string[] = [];
  if (f.cwe) tags.push(f.cwe);
  if (f.owasp) tags.push(f.owasp);
  if (f.confidence) tags.push(`confiance: ${f.confidence}`);
  return tags.length ? ` _[${tags.join(" · ")}]_` : "";
}

export function explainFinding(f: FindingResult): string {
  const where = f.filePath ? ` (${f.filePath}${f.line ? `:${f.line}` : ""})` : "";
  const fix = f.remediation ? ` Correctif : ${f.remediation}` : "";
  return `${f.title}${where}. ${f.description}${fix}${findingTags(f)}`;
}

/** Build the structured GitHub PR comment body (cahier §6.2, §5.6). */
/** Engine labels, from the shared catalog (single source of truth). */
export const ENGINE_LABELS: Record<EngineName, string> = Object.fromEntries(
  Object.entries(ENGINE_CATALOG).map(([id, e]) => [id, e.label]),
) as Record<EngineName, string>;

/** Passes that were expected to run but failed (skipped-by-design is not shown). */
export function failedEngines(
  engines: AnalysisResult["engines"],
): { name: EngineName; label: string; detail: string }[] {
  if (!engines) return [];
  return (Object.entries(engines) as [EngineName, EngineReport][])
    .filter(([, r]) => r.status === "failed")
    .map(([name, r]) => ({ name, label: ENGINE_LABELS[name], detail: r.detail ?? "échec" }));
}

export function buildPrComment(result: {
  riskScore: number;
  decision: string;
  status: string;
  findings: FindingResult[];
  secrets: SecretResult[];
  dependencies: DependencyResult[];
  engines?: AnalysisResult["engines"];
}): string {
  const emoji =
    result.status === "blocked" ? "🛑" : result.status === "warning" ? "⚠️" : "✅";
  const lines: string[] = [];
  // Hidden marker so we can find-and-update our own comment (no spam).
  lines.push(CODEGATE_COMMENT_MARKER);
  lines.push(`## ${emoji} CodeGate — analyse de sécurité`);
  lines.push("");
  lines.push(`**Score de risque : ${result.riskScore}/100 — décision : ${result.decision}**`);
  lines.push("");

  if (result.secrets.length) {
    lines.push(`### 🔑 Secrets (${result.secrets.length})`);
    for (const s of result.secrets) lines.push(`- ${explainSecret(s)}`);
    lines.push("");
  }
  if (result.dependencies.some((d) => d.riskLevel !== "low")) {
    lines.push("### 📦 Dépendances à risque");
    for (const d of result.dependencies.filter((x) => x.riskLevel !== "low")) {
      lines.push(`- ${explainDependency(d)}`);
    }
    lines.push("");
  }
  if (result.findings.length) {
    lines.push(`### 🔎 Problèmes de code (${result.findings.length})`);
    for (const f of result.findings) lines.push(`- **[${f.severity}]** ${explainFinding(f)}`);
    lines.push("");
  }
  const failed = failedEngines(result.engines);
  if (!result.secrets.length && !result.findings.length &&
      !result.dependencies.some((d) => d.riskLevel !== "low")) {
    lines.push(
      failed.length
        ? "Aucun risque détecté par les analyses qui ont pu s'exécuter (voir ci-dessous)."
        : "Aucun risque détecté. ✅",
    );
  }
  // A pass that could not run must be visible: otherwise "nothing found"
  // reads as "checked and clean".
  if (failed.length) {
    lines.push("");
    lines.push("> ⚠️ **Analyse partielle** — certaines vérifications n'ont pas pu s'exécuter :");
    for (const { label, detail } of failed) lines.push(`> - ${label} : ${detail}`);
  }

  lines.push("");
  lines.push("<sub>CodeGate vérifie chaque PR générée par IA avant la production.</sub>");
  return lines.join("\n");
}
