import { findingAssurance, needsHumanReview } from "./assurance.js";
import { ENGINE_CATALOG } from "@codegate/shared";
import type {
  AnalysisResult,
  DependencyResult,
  EngineName,
  EngineReport,
  FindingResult,
  SecretResult,
} from "./types.js";
import { revocationGuide } from "./revocation.js";

/** Hidden HTML marker identifying CodeGate's own PR comment, for upserts. */
export const CODEGATE_COMMENT_MARKER = "<!-- codegate:report -->";

/**
 * Risk Explainer (cahier §5.6). Turns technical findings into plain-language
 * guidance. Deterministic and offline — the Python AI engine can enrich these
 * later, but the product never depends on an LLM to explain a risk.
 */

export function explainSecret(s: SecretResult): string {
  const guide = revocationGuide(s.secretType);
  return (
    `Un secret de type « ${s.secretType} » a été détecté dans ${s.location} ` +
    `(valeur masquée : ${s.maskedPreview}). ` +
    `Un secret exposé dans le code peut être lu par quiconque a accès au dépôt ou à l'historique. ` +
    `Révoquez immédiatement cette clé${guide.url ? ` (${guide.provider} : ${guide.url})` : ""}, ` +
    `régénérez-en une nouvelle, et déplacez-la dans une variable d'environnement ou un gestionnaire de secrets.`
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

export function buildPrComment(
  result: {
    riskScore: number;
    decision: string;
    status: string;
    findings: FindingResult[];
    secrets: SecretResult[];
    dependencies: DependencyResult[];
    engines?: AnalysisResult["engines"];
  },
  /** suppressed: alerts the team already marked as false positives. */
  extra: { suppressed?: number } = {},
): string {
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
  const risks = result.findings.filter((f) => f.severity !== "info");
  const notes = result.findings.filter((f) => f.severity === "info");
  const level = (f: FindingResult) => findingAssurance(f);
  const firm = risks.filter((f) => level(f) === "verified" || level(f) === "likely");
  const toReview = risks.filter((f) => level(f) === "uncertain");
  const proofLine = (f: FindingResult) => {
    const tag = level(f) === "verified" ? "prouvée" : needsHumanReview(f) ? "probable — validation humaine requise" : "probable";
    const evidence = f.details?.evidence ? `\n  \`${f.details.evidence.replace(/`/g, "'")}\`` : "";
    const scenario = f.details?.scenario ? `\n  <sub>Scénario : ${f.details.scenario}</sub>` : "";
    return `- **[${f.severity} · ${tag}]** ${explainFinding(f)}${evidence}${scenario}`;
  };
  if (firm.length) {
    lines.push(`### 🔎 Problèmes de code (${firm.length})`);
    for (const f of firm) lines.push(proofLine(f));
    lines.push("");
  }
  if (toReview.length) {
    // Uncertain signals are in observation: listed for a human look, they
    // never drive the verdict.
    lines.push(`### 🔍 En observation — preuve insuffisante, sans effet sur la décision (${toReview.length})`);
    for (const f of toReview) {
      const why = f.details?.observationReason ? ` _(${f.details.observationReason})_` : "";
      lines.push(`- **[${f.severity}]** ${explainFinding(f)}${why}`);
    }
    lines.push("");
  }
  const failed = failedEngines(result.engines);
  if (!result.secrets.length && !risks.length &&
      !result.dependencies.some((d) => d.riskLevel !== "low")) {
    lines.push(
      failed.length
        ? "Aucun risque détecté par les analyses qui ont pu s'exécuter (voir ci-dessous)."
        : "Aucun risque détecté. ✅",
    );
    lines.push("");
  }
  // A pass that could not run must be visible: otherwise "nothing found"
  // reads as "checked and clean".
  if (failed.length) {
    lines.push("> ⚠️ **Analyse partielle** — certaines vérifications n'ont pas pu s'exécuter :");
    for (const { label, detail } of failed) lines.push(`> - ${label} : ${detail}`);
    lines.push("");
  }
  if (notes.length) {
    // Shown for transparency, folded: they carry no risk and no score.
    lines.push(`<details><summary>ℹ️ ${notes.length} information(s) sans impact sur le score</summary>`);
    lines.push("");
    for (const f of notes) lines.push(`- ${explainFinding(f)}`);
    lines.push("");
    lines.push("</details>");
  }

  if (extra.suppressed) {
    lines.push(
      `🙈 ${extra.suppressed} alerte(s) masquée(s) : déjà signalée(s) comme fausse(s) alerte(s) par l'équipe sur ce dépôt.`,
    );
    lines.push("");
  }

  lines.push("");
  lines.push(
    "<sub>CodeGate vérifie chaque PR générée par IA avant la production. Une alerte vous semble fausse ? Signalez-la depuis la page de la PR dans le tableau de bord CodeGate : elle ne comptera plus dans le verdict de ce dépôt.</sub>",
  );
  return lines.join("\n");
}
