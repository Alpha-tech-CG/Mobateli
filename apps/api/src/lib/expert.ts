import type { Severity } from "@codegate/shared";
import type { Block } from "./audit-report.js";

/**
 * The layer that turns raw findings into what a security consultant hands
 * over: an executive summary in business terms, a maturity score per domain,
 * a prioritised remediation plan (effort, expected gain, quick wins) and the
 * mapping to the frameworks auditors ask for. Shared by every report type.
 */

export type Effort = "faible" | "moyen" | "élevé";

export interface ExpertItem {
  /** Same key = same action (e.g. "docker.limits" across 5 containers). */
  key: string;
  domain: string;
  severity: Severity;
  title: string;
  /** Imperative, short: "Fermer le port Redis au public". */
  action: string;
  effort: Effort;
  /** Business consequence, for the executive summary. */
  impact: string;
  refs: string[];
  /** Contribution to the score penalty (or to the risk score). */
  weight: number;
  /** What it applies to (container, file, port…), listed in the plan. */
  subject?: string;
  /** Titles of attack chains this item is part of. */
  chains?: string[];
}

export interface ExpertInput {
  /** "security": higher is better (server, backup); "risk": higher is worse (PR, scan). */
  scale: "security" | "risk";
  score: number | null;
  items: ExpertItem[];
  domains: string[];
  /** Score if only `remaining` were still open. */
  rescore: (remaining: ExpertItem[]) => number;
  /** "ce serveur", "cette pull request"… */
  subject: string;
  /** Extra facts for the summary (context the findings do not carry). */
  context?: string[];
}

// ─── Frameworks ────────────────────────────────────────────────────────────
// Section-level references only: a precise control number we are not sure of
// would cost more credibility than it buys.
export const REF = {
  owaspA01: "OWASP Top 10 2021 · A01 Contrôle d'accès défaillant",
  owaspA02: "OWASP Top 10 2021 · A02 Défaillances cryptographiques",
  owaspA03: "OWASP Top 10 2021 · A03 Injection",
  owaspA05: "OWASP Top 10 2021 · A05 Mauvaise configuration de sécurité",
  owaspA06: "OWASP Top 10 2021 · A06 Composants vulnérables et obsolètes",
  owaspA07: "OWASP Top 10 2021 · A07 Identification et authentification",
  owaspA08: "OWASP Top 10 2021 · A08 Intégrité des logiciels et des données",
  llm01: "OWASP Top 10 LLM 2025 · LLM01 Injection de prompt",
  iso515: "ISO/IEC 27001:2022 · A.5.15 Contrôle d'accès",
  iso517: "ISO/IEC 27001:2022 · A.5.17 Informations d'authentification",
  iso530: "ISO/IEC 27001:2022 · A.5.30 Préparation des TIC à la continuité",
  iso82: "ISO/IEC 27001:2022 · A.8.2 Droits d'accès privilégiés",
  iso85: "ISO/IEC 27001:2022 · A.8.5 Authentification sécurisée",
  iso88: "ISO/IEC 27001:2022 · A.8.8 Gestion des vulnérabilités techniques",
  iso89: "ISO/IEC 27001:2022 · A.8.9 Gestion de la configuration",
  iso813: "ISO/IEC 27001:2022 · A.8.13 Sauvegarde des informations",
  iso820: "ISO/IEC 27001:2022 · A.8.20 Sécurité des réseaux",
  iso824: "ISO/IEC 27001:2022 · A.8.24 Utilisation de la cryptographie",
  iso828: "ISO/IEC 27001:2022 · A.8.28 Codage sécurisé",
  cisDockerDaemon: "CIS Docker Benchmark · §2 Configuration du démon Docker",
  cisDockerImages: "CIS Docker Benchmark · §4 Images et fichiers de build",
  cisDockerRuntime: "CIS Docker Benchmark · §5 Exécution des conteneurs",
  cisLinuxSsh: "CIS Benchmark Linux · Configuration du serveur SSH",
  cisLinuxFirewall: "CIS Benchmark Linux · Pare-feu de l'hôte",
  cisLinuxUpdates: "CIS Benchmark Linux · Mises à jour et correctifs",
  cisLinuxAccounts: "CIS Benchmark Linux · Comptes utilisateurs et privilèges",
  anssiDocker: "ANSSI · Déploiement de conteneurs Docker (recommandations)",
  anssiLinux: "ANSSI · Configuration d'un système GNU/Linux (recommandations)",
  anssiTls: "ANSSI · Recommandations de sécurité relatives à TLS",
} as const;

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
/** Agrees with "sévérité" (feminine) in tables… */
const SEV_FR: Record<Severity, string> = { critical: "critique", high: "élevée", medium: "moyenne", low: "faible", info: "info" };
/** …and with "risque" (masculine) in the summary. */
const RISK_FR: Record<Severity, string> = { critical: "critique", high: "élevé", medium: "moyen", low: "faible", info: "info" };

const PRIORITIES = ["Immédiat (24 h)", "Sous 7 jours", "Sous 30 jours", "Prochain cycle"] as const;
function priorityOf(severity: Severity, inChain: boolean): number {
  if (severity === "critical" || inChain) return 0;
  if (severity === "high") return 1;
  if (severity === "medium") return 2;
  return 3;
}

/** 0–100 "maîtrise" of a domain: 100 × K / (K + penalty), same curve as the server score. */
export function maturity(items: ExpertItem[], k = 60): number {
  const penalty = items.reduce((s, i) => s + i.weight, 0);
  return Math.round((100 * k) / (k + penalty));
}

interface PlanRow {
  key: string;
  priority: number;
  severity: Severity;
  action: string;
  effort: Effort;
  gain: number;
  subjects: string[];
  refs: string[];
  chains: string[];
  items: ExpertItem[];
}

export function remediationPlan(input: ExpertInput): PlanRow[] {
  const groups = new Map<string, ExpertItem[]>();
  for (const i of input.items) groups.set(i.key, [...(groups.get(i.key) ?? []), i]);
  const current = input.score ?? input.rescore(input.items);
  const rows: PlanRow[] = [];
  for (const [key, items] of groups) {
    const severity = items.reduce<Severity>((a, i) => (SEV_RANK[i.severity] > SEV_RANK[a] ? i.severity : a), "info");
    if (severity === "info") continue;
    const chains = [...new Set(items.flatMap((i) => i.chains ?? []))];
    const without = input.items.filter((i) => i.key !== key);
    const after = input.rescore(without);
    rows.push({
      key,
      priority: priorityOf(severity, chains.length > 0),
      severity,
      action: items[0]!.action,
      effort: items.reduce<Effort>((a, i) => (EFFORT_RANK[i.effort] > EFFORT_RANK[a] ? i.effort : a), "faible"),
      gain: input.scale === "security" ? after - current : current - after,
      subjects: [...new Set(items.map((i) => i.subject).filter((s): s is string => !!s))],
      refs: [...new Set(items.flatMap((i) => i.refs))],
      chains,
      items,
    });
  }
  return rows.sort((a, b) => a.priority - b.priority || b.gain - a.gain || SEV_RANK[b.severity] - SEV_RANK[a.severity]);
}
const EFFORT_RANK: Record<Effort, number> = { faible: 0, moyen: 1, élevé: 2 };

/** Executive summary, domain scores, remediation plan and framework mapping. */
export function expertBlocks(input: ExpertInput): Block[] {
  const open = input.items.filter((i) => i.severity !== "info");
  const plan = remediationPlan(input);
  const current = input.score ?? input.rescore(input.items);
  const scoreWord = input.scale === "security" ? "score de sécurité" : "score de risque";
  const unit = input.scale === "security" ? "/100" : "/100";

  // ── Executive summary ──
  const bullets: string[] = [];
  const crit = open.filter((i) => i.severity === "critical").length;
  const high = open.filter((i) => i.severity === "high").length;
  if (!open.length) {
    bullets.push(`Aucun risque ouvert sur ${input.subject} : les contrôles CodeGate sont tous satisfaits ou justifiés.`);
  } else {
    const posture =
      crit > 0
        ? `La posture de sécurité ${ofSubject(input.subject)} est insuffisante : ${crit} risque(s) critique(s) peuvent être exploités sans action de votre part.`
        : high > 0
          ? `La posture de sécurité ${ofSubject(input.subject)} est à renforcer : ${high} risque(s) élevé(s) restent ouverts, sans risque critique.`
          : `La posture de sécurité ${ofSubject(input.subject)} est correcte : seuls des points de durcissement restent ouverts.`;
    bullets.push(posture);
    const chained = [...new Set(open.flatMap((i) => i.chains ?? []))];
    if (chained.length) {
      bullets.push(
        `${chained.length} chaîne(s) d'attaque relient plusieurs faiblesses jusqu'à une prise de contrôle : « ${chained[0]} »${chained.length > 1 ? " et d'autres" : ""}.`,
      );
    }
    const top = [...open].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.weight - a.weight);
    const seen = new Set<string>();
    for (const i of top) {
      if (seen.size >= 3) break;
      if (seen.has(i.impact)) continue;
      seen.add(i.impact);
      bullets.push(`Risque ${RISK_FR[i.severity]} — ${i.impact} (${i.title}).`);
    }
    const quick = plan.filter((p) => p.effort === "faible" && p.priority <= 2);
    const quickAfter = quick.length
      ? input.rescore(input.items.filter((i) => !new Set(quick.map((q) => q.key)).has(i.key)))
      : current;
    // Only announce quick wins that actually move the score.
    if (quick.length && quickAfter !== current) {
      const after = quickAfter;
      bullets.push(
        input.scale === "security"
          ? `${quick.length} action(s) rapide(s), à effort faible, font passer le ${scoreWord} de ${current} à ${after}${unit}.`
          : `${quick.length} action(s) rapide(s), à effort faible, font baisser le ${scoreWord} de ${current} à ${after}${unit}.`,
      );
    }
    const first = plan[0];
    if (first) bullets.push(`Première action recommandée : ${lowerFirst(first.action)}.`);
  }
  bullets.push(...(input.context ?? []));

  const blocks: Block[] = [
    { kind: "section", title: "Synthèse pour la direction", subtitle: "Ce qu'il faut retenir, en langage métier." },
    { kind: "bullets", items: bullets },
  ];

  // ── Maturity per domain ──
  const domains = input.domains.map((d) => {
    const inDomain = open.filter((i) => i.domain === d);
    return { label: d, value: maturity(inDomain), note: inDomain.length ? `${inDomain.length} point(s) ouvert(s)` : "conforme" };
  });
  blocks.push(
    {
      kind: "section",
      title: "Niveau de maîtrise par domaine",
      subtitle: "100 = aucun point ouvert ; chaque point retire des points selon sa gravité.",
    },
    { kind: "bars", items: domains },
  );

  // ── Prioritised remediation plan ──
  if (plan.length) {
    blocks.push(
      {
        kind: "section",
        title: "Plan de remédiation priorisé",
        subtitle: `Classé par urgence puis par gain. Le gain est l'évolution du ${scoreWord} si l'action est faite seule.`,
      },
      {
        kind: "table",
        columns: [
          { label: "Priorité", width: 0.14 },
          { label: "Action", width: 0.46 },
          { label: "Effort", width: 0.1 },
          { label: "Gain", width: 0.1, align: "right" },
          { label: "Sévérité", width: 0.2 },
        ],
        rows: plan.map((p) => [
          PRIORITIES[p.priority]!,
          `${p.action}${p.subjects.length ? `\nConcerne : ${p.subjects.slice(0, 6).join(", ")}${p.subjects.length > 6 ? "…" : ""}` : ""}${
            p.chains.length ? `\nCasse la chaîne : ${p.chains[0]}` : ""
          }`,
          p.effort,
          p.gain > 0 ? `${input.scale === "security" ? "+" : "-"}${p.gain} pts` : "—",
          `${SEV_FR[p.severity]}${p.items.length > 1 ? ` (${p.items.length})` : ""}`,
        ]),
        fontSize: 7.5,
      },
    );
  }

  // ── Framework mapping ──
  const byRef = new Map<string, ExpertItem[]>();
  for (const i of open) for (const r of i.refs) byRef.set(r, [...(byRef.get(r) ?? []), i]);
  const mapping = [...byRef].sort((a, b) => a[0].localeCompare(b[0]));
  blocks.push(
    {
      kind: "section",
      title: "Correspondance avec les référentiels",
      subtitle: "Exigences concernées par au moins un constat ouvert ; les exigences sans écart ne sont pas listées.",
    },
    {
      kind: "table",
      columns: [
        { label: "Référentiel", width: 0.27 },
        { label: "Exigence", width: 0.4 },
        { label: "Constats", width: 0.11, align: "right" },
        { label: "Statut", width: 0.22 },
      ],
      rows: mapping.map(([ref, items]) => {
        const [framework, requirement] = ref.split(" · ");
        const worst = items.reduce((a, i) => Math.max(a, SEV_RANK[i.severity]), 0);
        return [
          framework ?? ref,
          requirement ?? "",
          String(items.length),
          worst >= SEV_RANK.high ? "Non conforme" : "Partiellement conforme",
        ];
      }),
      empty: "Aucun écart constaté sur les référentiels suivis (OWASP, ISO/IEC 27001, CIS, ANSSI).",
    },
  );
  return blocks;
}

const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);

/** French contraction: "de le dépôt" → "du dépôt", "de les …" → "des …". */
export function ofSubject(subject: string): string {
  if (/^le /i.test(subject)) return `du ${subject.slice(3)}`;
  if (/^les /i.test(subject)) return `des ${subject.slice(4)}`;
  return `de ${subject}`;
}
