import { prisma } from "@codegate/db";
import { evaluateBackup } from "../analysis/backup.js";
import type { DependencyResult, FindingResult, SecretResult } from "../analysis/types.js";
import { fmtDate, type Block, type Kpi, type ReportDocument } from "./audit-report.js";
import type { EvidencePack } from "./evidence.js";

/**
 * One signed report per feature: the whole organization (evidence pack), a
 * pull request, a repository scan, a server, a brute-force target and a
 * backup. Every builder is scoped to the caller's organization and returns
 * null when the subject is not theirs.
 */

export const REPORT_TYPES = ["pull-request", "scan", "server", "bruteforce", "backup"] as const;
export type ReportType = (typeof REPORT_TYPES)[number];

const STATUS_FR: Record<string, string> = {
  pending: "En attente",
  analyzing: "En cours",
  passed: "Validée",
  warning: "À corriger",
  blocked: "Bloquée",
  escalated: "Escaladée",
};
const SEVERITY_FR: Record<string, string> = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info" };
const FINDING_TYPE_FR: Record<string, string> = {
  secret: "Secret",
  dependency: "Dépendance",
  sast: "Code",
  config: "Configuration",
  auth: "Authentification",
  prompt_injection: "Prompt injection",
};
const FINDING_STATUS_FR: Record<string, string> = {
  open: "Ouvert",
  acknowledged: "Pris en compte",
  resolved: "Résolu",
  false_positive: "Faux positif",
};
const RISK_FR: Record<string, string> = { low: "Faible", medium: "Moyen", high: "Élevé", critical: "Critique" };
const INFRA_FR: Record<string, string> = {
  ports: "Ports exposés",
  ssh: "SSH",
  firewall: "Firewall",
  bruteforce: "Brute force",
  docker: "Docker",
  updates: "Mises à jour",
  backups: "Sauvegardes",
  tls: "TLS",
  secrets: "Secrets",
  network: "Réseau",
  admin: "Console d'admin",
  http: "En-têtes HTTP",
  daemon: "Démon Docker",
};
const BF_TYPE_FR: Record<string, string> = { login_lockout: "Verrouillage après échecs", account_enumeration: "Énumération de comptes" };
const BF_RESULT_FR: Record<string, string> = { pass: "Conforme", warn: "À améliorer", fail: "Non conforme" };
const BACKUP_STATUS_FR: Record<string, string> = { healthy: "Saine", attention: "À surveiller", critical: "Critique" };
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const bySeverity = <T extends { severity: string }>(items: T[]) =>
  [...items].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
const location = (f: { filePath?: string | null; line?: number | null }) =>
  f.filePath ? `${f.filePath}${f.line ? `:${f.line}` : ""}` : "—";
const sevCount = (items: { severity: string }[], s: string) => items.filter((i) => i.severity === s).length;

function verdictFor(status: string, score: number | null): NonNullable<ReportDocument["verdict"]> {
  if (status === "blocked")
    return { label: "Bloquée", tone: "bad", text: `Risque ${score ?? "—"}/100 : au moins un risque bloquant (secret, problème critique ou score de 70 ou plus). Ne pas fusionner avant correction.` };
  if (status === "warning" || status === "escalated")
    return { label: STATUS_FR[status]!, tone: "warn", text: `Risque ${score ?? "—"}/100 : des problèmes sont à corriger avant la fusion.` };
  if (status === "passed") return { label: "Validée", tone: "ok", text: "Aucun risque détecté : le changement peut être fusionné." };
  return { label: STATUS_FR[status] ?? status, tone: "warn", text: "Analyse non terminée au moment de l'export." };
}

// Shared tables for code analyses (pull request and repository scan).
function codeBlocks(
  secrets: { secretType: string; location: string; maskedPreview: string; severity: string; status?: string; revokedAt?: Date | null }[],
  findings: { type: string; severity: string; title: string; description: string; filePath?: string | null; line?: number | null; remediation?: string | null; status?: string }[],
  dependencies: { ecosystem: string; name: string; version: string; trustScore: number | null; riskLevel: string; reason?: string | null }[],
  dependencyNote: string,
): Block[] {
  return [
    { kind: "section", title: "Secrets", subtitle: "Valeurs toujours masquées : CodeGate ne conserve jamais un secret en clair." },
    {
      kind: "table",
      columns: [
        { label: "Type", width: 0.24 },
        { label: "Emplacement", width: 0.36 },
        { label: "Aperçu masqué", width: 0.22 },
        { label: "État", width: 0.18 },
      ],
      rows: secrets.map((s) => [
        s.secretType,
        s.location,
        s.maskedPreview,
        s.revokedAt || s.status === "resolved" ? "Révoqué" : s.status ? (FINDING_STATUS_FR[s.status] ?? s.status) : "À révoquer",
      ]),
      empty: "Aucun secret détecté.",
    },
    { kind: "section", title: "Problèmes de code et de configuration" },
    {
      kind: "table",
      columns: [
        { label: "Sévérité", width: 0.11 },
        { label: "Type", width: 0.13 },
        { label: "Problème et correctif", width: 0.48 },
        { label: "Emplacement", width: 0.18 },
        { label: "État", width: 0.1 },
      ],
      rows: bySeverity(findings).map((f) => [
        SEVERITY_FR[f.severity] ?? f.severity,
        FINDING_TYPE_FR[f.type] ?? f.type,
        `${f.title}\n${f.description}${f.remediation ? `\nCorrectif : ${f.remediation}` : ""}`,
        location(f),
        f.status ? (FINDING_STATUS_FR[f.status] ?? f.status) : "Ouvert",
      ]),
      fontSize: 7.5,
      empty: "Aucun problème de code détecté.",
    },
    { kind: "section", title: "Dépendances", subtitle: dependencyNote },
    {
      kind: "table",
      columns: [
        { label: "Paquet", width: 0.3 },
        { label: "Écosystème", width: 0.12 },
        { label: "Risque", width: 0.1 },
        { label: "Confiance", width: 0.11, align: "right" },
        { label: "Motif", width: 0.37 },
      ],
      rows: dependencies.map((d) => [
        `${d.name}@${d.version}`,
        d.ecosystem,
        RISK_FR[d.riskLevel] ?? d.riskLevel,
        d.trustScore === null ? "—" : `${d.trustScore}/100`,
        d.reason ?? "Saine : aucune vulnérabilité connue, registre et nom vérifiés.",
      ]),
      empty: "Aucune dépendance concernée.",
    },
  ];
}

// --------------------------------------------------------- organization --

export function organizationDocument(pack: EvidencePack): ReportDocument {
  const s = pack.summary;
  const serious = (s.findingsBySeverity.critical ?? 0) + (s.findingsBySeverity.high ?? 0);
  const period =
    pack.filters.from || pack.filters.to
      ? `du ${fmtDate(pack.filters.from ?? null)} au ${pack.filters.to ? fmtDate(pack.filters.to) : "jour de l'export"}`
      : "toute la période";
  const statuses = Object.entries(s.byStatus).map(([k, v]) => `${STATUS_FR[k] ?? k} : ${v}`).join(" · ");
  const severities = ["critical", "high", "medium", "low", "info"]
    .filter((k) => s.findingsBySeverity[k])
    .map((k) => `${SEVERITY_FR[k]} : ${s.findingsBySeverity[k]}`)
    .join(" · ");

  const blocks: Block[] = [
    { kind: "text", text: `Décisions : ${statuses || "aucune pull request sur la période"}` },
    { kind: "text", text: `Problèmes de code par sévérité (hors faux positifs) : ${severities || "aucun"}` },
    { kind: "text", text: `Issues de remédiation : ${s.remediationIssues} · Événements d'audit : ${s.auditEvents}` },
    {
      kind: "section",
      title: "Décisions par pull request",
      subtitle: "Chaque pull request, écrite par un développeur ou générée par IA, est analysée avant fusion.",
    },
    {
      kind: "table",
      columns: [
        { label: "Dépôt / PR", width: 0.24 },
        { label: "Titre", width: 0.34 },
        { label: "Risque", width: 0.09, align: "right" },
        { label: "Décision", width: 0.15 },
        { label: "Date", width: 0.18 },
      ],
      rows: pack.pullRequests.slice(0, 200).map((pr) => [
        `${pr.repository} #${pr.number}${pr.aiGenerated ? "  (IA)" : ""}`,
        pr.title,
        pr.riskScore === null ? "—" : `${pr.riskScore}/100`,
        STATUS_FR[pr.status] ?? pr.status,
        fmtDate(pr.createdAt),
      ]),
      empty: "Aucune pull request analysée sur la période.",
    },
  ];
  if (pack.pullRequests.length > 200)
    blocks.push({ kind: "note", text: `… et ${pack.pullRequests.length - 200} autres (export JSON pour la liste complète).` });

  if (pack.infrastructure.length) {
    blocks.push(
      { kind: "section", title: "Infrastructure — Infra Shield", subtitle: "Score de durcissement des serveurs audités et points restant à corriger." },
      {
        kind: "table",
        columns: [
          { label: "Serveur", width: 0.26 },
          { label: "Environnement", width: 0.16 },
          { label: "Score", width: 0.1, align: "right" },
          { label: "Dernier audit", width: 0.2 },
          { label: "À corriger", width: 0.28 },
        ],
        rows: pack.infrastructure.map((sv) => [
          sv.server,
          sv.environment,
          sv.securityScore === null ? "—" : `${sv.securityScore}/100`,
          fmtDate(sv.lastAuditAt),
          Object.entries(sv.openFindings).map(([k, v]) => `${SEVERITY_FR[k] ?? k} ${v}`).join(", ") || "rien",
        ]),
      },
    );
  }
  const bf = pack.bruteForce;
  if (bf.policies.length || bf.tests.length) {
    blocks.push({ kind: "section", title: "Protection anti brute force — BruteForce Shield" });
    if (bf.policies.length)
      blocks.push({
        kind: "table",
        columns: [
          { label: "Point d'entrée", width: 0.4 },
          { label: "Échecs max", width: 0.2, align: "right" },
          { label: "Fenêtre", width: 0.2, align: "right" },
          { label: "Blocage", width: 0.2, align: "right" },
        ],
        rows: bf.policies.map((p) => [p.endpoint, String(p.maxAttempts), `${p.windowSeconds} s`, `${p.lockoutSeconds} s`]),
      });
    if (bf.tests.length)
      blocks.push({
        kind: "table",
        columns: [
          { label: "Date", width: 0.2 },
          { label: "Cible", width: 0.4 },
          { label: "Test", width: 0.22 },
          { label: "Résultat", width: 0.18 },
        ],
        rows: bf.tests.slice(0, 60).map((t) => [
          fmtDate(t.createdAt),
          `${t.target}${t.endpoint}`,
          BF_TYPE_FR[t.testType] ?? t.testType,
          BF_RESULT_FR[t.result] ?? t.result,
        ]),
      });
  }
  if (pack.backups.length) {
    blocks.push(
      { kind: "section", title: "Sauvegardes — Backup Shield", subtitle: "Capacité de restauration, y compris face à un rançongiciel." },
      {
        kind: "table",
        columns: [
          { label: "Sauvegarde", width: 0.22 },
          { label: "État", width: 0.12 },
          { label: "Récupération", width: 0.13, align: "right" },
          { label: "Dernière exécution", width: 0.17 },
          { label: "Restauration testée", width: 0.17 },
          { label: "À corriger", width: 0.19 },
        ],
        rows: pack.backups.map((b) => [
          `${b.name} (${b.type})${b.ransomwareReady ? " · prête rançongiciel" : ""}`,
          BACKUP_STATUS_FR[b.status] ?? b.status,
          `${b.recoveryScore}/100`,
          fmtDate(b.lastRunAt),
          fmtDate(b.lastRestoreTestAt),
          b.failedChecks.join(", ") || "rien",
        ]),
      },
    );
  }
  if (pack.policies.length) {
    blocks.push(
      { kind: "section", title: "Politiques de sécurité appliquées" },
      {
        kind: "table",
        columns: [
          { label: "Règle", width: 0.4 },
          { label: "Action", width: 0.2 },
          { label: "Seuil", width: 0.2 },
          { label: "Portée", width: 0.2 },
        ],
        rows: pack.policies.map((p) => [
          p.rule,
          p.action,
          SEVERITY_FR[p.severityThreshold] ?? p.severityThreshold,
          p.scope === "repository" ? "dépôt" : "organisation",
        ]),
      },
    );
  }
  blocks.push(
    {
      kind: "section",
      title: "Journal d'audit",
      subtitle: `Extrait des ${Math.min(pack.auditEvents.length, 150)} événements les plus récents sur ${pack.auditEvents.length} (journal immuable ; export CSV pour l'intégralité).`,
    },
    {
      kind: "table",
      columns: [
        { label: "Horodatage", width: 0.22 },
        { label: "Acteur", width: 0.14 },
        { label: "Action", width: 0.38 },
        { label: "Ressource", width: 0.26 },
      ],
      rows: pack.auditEvents.slice(0, 150).map((e) => [fmtDate(e.createdAt), e.actorType, e.action, e.resourceType]),
      fontSize: 7.5,
      empty: "Aucun événement sur la période.",
    },
  );

  return {
    type: "organization",
    heading: "RAPPORT D'AUDIT DE SÉCURITÉ",
    eyebrow: "DOSSIER DE PREUVES DE SÉCURITÉ",
    title: "Rapport d'audit de sécurité",
    subtitle: pack.organization.name,
    organization: pack.organization.name,
    facts: [
      ["Période couverte", period],
      ["Généré le", fmtDate(pack.generatedAt)],
      ["Seuil de sévérité", pack.filters.severityThreshold ? SEVERITY_FR[pack.filters.severityThreshold]! : "toutes"],
    ],
    kpis: [
      { label: "Pull requests analysées", value: s.pullRequests },
      { label: "Secrets interceptés", value: s.secretsBlocked, alert: s.secretsBlocked > 0 },
      { label: "Dépendances refusées", value: s.dependenciesRefused, alert: s.dependenciesRefused > 0 },
      { label: "Problèmes critiques / élevés", value: serious, alert: serious > 0 },
    ],
    blocks,
  };
}

// --------------------------------------------------------- pull request --

export async function pullRequestDocument(organizationId: string, id: string): Promise<ReportDocument | null> {
  const pr = await prisma.pullRequest.findFirst({
    where: { id, repository: { organizationId } },
    include: {
      repository: { select: { name: true, provider: true, protectionLevel: true, organization: { select: { name: true } } } },
      findings: true,
      dependencies: true,
      secretFindings: true,
      remediationIssues: true,
    },
  });
  if (!pr) return null;
  const openFindings = pr.findings.filter((f) => f.status !== "false_positive" && f.severity !== "info");
  const risky = pr.dependencies.filter((d) => d.riskLevel !== "low");
  const unrevoked = pr.secretFindings.filter((s) => !s.revokedAt && s.status !== "resolved" && s.status !== "false_positive");
  const label = `${pr.repository.name} #${pr.number}`;

  const blocks = codeBlocks(
    pr.secretFindings,
    pr.findings,
    pr.dependencies,
    `${pr.dependencies.length} dépendance(s) ajoutée(s) ou mise(s) à jour analysée(s), ${risky.length} à risque.`,
  );
  if (pr.remediationIssues.length) {
    blocks.push(
      { kind: "section", title: "Suivi de la remédiation" },
      {
        kind: "table",
        columns: [
          { label: "Outil", width: 0.2 },
          { label: "Ticket", width: 0.5 },
          { label: "Créé le", width: 0.3 },
        ],
        rows: pr.remediationIssues.map((r) => [
          `${r.provider} · ${r.status === "done" ? "terminé" : r.status === "canceled" ? "annulé" : "ouvert"}`,
          r.url ?? r.identifier ?? r.externalId,
          fmtDate(r.createdAt),
        ]),
      },
    );
  }

  return {
    type: "pull_request",
    heading: "RAPPORT D'ANALYSE DE PULL REQUEST",
    eyebrow: "PULL REQUEST",
    title: `#${pr.number} ${pr.title}`,
    subtitle: pr.repository.name,
    organization: pr.repository.organization.name,
    subjectId: pr.id,
    subjectLabel: label,
    facts: [
      ["Dépôt", `${pr.repository.name} (${pr.repository.provider})`],
      ["Auteur", `${pr.author}${pr.aiGenerated ? " · généré par IA" : " · écrit par un développeur"}`],
      ["Commit analysé", pr.headSha ? pr.headSha.slice(0, 12) : "—"],
      ["Dernière analyse", fmtDate(pr.updatedAt)],
      ["Niveau de protection", pr.repository.protectionLevel],
    ],
    verdict: verdictFor(pr.status, pr.riskScore),
    kpis: [
      { label: "Score de risque / 100", value: pr.riskScore ?? "—", alert: (pr.riskScore ?? 0) >= 40 },
      { label: "Secrets non révoqués", value: unrevoked.length, alert: unrevoked.length > 0 },
      { label: "Problèmes de code ouverts", value: openFindings.length, alert: openFindings.length > 0 },
      { label: "Dépendances à risque", value: `${risky.length} / ${pr.dependencies.length}`, alert: risky.length > 0 },
    ],
    blocks,
  };
}

// ------------------------------------------------------ repository scan --

export async function scanDocument(organizationId: string, id: string): Promise<ReportDocument | null> {
  const scan = await prisma.repositoryScan.findFirst({
    where: { id, organizationId },
    include: { repository: { select: { name: true, provider: true, organization: { select: { name: true } } } } },
  });
  if (!scan) return null;
  const result = (scan.result ?? {}) as {
    secrets?: SecretResult[];
    findings?: FindingResult[];
    dependencies?: DependencyResult[];
    suppressed?: number;
  };
  const summary = (scan.summary ?? {}) as { files?: number; secrets?: number; findings?: number; riskyDependencies?: number; informational?: number };
  const status = scan.status !== "done" ? scan.status : scan.decision === "block" ? "blocked" : scan.decision === "allow" ? "passed" : "warning";
  const verdict =
    scan.status === "done"
      ? status === "blocked"
        ? { label: "À risque", tone: "bad" as const, text: `Risque ${scan.riskScore}/100 : le code de la branche contient au moins un risque bloquant.` }
        : status === "passed"
          ? { label: "Sain", tone: "ok" as const, text: "Aucun risque détecté dans le code de la branche analysée." }
          : { label: "À corriger", tone: "warn" as const, text: `Risque ${scan.riskScore}/100 : des problèmes sont à corriger.` }
      : { label: "Incomplet", tone: "warn" as const, text: scan.error ?? "L'analyse n'était pas terminée au moment de l'export." };
  const findings = result.findings ?? [];
  const blocks = codeBlocks(
    result.secrets ?? [],
    findings,
    result.dependencies ?? [],
    `${summary.riskyDependencies ?? 0} dépendance(s) à risque (les dépendances saines ne sont pas listées).`,
  );
  if (result.suppressed)
    blocks.push({ kind: "note", text: `${result.suppressed} problème(s) qualifié(s) faux positif par l'équipe, exclus du score (tracé dans le journal d'audit).` });
  const label = `${scan.repository.name}@${scan.ref ?? "branche principale"}`;

  return {
    type: "repository_scan",
    heading: "RAPPORT D'AUDIT DE DÉPÔT",
    eyebrow: "AUDIT DU CODE EXISTANT",
    title: "Audit de dépôt",
    subtitle: scan.repository.name,
    organization: scan.repository.organization.name,
    subjectId: scan.id,
    subjectLabel: label,
    facts: [
      ["Dépôt", `${scan.repository.name} (${scan.repository.provider})`],
      ["Branche / commit", `${scan.ref ?? "—"} · ${scan.commitSha ? scan.commitSha.slice(0, 12) : "—"}`],
      ["Déclenchement", ({ manual: "manuel", auto: "réanalyse quotidienne", connect: "connexion du dépôt" } as Record<string, string>)[scan.trigger] ?? scan.trigger],
      ["Analyse terminée le", fmtDate(scan.finishedAt)],
    ],
    verdict,
    kpis: [
      { label: "Score de risque / 100", value: scan.riskScore ?? "—", alert: (scan.riskScore ?? 0) >= 40 },
      { label: "Fichiers analysés", value: scan.filesScanned },
      { label: "Secrets", value: summary.secrets ?? 0, alert: (summary.secrets ?? 0) > 0 },
      { label: "Problèmes de code", value: summary.findings ?? 0, alert: (summary.findings ?? 0) > 0 },
    ],
    blocks,
  };
}

// --------------------------------------------------------------- server --

export async function serverDocument(organizationId: string, id: string): Promise<ReportDocument | null> {
  const server = await prisma.server.findFirst({
    where: { id, organizationId },
    include: {
      findings: true,
      acceptances: true,
      scans: { orderBy: { createdAt: "desc" }, take: 10 },
      organization: { select: { name: true } },
      backupJobs: { select: { name: true } },
    },
  });
  if (!server) return null;
  const now = Date.now();
  const acceptance = new Map(
    server.acceptances.filter((a) => !a.expiresAt || a.expiresAt.getTime() > now).map((a) => [a.checkId, a]),
  );
  const f = server.findings.filter((x) => !acceptance.has(x.checkId) && x.severity !== "info");
  const acceptedFindings = server.findings.filter((x) => acceptance.has(x.checkId));
  const analysis = (server.analysis ?? {}) as {
    chains?: { severity: string; title: string; steps: string[] }[];
    mitigations?: string[];
    resolved?: string[];
  };
  const crit = sevCount(f, "critical") + sevCount(f, "high");
  const score = server.securityScore;
  const delta = score !== null && server.previousScore !== null ? score - server.previousScore : null;
  const deltaText = delta ? ` (${delta > 0 ? "+" : ""}${delta} depuis l'audit précédent)` : "";
  const verdict: NonNullable<ReportDocument["verdict"]> =
    score === null
      ? { label: "Jamais audité", tone: "warn", text: "L'agent n'a encore envoyé aucun rapport pour ce serveur." }
      : crit
        ? { label: "À durcir", tone: "bad", text: `Score ${score}/100${deltaText} : ${crit} point(s) critique(s) ou élevé(s) exposent le serveur.` }
        : f.length
          ? { label: "À améliorer", tone: "warn", text: `Score ${score}/100${deltaText} : ${f.length} point(s) mineur(s) restent à corriger.` }
          : { label: "Durci", tone: "ok", text: `Score ${score}/100${deltaText} : aucun point ouvert.` };

  return {
    type: "server",
    heading: "RAPPORT D'AUDIT D'INFRASTRUCTURE",
    eyebrow: "INFRA SHIELD",
    title: "Audit de serveur",
    subtitle: server.name,
    organization: server.organization.name,
    subjectId: server.id,
    subjectLabel: server.name,
    facts: [
      ["Serveur", `${server.name} (${server.environment})`],
      ["Hôte / système", `${server.hostname ?? "—"} · ${server.os ?? "—"}`],
      ["Agent", server.agentVersion ? `v${server.agentVersion}, lecture seule` : "lecture seule"],
      ["Dernier audit", fmtDate(server.lastReportAt)],
    ],
    verdict,
    kpis: [
      { label: "Score de sécurité / 100", value: score ?? "—", alert: score !== null && score < 70 },
      { label: "Critiques / élevés", value: crit, alert: crit > 0 },
      { label: "Points à corriger", value: f.length, alert: f.length > 0 },
      { label: "Chaînes d'attaque", value: analysis.chains?.length ?? 0, alert: (analysis.chains?.length ?? 0) > 0 },
    ],
    blocks: [
      ...(analysis.chains?.length
        ? ([
            { kind: "section", title: "Chaînes d'attaque", subtitle: "Points qui, combinés, ouvrent un chemin jusqu'au serveur." },
            {
              kind: "table",
              columns: [
                { label: "Sévérité", width: 0.12 },
                { label: "Chemin", width: 0.3 },
                { label: "Étapes", width: 0.58 },
              ],
              rows: analysis.chains.map((c) => [
                SEVERITY_FR[c.severity] ?? c.severity,
                c.title,
                c.steps.map((s, i) => `${i + 1}. ${s}`).join("\n"),
              ]),
              fontSize: 7.5,
            },
          ] satisfies Block[])
        : []),
      { kind: "section", title: "Points à corriger", subtitle: "Constatés par l'agent CodeGate, qui ne modifie rien sur le serveur." },
      {
        kind: "table",
        columns: [
          { label: "Sévérité", width: 0.1 },
          { label: "Domaine", width: 0.12 },
          { label: "Constat et preuve", width: 0.42 },
          { label: "Correction et vérification", width: 0.36 },
        ],
        rows: bySeverity(f).map((x) => [
          `${SEVERITY_FR[x.severity] ?? x.severity}${x.exposure === "public" ? "\nexposé" : ""}`,
          INFRA_FR[x.category] ?? x.category,
          `${x.title}\n${x.detail}${x.evidence ? `\nPreuve : ${x.evidence}` : ""}`,
          `${x.recommendation}${x.verifyCommand ? `\nVérifier : ${x.verifyCommand}` : ""}`,
        ]),
        fontSize: 7,
        empty: "Aucun point à corriger.",
      },
      ...(acceptedFindings.length
        ? ([
            {
              kind: "section",
              title: "Risques acceptés ou atténués",
              subtitle: "Exclus du score par une décision tracée dans le journal d'audit.",
            },
            {
              kind: "table",
              columns: [
                { label: "Sévérité", width: 0.1 },
                { label: "Point", width: 0.32 },
                { label: "Décision", width: 0.16 },
                { label: "Justification", width: 0.42 },
              ],
              rows: acceptedFindings.map((x) => {
                const a = acceptance.get(x.checkId)!;
                return [
                  SEVERITY_FR[x.severity] ?? x.severity,
                  x.title,
                  `${a.kind === "accepted" ? "Accepté" : "Atténué"} le ${fmtDate(a.createdAt)}${a.expiresAt ? `\nà revoir le ${fmtDate(a.expiresAt)}` : ""}`,
                  a.justification,
                ];
              }),
              fontSize: 7.5,
            },
          ] satisfies Block[])
        : []),
      ...(analysis.mitigations?.length
        ? ([
            { kind: "section", title: "Contrôles en place" },
            { kind: "text", text: analysis.mitigations.map((m) => `• ${m}`).join("\n") },
          ] satisfies Block[])
        : []),
      ...(server.scans.length
        ? ([
            { kind: "section", title: "Historique des audits", subtitle: "Score et points corrigés à chaque rapport de l'agent." },
            {
              kind: "table",
              columns: [
                { label: "Date", width: 0.25 },
                { label: "Score", width: 0.15, align: "right" },
                { label: "Critiques / élevés", width: 0.2, align: "right" },
                { label: "Corrigés", width: 0.2, align: "right" },
                { label: "Nouveaux", width: 0.2, align: "right" },
              ],
              rows: server.scans.map((s) => [
                fmtDate(s.createdAt),
                `${s.score}/100`,
                `${s.critical} / ${s.high}`,
                String(s.resolved.length),
                String(s.introduced.length),
              ]),
            },
          ] satisfies Block[])
        : []),
    ],
  };
}

// ---------------------------------------------------------- brute force --

export async function bruteForceDocument(organizationId: string, id: string): Promise<ReportDocument | null> {
  const target = await prisma.bruteForceTarget.findFirst({
    where: { id, organizationId },
    include: {
      tests: { orderBy: { createdAt: "desc" }, take: 100 },
      organization: { select: { name: true, bruteforcePolicies: true } },
    },
  });
  if (!target) return null;
  const last = target.tests[0];
  const fails = target.tests.filter((t) => t.result === "fail").length;
  const verdict: NonNullable<ReportDocument["verdict"]> = !last
    ? { label: "Non testé", tone: "warn", text: "Aucun test n'a encore été lancé sur cette cible." }
    : last.result === "pass"
      ? { label: "Conforme", tone: "ok", text: `Dernier test : ${last.summary}` }
      : last.result === "warn"
        ? { label: "À améliorer", tone: "warn", text: `Dernier test : ${last.summary}` }
        : { label: "Non conforme", tone: "bad", text: `Dernier test : ${last.summary}` };
  const policies = target.organization.bruteforcePolicies;

  return {
    type: "bruteforce",
    heading: "RAPPORT DE TEST ANTI BRUTE FORCE",
    eyebrow: "BRUTEFORCE SHIELD",
    title: "Test de résistance au brute force",
    subtitle: target.origin,
    organization: target.organization.name,
    subjectId: target.id,
    subjectLabel: target.origin,
    facts: [
      ["Cible", `${target.name} · ${target.origin}`],
      ["Environnement", target.environment],
      ["Propriété vérifiée", target.verifiedAt ? `oui, le ${fmtDate(target.verifiedAt)}` : "non"],
      ["Dernier test", fmtDate(last?.createdAt)],
    ],
    verdict,
    kpis: [
      { label: "Tests réalisés", value: target.tests.length },
      { label: "Non conformes", value: fails, alert: fails > 0 },
      { label: "Bloqué après (dernier)", value: last?.blockedAfter ? `${last.blockedAfter} essais` : "—", alert: !!last && !last.blockedAfter },
      { label: "Politiques définies", value: policies.length },
    ],
    blocks: [
      {
        kind: "text",
        text: "Tests réalisés uniquement sur un domaine dont la propriété a été prouvée, avec un compte de test dédié et en faible volume (20 requêtes maximum).",
      },
      { kind: "section", title: "Résultats des tests" },
      {
        kind: "table",
        columns: [
          { label: "Date", width: 0.17 },
          { label: "Test", width: 0.2 },
          { label: "Point d'entrée", width: 0.18 },
          { label: "Essais", width: 0.1, align: "right" },
          { label: "Résultat", width: 0.35 },
        ],
        rows: target.tests.map((t) => [
          fmtDate(t.createdAt),
          BF_TYPE_FR[t.testType] ?? t.testType,
          t.endpoint,
          `${t.attempts}${t.blockedAfter ? ` (bloqué à ${t.blockedAfter})` : ""}`,
          `${BF_RESULT_FR[t.result] ?? t.result} — ${t.summary}`,
        ]),
        empty: "Aucun test lancé.",
      },
      { kind: "section", title: "Politiques de référence" },
      {
        kind: "table",
        columns: [
          { label: "Point d'entrée", width: 0.4 },
          { label: "Échecs max", width: 0.2, align: "right" },
          { label: "Fenêtre", width: 0.2, align: "right" },
          { label: "Blocage", width: 0.2, align: "right" },
        ],
        rows: policies.map((p) => [p.endpoint, String(p.maxAttempts), `${p.windowSeconds} s`, `${p.lockoutSeconds} s`]),
        empty: "Aucune politique : la référence est 5 échecs en 10 minutes.",
      },
    ],
  };
}

// --------------------------------------------------------------- backup --

export async function backupDocument(organizationId: string, id: string): Promise<ReportDocument | null> {
  const job = await prisma.backupJob.findFirst({
    where: { id, organizationId },
    include: {
      runs: { orderBy: { finishedAt: "desc" }, take: 30 },
      restoreTests: { orderBy: { completedAt: "desc" }, take: 20 },
      server: { select: { name: true } },
      organization: { select: { name: true } },
    },
  });
  if (!job) return null;
  const e = evaluateBackup(job, job.runs[0] ?? null, job.restoreTests[0] ?? null);
  const failed = e.checks.filter((c) => !c.ok);
  const verdict: NonNullable<ReportDocument["verdict"]> = {
    label: BACKUP_STATUS_FR[e.status] ?? e.status,
    tone: e.status === "healthy" ? "ok" : e.status === "attention" ? "warn" : "bad",
    text: `Score de récupération ${e.score}/100${e.ransomwareReady ? " · prête face à un rançongiciel" : " · pas encore prête face à un rançongiciel"}. ${
      failed.length ? `${failed.length} contrôle(s) à corriger.` : "Tous les contrôles sont satisfaits."
    }`,
  };

  return {
    type: "backup",
    heading: "RAPPORT D'AUDIT DE SAUVEGARDE",
    eyebrow: "BACKUP SHIELD",
    title: "Audit de sauvegarde",
    subtitle: job.name,
    organization: job.organization.name,
    subjectId: job.id,
    subjectLabel: job.name,
    facts: [
      ["Sauvegarde", `${job.name} (${job.type})`],
      ["Serveur", job.server?.name ?? "—"],
      ["Fréquence attendue", `toutes les ${job.frequencyHours} h`],
      ["Dernière exécution", fmtDate(job.runs[0]?.finishedAt)],
      ["Dernière restauration testée", fmtDate(job.restoreTests[0]?.completedAt)],
    ],
    verdict,
    kpis: [
      { label: "Score de récupération / 100", value: e.score, alert: e.score < 70 },
      { label: "Contrôles à corriger", value: failed.length, alert: failed.length > 0 },
      { label: "Exécutions récentes", value: job.runs.length },
      { label: "Restaurations testées", value: job.restoreTests.length, alert: job.restoreTests.length === 0 },
    ],
    blocks: [
      { kind: "section", title: "Contrôles", subtitle: "Existence, chiffrement, intégrité, isolement et restauration réellement testée." },
      {
        kind: "table",
        columns: [
          { label: "Contrôle", width: 0.28 },
          { label: "État", width: 0.12 },
          { label: "Constat", width: 0.32 },
          { label: "Recommandation", width: 0.28 },
        ],
        rows: [...e.checks]
          .sort((a, b) => Number(a.ok) - Number(b.ok))
          .map((c) => [c.label, c.ok ? "Conforme" : SEVERITY_FR[c.severity] ?? c.severity, c.detail, c.ok ? "—" : (c.recommendation ?? "—")]),
        fontSize: 7.5,
      },
      { kind: "section", title: "Historique des exécutions" },
      {
        kind: "table",
        columns: [
          { label: "Terminée le", width: 0.2 },
          { label: "Statut", width: 0.12 },
          { label: "Taille", width: 0.12, align: "right" },
          { label: "Chiffrement", width: 0.2 },
          { label: "Stockage", width: 0.2 },
          { label: "Intégrité", width: 0.16 },
        ],
        rows: job.runs.map((r) => [
          fmtDate(r.finishedAt),
          r.status,
          r.sizeBytes ? `${(r.sizeBytes / 1024 / 1024).toFixed(1)} Mo` : "—",
          r.encrypted ? (r.encryptionAlgorithm ?? "oui") : "non chiffrée",
          `${r.storageProvider ?? "—"} · ${r.storageLocation}${r.immutable ? " · immuable" : ""}`,
          r.integrityOk === null ? "non vérifiée" : r.integrityOk ? "vérifiée" : "corrompue",
        ]),
        empty: "Aucune exécution reçue.",
      },
      { kind: "section", title: "Tests de restauration" },
      {
        kind: "table",
        columns: [
          { label: "Date", width: 0.2 },
          { label: "Moteur", width: 0.15 },
          { label: "Durée", width: 0.12, align: "right" },
          { label: "Résultat", width: 0.13 },
          { label: "Détail", width: 0.4 },
        ],
        rows: job.restoreTests.map((t) => [
          fmtDate(t.completedAt),
          t.engine,
          `${t.durationSeconds} s`,
          t.result,
          [t.restoredTables != null ? `${t.restoredTables} table(s)` : "", t.restoredRecords != null ? `${t.restoredRecords} enregistrement(s)` : "", t.detail ?? ""]
            .filter(Boolean)
            .join(" · ") || "—",
        ]),
        empty: "Aucune restauration testée : une sauvegarde jamais restaurée n'est pas une sauvegarde fiable.",
      },
    ],
  };
}

export function documentFor(type: ReportType, organizationId: string, id: string): Promise<ReportDocument | null> {
  switch (type) {
    case "pull-request":
      return pullRequestDocument(organizationId, id);
    case "scan":
      return scanDocument(organizationId, id);
    case "server":
      return serverDocument(organizationId, id);
    case "bruteforce":
      return bruteForceDocument(organizationId, id);
    case "backup":
      return backupDocument(organizationId, id);
  }
}

/** What the public verification page shows about the content. */
export function reportSummary(report: ReportDocument): { title: string; kpis: Kpi[]; verdict: string | null } {
  return {
    title: report.title,
    kpis: report.kpis.map((k) => ({ label: k.label, value: k.value })),
    verdict: report.verdict?.label ?? null,
  };
}
