import type { Severity } from "@codegate/shared";
import { SEVERITY_WEIGHT as INFRA_WEIGHT, SCORE_K } from "../analysis/infra.js";
import { DEP_RISK_WEIGHT, SECRET_WEIGHT, SEVERITY_WEIGHT as CODE_WEIGHT } from "../analysis/risk.js";
import { WEIGHT as BACKUP_WEIGHT } from "../analysis/backup.js";
import { REF, type Effort, type ExpertInput, type ExpertItem } from "./expert.js";

/**
 * Maps each module's findings to expert items: which domain, what to do,
 * how hard it is, what it means for the business and which framework
 * requirements it touches.
 */

interface Rule {
  domain: string;
  action: string;
  effort: Effort;
  impact: string;
  refs: string[];
}

// ─── Infra Shield ─────────────────────────────────────────────────────────

export const INFRA_DOMAINS = ["Exposition réseau", "Accès et comptes", "Conteneurs", "Données et secrets", "Chiffrement (TLS / HTTP)", "Maintenance"];

const TAKEOVER = "prise de contrôle complète du serveur et de toutes les données qu'il héberge";
const INFRA_RULES: Record<string, Rule> = {
  "port.public": { domain: "Exposition réseau", action: "Fermer au public les ports de bases et d'API internes (bind 127.0.0.1 ou réseau privé)", effort: "faible", impact: "accès direct aux bases de données ou à l'API Docker depuis Internet", refs: [REF.iso820, REF.owaspA05, REF.cisLinuxFirewall] },
  "firewall.inactive": { domain: "Exposition réseau", action: "Activer un pare-feu (refus par défaut, 22/80/443 seulement)", effort: "faible", impact: "tout service lancé par erreur devient joignable depuis Internet", refs: [REF.iso820, REF.cisLinuxFirewall, REF.anssiLinux] },
  "firewall.docker_bypass": { domain: "Exposition réseau", action: "Publier les ports Docker sur 127.0.0.1 derrière le reverse proxy", effort: "faible", impact: "des services que vous croyez fermés par le pare-feu sont en réalité publics", refs: [REF.iso820, REF.cisDockerRuntime, REF.owaspA05] },
  "network.host_mode": { domain: "Exposition réseau", action: "Sortir les conteneurs du réseau de l'hôte (réseau Docker dédié)", effort: "moyen", impact: "un conteneur compromis joint tous les services internes du serveur", refs: [REF.iso820, REF.cisDockerRuntime, REF.anssiDocker] },
  "ssh.root_login": { domain: "Accès et comptes", action: "Interdire la connexion SSH de root (PermitRootLogin no)", effort: "faible", impact: "le compte root est directement exposé aux attaques", refs: [REF.iso82, REF.cisLinuxSsh, REF.anssiLinux] },
  "ssh.root_login_key": { domain: "Accès et comptes", action: "Passer par un compte nominatif avec sudo plutôt que root", effort: "faible", impact: "les actions d'administration ne sont pas attribuables à une personne", refs: [REF.iso82, REF.cisLinuxSsh] },
  "ssh.password_auth": { domain: "Accès et comptes", action: "Désactiver l'authentification SSH par mot de passe (clés uniquement)", effort: "faible", impact: "un mot de passe deviné par brute force ouvre le serveur", refs: [REF.iso85, REF.owaspA07, REF.cisLinuxSsh] },
  "ssh.max_auth_tries": { domain: "Accès et comptes", action: "Limiter MaxAuthTries à 3", effort: "faible", impact: "chaque connexion permet trop d'essais d'authentification", refs: [REF.iso85, REF.cisLinuxSsh] },
  "bruteforce.ssh_unprotected": { domain: "Accès et comptes", action: "Installer Fail2ban ou CrowdSec sur SSH", effort: "faible", impact: "les tentatives de connexion répétées ne sont jamais bloquées", refs: [REF.iso85, REF.owaspA07] },
  "host.uid0_accounts": { domain: "Accès et comptes", action: "Supprimer les comptes UID 0 autres que root (et enquêter sur leur origine)", effort: "moyen", impact: "un compte root caché, signe possible d'une intrusion passée", refs: [REF.iso82, REF.cisLinuxAccounts, REF.anssiLinux] },
  "host.sudo_nopasswd": { domain: "Accès et comptes", action: "Exiger le mot de passe pour sudo (ou le limiter à des commandes précises)", effort: "faible", impact: "un compte compromis devient root sans autre barrière", refs: [REF.iso82, REF.cisLinuxAccounts] },
  "admin.exposed": { domain: "Accès et comptes", action: "Retirer les consoles d'administration d'Internet ou les placer derrière une authentification (SSO, VPN)", effort: "moyen", impact: "consultation ou modification de la configuration par n'importe qui", refs: [REF.iso515, REF.owaspA01, REF.owaspA05] },
  "admin.auth_broken": { domain: "Accès et comptes", action: "Réparer le middleware d'authentification (fichier d'utilisateurs manquant)", effort: "faible", impact: "la protection d'accès que vous croyez en place ne fonctionne pas", refs: [REF.iso515, REF.owaspA01, REF.owaspA07] },
  "docker.socket": { domain: "Conteneurs", action: "Remplacer le socket Docker monté par un proxy en lecture seule", effort: "moyen", impact: TAKEOVER, refs: [REF.iso82, REF.cisDockerRuntime, REF.anssiDocker] },
  "docker.socket_proxy_write": { domain: "Conteneurs", action: "Désactiver l'écriture sur le proxy du socket Docker (POST=0)", effort: "faible", impact: TAKEOVER, refs: [REF.iso82, REF.cisDockerRuntime] },
  "docker.socket_proxy_public": { domain: "Conteneurs", action: "Ne plus publier le proxy du socket Docker (réseau interne)", effort: "faible", impact: "la configuration et les secrets de tous les conteneurs sont lisibles depuis Internet", refs: [REF.iso820, REF.cisDockerRuntime] },
  "docker.privileged": { domain: "Conteneurs", action: "Supprimer le mode privilégié (capacités et périphériques ciblés à la place)", effort: "moyen", impact: TAKEOVER, refs: [REF.iso82, REF.cisDockerRuntime, REF.anssiDocker] },
  "docker.host_mount": { domain: "Conteneurs", action: "Ne monter que les sous-dossiers nécessaires de l'hôte, en lecture seule", effort: "moyen", impact: "lecture des secrets de l'hôte (mots de passe, clés) ou modification du système", refs: [REF.iso82, REF.cisDockerRuntime, REF.anssiDocker] },
  "docker.caps": { domain: "Conteneurs", action: "Retirer les capacités Linux sensibles (cap_drop: ALL puis le strict nécessaire)", effort: "faible", impact: "sortie du conteneur vers l'hôte", refs: [REF.iso82, REF.cisDockerRuntime] },
  "docker.root": { domain: "Conteneurs", action: "Faire tourner les services sous un utilisateur non root", effort: "moyen", impact: "une faille applicative donne root dans le conteneur", refs: [REF.iso82, REF.cisDockerImages, REF.anssiDocker] },
  "docker.limits": { domain: "Conteneurs", action: "Fixer des limites mémoire et de processus aux conteneurs", effort: "faible", impact: "un service emballé peut arrêter tout le serveur", refs: [REF.iso89, REF.cisDockerRuntime] },
  "daemon.hardening": { domain: "Conteneurs", action: "Durcir /etc/docker/daemon.json (limite des journaux, live-restore, no-new-privileges)", effort: "faible", impact: "disque saturé par les journaux et élévations de privilèges facilitées", refs: [REF.iso89, REF.cisDockerDaemon] },
  "secrets.env": { domain: "Données et secrets", action: "Passer les secrets en fichiers (Docker secrets, variantes _FILE) au lieu de variables d'environnement", effort: "moyen", impact: "fuite des mots de passe et clés via docker inspect ou les journaux", refs: [REF.iso517, REF.owaspA05, REF.anssiDocker] },
  "secrets.env_file": { domain: "Données et secrets", action: "Restreindre les fichiers .env (chmod 600)", effort: "faible", impact: "n'importe quel utilisateur du serveur lit les secrets", refs: [REF.iso517] },
  "backups.none": { domain: "Données et secrets", action: "Planifier une sauvegarde chiffrée et externalisée de la base", effort: "moyen", impact: "perte définitive des données en cas de panne, d'erreur ou de rançongiciel", refs: [REF.iso813, REF.iso530] },
  "backups.unmonitored": { domain: "Données et secrets", action: "Faire suivre la sauvegarde par CodeGate (codegate-backup report)", effort: "faible", impact: "rien ne prouve que la sauvegarde existante est restaurable", refs: [REF.iso813] },
  "tls.cert_expiry": { domain: "Chiffrement (TLS / HTTP)", action: "Automatiser le renouvellement des certificats", effort: "faible", impact: "site inaccessible et alertes de sécurité dans les navigateurs", refs: [REF.iso824, REF.anssiTls] },
  "tls.untrusted": { domain: "Chiffrement (TLS / HTTP)", action: "Servir un certificat d'une autorité reconnue avec sa chaîne complète", effort: "faible", impact: "interception possible du trafic des utilisateurs", refs: [REF.iso824, REF.owaspA02, REF.anssiTls] },
  "tls.weak_protocol": { domain: "Chiffrement (TLS / HTTP)", action: "Exiger TLS 1.2 minimum", effort: "faible", impact: "trafic déchiffrable par un attaquant sur le réseau", refs: [REF.iso824, REF.owaspA02, REF.anssiTls] },
  "tls.legacy_accepted": { domain: "Chiffrement (TLS / HTTP)", action: "Désactiver TLS 1.0 et 1.1", effort: "faible", impact: "attaque par rétrogradation vers un protocole obsolète", refs: [REF.iso824, REF.owaspA02, REF.anssiTls] },
  "tls.default_cert": { domain: "Chiffrement (TLS / HTTP)", action: "Mettre à jour l'agent pour vérifier les certificats de chaque domaine", effort: "faible", impact: "certificats réels non vérifiés", refs: [REF.iso824] },
  "http.headers": { domain: "Chiffrement (TLS / HTTP)", action: "Ajouter les en-têtes de sécurité (HSTS, CSP, X-Frame-Options, nosniff)", effort: "faible", impact: "sessions détournables et pages intégrables par un site malveillant", refs: [REF.owaspA05, REF.iso89] },
  "updates.security_pending": { domain: "Maintenance", action: "Appliquer les mises à jour de sécurité en attente", effort: "faible", impact: "failles publiques et connues des attaquants toujours présentes", refs: [REF.iso88, REF.owaspA06, REF.cisLinuxUpdates] },
  "updates.no_auto": { domain: "Maintenance", action: "Activer les mises à jour de sécurité automatiques", effort: "faible", impact: "les correctifs critiques dépendent d'une action manuelle", refs: [REF.iso88, REF.cisLinuxUpdates] },
  "updates.auto_stale": { domain: "Maintenance", action: "Réparer les mises à jour automatiques (timers apt arrêtés)", effort: "faible", impact: "le serveur ne reçoit plus de correctifs alors que vous le croyez à jour", refs: [REF.iso88, REF.cisLinuxUpdates] },
  "firewall.unknown": { domain: "Exposition réseau", action: "Lancer l'agent avec les droits nécessaires pour lire le pare-feu", effort: "faible", impact: "état du pare-feu inconnu", refs: [] },
};

export interface InfraLike {
  checkId: string;
  category: string;
  severity: Severity;
  title: string;
}

export function infraItems(findings: InfraLike[], chains: { title: string; checkIds: string[] }[] = []): ExpertItem[] {
  return findings.map((f) => {
    const parts = f.checkId.split(".");
    const key = parts.slice(0, 2).join(".");
    const rule = INFRA_RULES[key] ?? {
      domain: "Exposition réseau",
      action: f.title,
      effort: "moyen" as Effort,
      impact: f.title.toLowerCase(),
      refs: [REF.iso89],
    };
    const inChains = chains.filter((c) => c.checkIds.includes(f.checkId)).map((c) => c.title);
    const subject = parts.slice(2).join(".");
    return {
      key,
      domain: rule.domain,
      severity: f.severity,
      title: f.title,
      action: rule.action,
      effort: rule.effort,
      impact: rule.impact,
      refs: rule.refs,
      weight: INFRA_WEIGHT[f.severity],
      ...(subject ? { subject } : {}),
      ...(inChains.length ? { chains: inChains } : {}),
    };
  });
}

/** Same curve as the server score: 100 × K / (K + penalty). */
export const infraRescore = (items: ExpertItem[]) =>
  Math.round((100 * SCORE_K) / (SCORE_K + items.reduce((s, i) => s + i.weight, 0)));

// ─── Code (pull request, repository scan) ────────────────────────────────

export const CODE_DOMAINS = ["Secrets", "Code applicatif", "Configuration et CI", "Authentification", "Dépendances", "Agents IA"];

const CWE: [RegExp, string][] = [
  [/sql/i, "MITRE CWE · CWE-89 Injection SQL"],
  [/xss|innerhtml|dangerouslysetinnerhtml|script/i, "MITRE CWE · CWE-79 Cross-site scripting"],
  [/commande|command|exec|shell|spawn/i, "MITRE CWE · CWE-78 Injection de commande"],
  [/\beval\b|function\(/i, "MITRE CWE · CWE-95 Évaluation de code dynamique"],
  [/chemin|path traversal|\.\.\//i, "MITRE CWE · CWE-22 Traversée de répertoires"],
  [/ssrf/i, "MITRE CWE · CWE-918 Falsification de requête côté serveur"],
  [/désérialis|deserial|pickle|yaml\.load/i, "MITRE CWE · CWE-502 Désérialisation non sûre"],
  [/md5|sha-?1|des\b|chiffrement faible|weak (hash|cipher)/i, "MITRE CWE · CWE-327 Algorithme cryptographique faible"],
  [/aléatoire|math\.random|random/i, "MITRE CWE · CWE-338 Générateur aléatoire prévisible"],
  [/cors/i, "MITRE CWE · CWE-942 Politique CORS permissive"],
];

const FINDING_RULES: Record<string, Omit<Rule, "action"> & { action?: string }> = {
  sast: { domain: "Code applicatif", effort: "moyen", impact: "exploitation d'une faille de l'application (vol de données, exécution de code)", refs: [REF.owaspA03, REF.iso828] },
  config: { domain: "Configuration et CI", effort: "faible", impact: "chaîne de livraison ou infrastructure détournable", refs: [REF.owaspA05, REF.owaspA08, REF.iso89] },
  auth: { domain: "Authentification", effort: "moyen", impact: "accès à des comptes ou à des fonctions sans autorisation", refs: [REF.owaspA07, REF.owaspA01, REF.iso85] },
  prompt_injection: { domain: "Agents IA", effort: "faible", impact: "un agent IA détourné par des instructions cachées dans le code", refs: [REF.llm01, REF.iso828] },
  dependency: { domain: "Dépendances", effort: "faible", impact: "code malveillant ou vulnérable importé dans l'application", refs: [REF.owaspA06, REF.iso88] },
  secret: { domain: "Secrets", effort: "moyen", impact: "accès frauduleux aux services tiers (paiement, cloud, API) avec vos identifiants", refs: [REF.iso517, REF.owaspA07] },
};

export interface CodeFinding {
  type: string;
  severity: Severity;
  title: string;
  ruleId?: string | null;
  filePath?: string | null;
  remediation?: string | null;
  status?: string;
}

export function codeItems(
  secrets: { secretType: string; location: string; severity: Severity; status?: string; revokedAt?: Date | null }[],
  findings: CodeFinding[],
  dependencies: { name: string; version: string; resolvedVersion?: string; riskLevel: string }[],
): ExpertItem[] {
  const items: ExpertItem[] = [];
  for (const s of secrets) {
    if (s.revokedAt || s.status === "resolved" || s.status === "false_positive") continue;
    items.push({
      key: `secret.${s.secretType}`,
      domain: "Secrets",
      severity: "critical",
      title: `${s.secretType} exposé`,
      action: `Révoquer et remplacer le secret « ${s.secretType} », puis le retirer du code et de l'historique Git`,
      effort: "moyen",
      impact: FINDING_RULES.secret!.impact,
      refs: [REF.iso517, REF.owaspA07, "MITRE CWE · CWE-798 Identifiants codés en dur"],
      weight: SECRET_WEIGHT + CODE_WEIGHT[s.severity],
      subject: s.location,
    });
  }
  for (const f of findings) {
    if (f.status === "false_positive" || f.status === "resolved" || f.severity === "info") continue;
    const rule = FINDING_RULES[f.type] ?? FINDING_RULES.sast!;
    const cwe = f.type === "sast" || f.type === "auth" ? CWE.find(([re]) => re.test(f.title))?.[1] : undefined;
    items.push({
      key: `finding.${f.ruleId ?? f.title}`,
      domain: rule.domain,
      severity: f.severity,
      title: f.title,
      action: `Corriger : ${f.title}${f.remediation ? ` — ${f.remediation.split(/(?<=\.)\s/)[0]}` : ""}`,
      effort: rule.effort,
      impact: rule.impact,
      refs: [...rule.refs, ...(cwe ? [cwe] : [])],
      weight: CODE_WEIGHT[f.severity],
      ...(f.filePath ? { subject: f.filePath } : {}),
    });
  }
  for (const d of dependencies) {
    if (d.riskLevel === "low") continue;
    const sev: Severity = d.riskLevel === "critical" ? "critical" : d.riskLevel === "high" ? "high" : "medium";
    items.push({
      key: `dependency.${d.name}`,
      domain: "Dépendances",
      severity: sev,
      title: `Dépendance à risque ${d.name}@${d.resolvedVersion ?? d.version}`,
      action: `Remplacer ou mettre à jour ${d.name}`,
      effort: "faible",
      impact: FINDING_RULES.dependency!.impact,
      refs: FINDING_RULES.dependency!.refs,
      weight: DEP_RISK_WEIGHT[d.riskLevel as keyof typeof DEP_RISK_WEIGHT] ?? 8,
      subject: `${d.name}@${d.resolvedVersion ?? d.version}`,
    });
  }
  return items;
}

/** The PR / scan risk score: sum of weights, capped at 100. */
export const codeRescore = (items: ExpertItem[]) => Math.min(100, Math.round(items.reduce((s, i) => s + i.weight, 0)));

// ─── Backup Shield ───────────────────────────────────────────────────────

export const BACKUP_DOMAINS = ["Disponibilité", "Chiffrement", "Intégrité", "Isolement (rançongiciel)", "Restauration"];
const BACKUP_RULES: Record<string, Omit<Rule, "refs">> = {
  exists: { domain: "Disponibilité", action: "Mettre en place la sauvegarde et la faire remonter à CodeGate", effort: "moyen", impact: "aucune copie des données en cas de sinistre" },
  freshness: { domain: "Disponibilité", action: "Rétablir la planification de la sauvegarde (elle n'a pas tourné à temps)", effort: "faible", impact: "les données récentes seraient perdues en cas de sinistre" },
  last_status: { domain: "Disponibilité", action: "Corriger l'échec de la dernière sauvegarde", effort: "faible", impact: "la dernière copie exploitable est plus ancienne qu'attendu" },
  encryption_at_rest: { domain: "Chiffrement", action: "Chiffrer les sauvegardes au repos (age, restic, GPG)", effort: "faible", impact: "fuite de toutes les données si le stockage est compromis" },
  encryption_in_transit: { domain: "Chiffrement", action: "Envoyer les sauvegardes en TLS", effort: "faible", impact: "interception des données pendant le transfert" },
  key_isolation: { domain: "Chiffrement", action: "Conserver la clé de chiffrement hors du serveur sauvegardé (KMS, coffre)", effort: "moyen", impact: "un attaquant qui prend le serveur prend aussi la clé" },
  integrity_hash: { domain: "Intégrité", action: "Calculer et vérifier l'empreinte de chaque sauvegarde", effort: "faible", impact: "une copie corrompue passerait inaperçue" },
  integrity_verified: { domain: "Intégrité", action: "Vérifier régulièrement l'intégrité d'une copie re-téléchargée", effort: "faible", impact: "corruption silencieuse découverte le jour de la restauration" },
  isolation: { domain: "Isolement (rançongiciel)", action: "Externaliser une copie hors du serveur (autre fournisseur ou site)", effort: "moyen", impact: "le sinistre ou le rançongiciel détruit aussi les sauvegardes" },
  immutability: { domain: "Isolement (rançongiciel)", action: "Rendre les copies immuables (object lock, WORM)", effort: "moyen", impact: "un rançongiciel peut chiffrer ou supprimer les sauvegardes" },
  separate_account: { domain: "Isolement (rançongiciel)", action: "Stocker les copies dans un compte séparé de la production", effort: "moyen", impact: "un identifiant de production volé suffit à effacer les sauvegardes" },
  retention: { domain: "Isolement (rançongiciel)", action: "Allonger la rétention (au moins 30 jours)", effort: "faible", impact: "une compromission découverte tard ne laisse aucune copie saine" },
  restore_test: { domain: "Restauration", action: "Tester la restauration au moins une fois par mois", effort: "moyen", impact: "rien ne prouve que les données sont réellement récupérables" },
};

export function backupItems(checks: { id: string; ok: boolean; severity: Severity; label: string }[]): ExpertItem[] {
  return checks
    .filter((c) => !c.ok)
    .map((c) => {
      const rule = BACKUP_RULES[c.id] ?? { domain: "Disponibilité", action: c.label, effort: "moyen" as Effort, impact: c.label };
      return {
        key: `backup.${c.id}`,
        domain: rule.domain,
        severity: c.severity,
        title: c.label,
        action: rule.action,
        effort: rule.effort,
        impact: rule.impact,
        refs: [REF.iso813, ...(rule.domain === "Chiffrement" ? [REF.iso824] : []), ...(rule.domain !== "Chiffrement" ? [REF.iso530] : [])],
        weight: BACKUP_WEIGHT[c.severity],
      };
    });
}

export const backupRescore = (items: ExpertItem[]) => Math.max(0, 100 - items.reduce((s, i) => s + i.weight, 0));

// ─── BruteForce Shield ───────────────────────────────────────────────────

export const BRUTEFORCE_DOMAINS = ["Verrouillage des comptes", "Énumération des comptes", "Politique"];

export function bruteForceItems(
  tests: { testType: string; result: string; summary: string; endpoint: string; createdAt: Date }[],
  policies: number,
): ExpertItem[] {
  const latest = new Map<string, (typeof tests)[number]>();
  for (const t of tests) if (!latest.has(t.testType)) latest.set(t.testType, t); // tests are newest first
  const items: ExpertItem[] = [];
  for (const t of latest.values()) {
    if (t.result === "pass") continue;
    const sev: Severity = t.result === "fail" ? "high" : "medium";
    const lockout = t.testType === "login_lockout";
    items.push({
      key: `bruteforce.${t.testType}`,
      domain: lockout ? "Verrouillage des comptes" : "Énumération des comptes",
      severity: sev,
      title: t.summary,
      action: lockout
        ? `Verrouiller le compte ou ralentir après 5 échecs sur ${t.endpoint} (délai progressif, puis CAPTCHA)`
        : `Renvoyer la même réponse que le compte existe ou non sur ${t.endpoint}`,
      effort: "moyen",
      impact: lockout
        ? "les mots de passe de vos utilisateurs peuvent être devinés par essais répétés"
        : "un attaquant établit la liste de vos comptes utilisateurs avant de les cibler",
      refs: [REF.owaspA07, REF.iso85],
      weight: INFRA_WEIGHT[sev],
      subject: t.endpoint,
    });
  }
  if (!policies) {
    items.push({
      key: "bruteforce.no_policy",
      domain: "Politique",
      severity: "low",
      title: "Aucune politique anti brute force définie",
      action: "Définir la politique attendue (seuil, fenêtre, durée de blocage) pour noter les tests",
      effort: "faible",
      impact: "les tests ne sont comparés qu'à la référence par défaut",
      refs: [REF.iso85],
      weight: INFRA_WEIGHT.low,
    });
  }
  return items;
}

export type { ExpertInput };
