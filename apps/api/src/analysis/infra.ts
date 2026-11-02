import type { AgentReport, Severity } from "@codegate/shared";

/**
 * Infra Shield rules (extension §3): turn the facts reported by the agent into
 * findings with an exact remediation, and a 0–100 server security score.
 * Deterministic — the same report always gives the same result.
 */

export type InfraCategory = "ports" | "ssh" | "firewall" | "bruteforce" | "docker" | "updates" | "backups" | "tls";

export interface InfraFinding {
  category: InfraCategory;
  checkId: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface InfraResult {
  score: number;
  findings: InfraFinding[];
}

/** Ports that must never be reachable from the Internet by default (§3.4). */
const DANGEROUS_PORTS: Record<number, { service: string; severity: Severity; risk: string }> = {
  2375: { service: "Docker API", severity: "critical", risk: "prise de contrôle du serveur" },
  2376: { service: "Docker API (TLS)", severity: "high", risk: "prise de contrôle du serveur" },
  3306: { service: "MySQL", severity: "critical", risk: "accès direct à la base" },
  5432: { service: "PostgreSQL", severity: "critical", risk: "accès direct à la base" },
  6379: { service: "Redis", severity: "critical", risk: "lecture, modification ou suppression du cache" },
  27017: { service: "MongoDB", severity: "critical", risk: "accès direct à la base" },
  9200: { service: "Elasticsearch", severity: "critical", risk: "exposition de données" },
  11211: { service: "Memcached", severity: "high", risk: "fuite de données et amplification" },
  8080: { service: "Admin / debug", severity: "high", risk: "accès à des interfaces internes" },
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
  info: 0,
};

/** True when a bind address is reachable beyond the host itself. */
export function isPublicBind(address: string): boolean {
  const a = address.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (a === "127.0.0.1" || a === "::1" || a.startsWith("127.")) return false;
  if (a === "localhost") return false;
  return true; // 0.0.0.0, ::, *, or a concrete interface address
}

function sshPortsOf(report: AgentReport): number[] {
  return report.listening
    .filter((l) => l.proto === "tcp" && (l.process === "sshd" || l.port === 22))
    .map((l) => l.port);
}

export function evaluateInfra(report: AgentReport): InfraResult {
  const findings: InfraFinding[] = [];
  const add = (f: InfraFinding) => findings.push(f);

  // ── Ports & services exposed (host sockets + Docker published ports) ──
  const exposed = new Map<number, string>(); // port -> where
  for (const l of report.listening) {
    if (l.proto === "tcp" && isPublicBind(l.address)) {
      exposed.set(l.port, l.process ? `processus ${l.process}` : "processus inconnu");
    }
  }
  for (const c of report.docker?.containers ?? []) {
    for (const p of c.publishedPorts) {
      if (isPublicBind(p.hostIp || "0.0.0.0")) exposed.set(p.hostPort, `conteneur ${c.name}`);
    }
  }
  for (const [port, where] of [...exposed].sort((a, b) => a[0] - b[0])) {
    const known = DANGEROUS_PORTS[port];
    if (!known) continue;
    add({
      category: "ports",
      checkId: `port.public.${port}`,
      severity: known.severity,
      title: `${known.service} exposé publiquement (port ${port})`,
      detail: `Le port ${port} écoute sur toutes les interfaces (${where}). Risque : ${known.risk}.`,
      recommendation:
        `Liez le service à 127.0.0.1 ou à un réseau privé, et fermez le port : \`ufw deny ${port}/tcp\`. ` +
        `Pour Docker, publiez \`127.0.0.1:${port}:${port}\` au lieu de \`${port}:${port}\` (Docker contourne UFW).`,
    });
  }

  // ── SSH (§3.3) ──
  const sshExposed = sshPortsOf(report).some((p) => exposed.has(p));
  if (report.ssh) {
    const root = report.ssh.permitRootLogin?.toLowerCase() ?? null;
    if (root === "yes") {
      add({
        category: "ssh",
        checkId: "ssh.root_login",
        severity: "high",
        title: "Connexion root SSH autorisée",
        detail: "PermitRootLogin vaut « yes » : un attaquant peut viser directement le compte root.",
        recommendation:
          "Dans /etc/ssh/sshd_config : `PermitRootLogin no`, utilisez un compte dédié avec sudo, puis `systemctl reload ssh`.",
      });
    } else if (root === "prohibit-password" || root === "without-password") {
      add({
        category: "ssh",
        checkId: "ssh.root_login_key",
        severity: "low",
        title: "Connexion root SSH par clé autorisée",
        detail: "Root peut se connecter avec une clé. Préférez un compte nominatif.",
        recommendation: "`PermitRootLogin no` et un utilisateur dédié (ex. `AllowUsers deploy`).",
      });
    }
    if (report.ssh.passwordAuthentication === true) {
      add({
        category: "ssh",
        checkId: "ssh.password_auth",
        severity: "high",
        title: "Authentification SSH par mot de passe active",
        detail: "Les mots de passe SSH peuvent être devinés par brute force.",
        recommendation:
          "Déployez une clé (`ssh-copy-id`), puis `PasswordAuthentication no` et `KbdInteractiveAuthentication no`.",
      });
    }
    if (report.ssh.maxAuthTries !== null && report.ssh.maxAuthTries > 3) {
      add({
        category: "ssh",
        checkId: "ssh.max_auth_tries",
        severity: "low",
        title: `MaxAuthTries trop élevé (${report.ssh.maxAuthTries})`,
        detail: "Chaque connexion autorise trop d'essais d'authentification.",
        recommendation: "`MaxAuthTries 3` et `LoginGraceTime 30` dans sshd_config.",
      });
    }
  }

  // ── Firewall (§3.4) ──
  const fw = report.firewall;
  const firewallActive =
    fw.ufw === "active" || (fw.nftablesRules ?? 0) > 0 || (fw.iptablesRules ?? 0) > 0;
  const firewallUnknown =
    fw.ufw === null && fw.nftablesRules === null && fw.iptablesRules === null;
  if (firewallUnknown) {
    add({
      category: "firewall",
      checkId: "firewall.unknown",
      severity: "info",
      title: "État du firewall non vérifiable",
      detail: "L'agent n'a pas pu lire les règles (lancez-le avec sudo).",
      recommendation:
        "Exécutez l'agent en root : `sudo python3 /opt/codegate/codegate-agent.py --token-file /etc/codegate/agent.token`.",
    });
  } else if (!firewallActive) {
    add({
      category: "firewall",
      checkId: "firewall.inactive",
      severity: "high",
      title: "Aucun firewall actif",
      detail: "Tous les ports en écoute sont joignables depuis Internet.",
      recommendation:
        "`ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable`",
    });
  }

  // ── Brute force SSH (§3.3 / §4) ──
  const bf = report.bruteforce;
  if (sshExposed && bf.fail2ban === false && bf.crowdsec === false) {
    add({
      category: "bruteforce",
      checkId: "bruteforce.ssh_unprotected",
      severity: "medium",
      title: "SSH exposé sans protection anti brute force",
      detail: "Ni Fail2ban ni CrowdSec ne sont actifs alors que SSH est joignable.",
      recommendation:
        "`apt install fail2ban` puis activez la jail sshd (maxretry = 3, findtime = 10m, bantime = 1h).",
    });
  }

  // ── Docker (§3.5) ──
  for (const c of report.docker?.containers ?? []) {
    if (c.dockerSocketMounted) {
      add({
        category: "docker",
        checkId: `docker.socket.${c.name}`,
        severity: "critical",
        title: `Socket Docker monté dans « ${c.name} »`,
        detail: "Le conteneur peut piloter Docker, donc prendre le contrôle de l'hôte.",
        recommendation: "Retirez le volume `/var/run/docker.sock`, ou passez par un proxy en lecture seule.",
      });
    }
    if (c.privileged) {
      add({
        category: "docker",
        checkId: `docker.privileged.${c.name}`,
        severity: "critical",
        title: `Conteneur « ${c.name} » en mode privilégié`,
        detail: "--privileged donne un accès quasi complet au noyau de l'hôte.",
        recommendation: "Supprimez `privileged: true` ; n'ajoutez que les capacités strictement nécessaires.",
      });
    }
    const dangerousCaps = c.capAdd.filter((cap) =>
      ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"].includes(cap.replace(/^CAP_/, "")),
    );
    if (dangerousCaps.length) {
      add({
        category: "docker",
        checkId: `docker.caps.${c.name}`,
        severity: "high",
        title: `Capacités Linux sensibles sur « ${c.name} »`,
        detail: `cap_add : ${dangerousCaps.join(", ")}.`,
        recommendation: "Retirez ces capacités et ajoutez `cap_drop: [ALL]` puis seulement le nécessaire.",
      });
    }
    if (c.user === "" || c.user === "root" || c.user === "0" || c.user.startsWith("0:")) {
      add({
        category: "docker",
        checkId: `docker.root.${c.name}`,
        severity: "medium",
        title: `Conteneur « ${c.name} » exécuté en root`,
        detail: "Une faille dans l'application donne root dans le conteneur.",
        recommendation: "Ajoutez `USER app` dans le Dockerfile ou `user: \"1000:1000\"` dans compose.",
      });
    }
    if (c.memoryLimit === 0) {
      add({
        category: "docker",
        checkId: `docker.limits.${c.name}`,
        severity: "low",
        title: `Pas de limite mémoire sur « ${c.name} »`,
        detail: "Un conteneur emballé peut épuiser la RAM de tout le serveur.",
        recommendation: "Définissez `mem_limit` (ou `deploy.resources.limits.memory`) et `pids_limit`.",
      });
    }
  }

  // ── Mises à jour (§3.2 Patch Level) ──
  const up = report.updates;
  if (up.pendingSecurity !== null && up.pendingSecurity > 0) {
    add({
      category: "updates",
      checkId: "updates.security_pending",
      severity: up.pendingSecurity >= 10 ? "high" : "medium",
      title: `${up.pendingSecurity} mise(s) à jour de sécurité en attente`,
      detail: "Des correctifs de sécurité publiés ne sont pas appliqués.",
      recommendation:
        up.manager === "dnf" ? "`dnf upgrade --security`" : "`apt update && apt upgrade`",
    });
  }
  if (up.autoUpdates === false) {
    add({
      category: "updates",
      checkId: "updates.no_auto",
      severity: "low",
      title: "Mises à jour de sécurité automatiques désactivées",
      detail: "Les correctifs critiques dépendent d'une action manuelle.",
      recommendation:
        up.manager === "dnf"
          ? "`dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer`"
          : "`apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`",
    });
  }

  // ── TLS (§3.2 TLS Audit) ──
  for (const t of report.tls ?? []) {
    const where = `port ${t.port}`;
    if (t.certExpiresInDays !== null && t.certExpiresInDays < 30) {
      const expired = t.certExpiresInDays < 0;
      add({
        category: "tls",
        checkId: `tls.cert_expiry.${t.port}`,
        severity: expired ? "critical" : t.certExpiresInDays < 14 ? "high" : "medium",
        title: expired
          ? `Certificat TLS expiré (${where})`
          : `Certificat TLS expirant dans ${t.certExpiresInDays} jour(s) (${where})`,
        detail: expired
          ? "Les navigateurs bloquent le site et les clients API refusent la connexion."
          : "Sans renouvellement, le service deviendra inaccessible en HTTPS.",
        recommendation: "Automatisez le renouvellement : `certbot renew` (timer systemd) ou Caddy / Traefik avec ACME.",
      });
    }
    if (t.selfSigned) {
      add({
        category: "tls",
        checkId: `tls.self_signed.${t.port}`,
        severity: "medium",
        title: `Certificat auto-signé (${where})`,
        detail: "Les clients ne peuvent pas vérifier l'identité du serveur : porte ouverte à l'interception.",
        recommendation: "Utilisez un certificat d'une autorité reconnue (Let's Encrypt gratuit).",
      });
    }
    if (t.protocol && /^TLSv1(\.[01])?$|^SSL/.test(t.protocol)) {
      add({
        category: "tls",
        checkId: `tls.weak_protocol.${t.port}`,
        severity: "high",
        title: `Protocole ${t.protocol} négocié (${where})`,
        detail: "Ce protocole est obsolète et vulnérable.",
        recommendation: "Exigez TLS 1.2 minimum, TLS 1.3 recommandé (`ssl_protocols TLSv1.2 TLSv1.3;` pour nginx).",
      });
    } else if (t.legacyAccepted) {
      add({
        category: "tls",
        checkId: `tls.legacy_accepted.${t.port}`,
        severity: "medium",
        title: `TLS 1.0 / 1.1 encore acceptés (${where})`,
        detail: "Un client peut forcer un protocole obsolète (attaque par rétrogradation).",
        recommendation: "Désactivez TLS 1.0 et 1.1 : `ssl_protocols TLSv1.2 TLSv1.3;` (nginx) ou équivalent.",
      });
    }
  }

  // ── Sauvegardes (Backup Shield §5.3 Backup Discovery) ──
  const dbPorts = new Set([3306, 5432, 27017]);
  const hostsDatabase =
    report.listening.some(
      (l) => dbPorts.has(l.port) || /^(postgres|mysqld|mariadbd|mongod)$/.test(l.process ?? ""),
    ) ||
    (report.docker?.containers ?? []).some((c) => /(^|\/)(postgres|mysql|mariadb|mongo)(:|$)/.test(c.image));
  const backups = report.backups;
  if (backups && hostsDatabase && backups.jobs === 0) {
    add({
      category: "backups",
      checkId: "backups.none",
      severity: "high",
      title: "Base de données sans sauvegarde planifiée",
      detail: "Une base de données tourne sur ce serveur mais aucun cron ni timer de sauvegarde n'a été trouvé.",
      recommendation:
        "Planifiez un dump chiffré et externalisé, puis déclarez-le dans CodeGate (page Sauvegardes) avec `codegate-backup report`.",
    });
  } else if (backups && backups.jobs > 0 && !backups.codegateReporting) {
    add({
      category: "backups",
      checkId: "backups.unmonitored",
      severity: "low",
      title: "Sauvegardes non suivies par CodeGate",
      detail: `Outils détectés : ${backups.tools.join(", ") || "script personnalisé"}. Leur chiffrement, intégrité et restauration ne sont pas vérifiés.`,
      recommendation: "Ajoutez `codegate-backup report --file <archive>` à la fin du job de sauvegarde.",
    });
  }

  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return { score: Math.max(0, 100 - penalty), findings };
}
