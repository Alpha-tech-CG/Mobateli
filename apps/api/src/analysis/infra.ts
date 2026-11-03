import type { AgentReport, Severity } from "@codegate/shared";

/**
 * Infra Shield rules (extension §3): turn the facts reported by the agent into
 * findings with proof, a verification command and a remediation that fits the
 * image, plus attack chains and a 0–100 server security score.
 * Deterministic — the same report always gives the same result.
 *
 * Severity is contextual (exploitability × exposure × blast radius): the same
 * weakness weighs more on a container reachable from the Internet than on an
 * internal one. Known mitigations (read-only socket proxy, images that drop
 * root themselves, trusted certificates behind SNI) are recognised instead of
 * being reported as problems.
 */

export type InfraCategory =
  | "ports"
  | "ssh"
  | "firewall"
  | "bruteforce"
  | "docker"
  | "updates"
  | "backups"
  | "tls"
  | "secrets"
  | "network"
  | "admin"
  | "http"
  | "daemon";

export type Exposure = "public" | "internal";

export interface InfraFinding {
  category: InfraCategory;
  checkId: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  evidence?: string;
  verifyCommand?: string;
  exploitScenario?: string;
  exposure?: Exposure;
}

/** Findings that, combined, open a path to the host (P2-3). */
export interface AttackChain {
  id: string;
  severity: Severity;
  title: string;
  steps: string[];
  checkIds: string[];
}

export interface InfraResult {
  score: number;
  /** All findings, accepted ones included (flagged by the caller). */
  findings: InfraFinding[];
  chains: AttackChain[];
  /** Controls in place that reduce the risk (shown, never penalised). */
  mitigations: string[];
}

export interface InfraOptions {
  /** checkIds accepted as a known risk or covered by a compensating control. */
  accepted?: ReadonlySet<string>;
}

type Container = NonNullable<AgentReport["docker"]>["containers"][number];

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

/**
 * Score weights. The score is continuous — 100 × K / (K + penalty) — so every
 * fix moves it, even on a server with many findings (P0-5).
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1.5, info: 0 };
export const SCORE_K = 60;
const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const maxSeverity = (a: Severity, b: Severity): Severity => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

export function scoreOf(findings: InfraFinding[], accepted: ReadonlySet<string> = new Set()): number {
  const penalty = findings
    .filter((f) => !accepted.has(f.checkId))
    .reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.round((100 * SCORE_K) / (SCORE_K + penalty));
}

/** True when a bind address is reachable beyond the host itself. */
export function isPublicBind(address: string): boolean {
  const a = address.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (a === "127.0.0.1" || a === "::1" || a.startsWith("127.")) return false;
  if (a === "localhost") return false;
  return true; // 0.0.0.0, ::, *, or a concrete interface address
}

/** "ghcr.io/org/app:1.2@sha256:…" → "org/app". */
export function imageName(image: string): string {
  const noDigest = image.split("@")[0] ?? image;
  const parts = noDigest.split("/");
  const last = parts.pop() ?? "";
  const repo = last.split(":")[0] ?? last;
  if (parts.length && /[.:]/.test(parts[0]!) ) parts.shift(); // registry host
  return [...parts, repo].join("/").toLowerCase();
}
const baseName = (image: string) => imageName(image).split("/").pop() ?? "";

const SOCKET_PROXY = /(^|\/)(docker-socket-proxy|socket-proxy|dockerproxy)$/;

/** Official images whose entrypoint drops root before starting the service. */
const DROPS_ROOT: Record<string, string> = {
  postgres: "l'image officielle postgres démarre en root puis exécute le serveur sous l'utilisateur postgres (UID 999)",
  redis: "l'image officielle redis exécute redis-server sous l'utilisateur redis (UID 999)",
  mysql: "l'image officielle mysql exécute mysqld sous l'utilisateur mysql",
  mariadb: "l'image officielle mariadb exécute mariadbd sous l'utilisateur mysql",
  mongo: "l'image officielle mongo exécute mongod sous l'utilisateur mongodb",
  rabbitmq: "l'image officielle rabbitmq exécute le broker sous l'utilisateur rabbitmq",
  elasticsearch: "l'image elasticsearch exécute le moteur sous l'utilisateur elasticsearch",
  gitea: "gitea exécute le serveur sous l'utilisateur git (USER_UID / USER_GID)",
};

/** Image-aware "stop running as root" advice — a wrong one breaks prod (P2-1). */
function rootRemediation(c: Container): string {
  const base = baseName(c.image);
  const name = imageName(c.image);
  if (DROPS_ROOT[base])
    return `Le processus principal tourne pourtant en root : vérifiez que l'entrypoint de l'image n'a pas été remplacé (\`entrypoint:\` ou \`command:\` dans compose), et ne forcez pas \`user:\` — ${DROPS_ROOT[base]} et les volumes existants lui appartiennent.`;
  if (base === "gitea")
    return "Utilisez l'image `gitea/gitea:<version>-rootless`, ou fixez `USER_UID` / `USER_GID` dans l'environnement, sans `user:` qui casserait les permissions du volume /data.";
  if (base === "nginx")
    return "Passez à `nginxinc/nginx-unprivileged` (port 8080 dans le conteneur) au lieu d'ajouter `user:`, qui empêche nginx d'écrire son PID et son cache.";
  if (base === "node" || name.endsWith("/node"))
    return "L'image node fournit l'utilisateur `node` (UID 1000) : `USER node` dans le Dockerfile après `chown -R node:node /app`.";
  if (base === "traefik")
    return "Faites tourner Traefik sous un UID dédié (`user: \"65532:65532\"`) en lui donnant accès au socket via un proxy, et en publiant 80/443 avec la capacité `NET_BIND_SERVICE` seule.";
  return "Ajoutez un utilisateur dédié dans l'image (`USER app`) ou `user: \"<uid>:<gid>\"` dans compose — en changeant d'abord le propriétaire des volumes (`chown -R <uid>:<gid> <volume>`) pour ne pas casser l'écriture des données. Testez sur un environnement de préproduction.";
}

/** Host paths whose mount gives (read or write) access to the host. */
const SENSITIVE_MOUNTS: Record<string, { rw: Severity; ro: Severity; what: string }> = {
  "/": { rw: "critical", ro: "high", what: "tout le système de fichiers de l'hôte" },
  "/etc": { rw: "critical", ro: "high", what: "la configuration de l'hôte (comptes, sudoers, cron)" },
  "/root": { rw: "critical", ro: "high", what: "le dossier de root (clés SSH)" },
  "/var/lib/docker": { rw: "critical", ro: "high", what: "les données de tous les conteneurs, volumes et secrets compris" },
  "/boot": { rw: "critical", ro: "medium", what: "le noyau et le chargeur de démarrage" },
  "/proc": { rw: "high", ro: "medium", what: "les processus de l'hôte" },
  "/sys": { rw: "high", ro: "medium", what: "le noyau de l'hôte (/sys)" },
  "/dev": { rw: "high", ro: "medium", what: "les périphériques de l'hôte, disques compris" },
  "/etc/shadow": { rw: "critical", ro: "high", what: "les empreintes des mots de passe" },
  "/etc/ssh": { rw: "critical", ro: "high", what: "les clés et la configuration SSH" },
  "/root/.ssh": { rw: "critical", ro: "high", what: "les clés SSH de root" },
  "/etc/sudoers": { rw: "critical", ro: "medium", what: "les droits sudo" },
};

const CRITICAL_CAPS = ["ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH"];
const HIGH_CAPS = ["NET_ADMIN", "SYS_PTRACE", "BPF", "SYS_BOOT"];

/** Admin consoles; builtinAuth = the tool has its own login (P1-3). */
const ADMIN_TOOLS: { match: RegExp; label: string; builtinAuth: boolean }[] = [
  { match: /(^|\/)cadvisor$/, label: "cAdvisor", builtinAuth: false },
  { match: /(^|\/)prometheus$/, label: "Prometheus", builtinAuth: false },
  { match: /(^|\/)alertmanager$/, label: "Alertmanager", builtinAuth: false },
  { match: /(^|\/)node-exporter$/, label: "Node exporter", builtinAuth: false },
  { match: /(^|\/)dozzle$/, label: "Dozzle (logs)", builtinAuth: false },
  { match: /(^|\/)netdata$/, label: "Netdata", builtinAuth: false },
  { match: /(^|\/)adminer$/, label: "Adminer", builtinAuth: false },
  { match: /(^|\/)traefik$/, label: "Tableau de bord Traefik", builtinAuth: false },
  { match: /(^|\/)(kibana|opensearch-dashboards)$/, label: "Kibana", builtinAuth: false },
  { match: /(^|\/)grafana(-oss|-enterprise)?$/, label: "Grafana", builtinAuth: true },
  { match: /(^|\/)portainer(-ce|-ee)?$/, label: "Portainer", builtinAuth: true },
  { match: /(^|\/)minio$/, label: "MinIO", builtinAuth: true },
  { match: /(^|\/)pgadmin4?$/, label: "pgAdmin", builtinAuth: true },
  { match: /(^|\/)phpmyadmin$/, label: "phpMyAdmin", builtinAuth: true },
  { match: /(^|\/)jenkins$/, label: "Jenkins", builtinAuth: true },
  { match: /(^|\/)uptime-kuma$/, label: "Uptime Kuma", builtinAuth: true },
  { match: /(^|\/)rabbitmq$/, label: "RabbitMQ", builtinAuth: true },
];

function sshPortsOf(report: AgentReport): number[] {
  return report.listening
    .filter((l) => l.proto === "tcp" && (l.process === "sshd" || l.port === 22))
    .map((l) => l.port);
}

function containerExposure(c: Container): { exposure: Exposure; where: string[] } {
  const where: string[] = [];
  for (const p of c.publishedPorts) if (isPublicBind(p.hostIp || "0.0.0.0")) where.push(`port ${p.hostPort}`);
  for (const h of c.routedHosts ?? []) where.push(h);
  return { exposure: where.length ? "public" : "internal", where };
}

const socketMounts = (c: Container) =>
  (c.mounts ?? []).filter((m) => m.source.endsWith("docker.sock") || m.destination.endsWith("docker.sock"));
const mountsSocket = (c: Container) => c.dockerSocketMounted || socketMounts(c).length > 0;

export function evaluateInfra(report: AgentReport, options: InfraOptions = {}): InfraResult {
  const findings: InfraFinding[] = [];
  const mitigations: string[] = [];
  const add = (f: InfraFinding) => findings.push(f);
  const containers = report.docker?.containers ?? [];
  const exposureOf = new Map(containers.map((c) => [c.name, containerExposure(c)]));
  const fw = report.firewall;
  const ufwActive = fw.ufw === "active";
  const ufwAllowed = fw.ufwAllowed ? new Set(fw.ufwAllowed) : null;

  // ── Ports & services exposed (host sockets + Docker published ports) ──
  const exposed = new Map<number, string>(); // port -> where
  const dockerPublished = new Map<number, string>();
  for (const l of report.listening) {
    if (l.proto === "tcp" && isPublicBind(l.address)) {
      exposed.set(l.port, l.process ? `processus ${l.process}` : "processus inconnu");
    }
  }
  for (const c of containers) {
    for (const p of c.publishedPorts) {
      if (isPublicBind(p.hostIp || "0.0.0.0")) {
        exposed.set(p.hostPort, `conteneur ${c.name}`);
        dockerPublished.set(p.hostPort, c.name);
      }
    }
  }
  for (const [port, where] of [...exposed].sort((a, b) => a[0] - b[0])) {
    const known = DANGEROUS_PORTS[port];
    if (!known) continue;
    add({
      category: "ports",
      checkId: `port.public.${port}`,
      severity: known.severity,
      exposure: "public",
      title: `${known.service} exposé publiquement (port ${port})`,
      detail: `Le port ${port} écoute sur toutes les interfaces (${where}). Risque : ${known.risk}.${
        dockerPublished.has(port) && ufwActive ? " Docker publie ce port en contournant UFW : la règle du firewall ne le protège pas." : ""
      }`,
      evidence: `${where} — 0.0.0.0:${port}`,
      verifyCommand: `ss -tlnp 'sport = :${port}'`,
      recommendation:
        `Liez le service à 127.0.0.1 ou à un réseau privé, et fermez le port : \`ufw deny ${port}/tcp\`. ` +
        `Pour Docker, publiez \`127.0.0.1:${port}:${port}\` au lieu de \`${port}:${port}\` (Docker contourne UFW).`,
    });
  }

  // ── Ports published by Docker that UFW believes closed (P1-5) ──
  if (ufwActive && ufwAllowed) {
    for (const [port, name] of [...dockerPublished].sort((a, b) => a[0] - b[0])) {
      if (DANGEROUS_PORTS[port] || ufwAllowed.has(port)) continue;
      add({
        category: "firewall",
        checkId: `firewall.docker_bypass.${port}`,
        severity: "medium",
        exposure: "public",
        title: `Port ${port} publié par Docker malgré UFW`,
        detail: `UFW n'autorise pas le port ${port}, mais le conteneur « ${name} » le publie sur toutes les interfaces : Docker insère ses propres règles iptables avant celles d'UFW, le port est donc joignable depuis Internet.`,
        evidence: `ufw : ${[...ufwAllowed].sort((a, b) => a - b).join(", ") || "aucun port"} autorisé(s) · ${name} publie 0.0.0.0:${port}`,
        verifyCommand: `sudo iptables -L DOCKER -n | grep ${port}`,
        recommendation: `Publiez le port sur 127.0.0.1 (\`127.0.0.1:${port}:…\`) derrière le reverse proxy, ou s'il doit être public, autorisez-le explicitement (\`ufw allow ${port}/tcp\`) pour que la politique reflète la réalité.`,
      });
    }
  }

  // ── SSH (§3.3) ──
  const sshExposed = sshPortsOf(report).some((p) => exposed.has(p));
  if (report.ssh) {
    const root = report.ssh.permitRootLogin?.toLowerCase() ?? null;
    if (root === "yes") {
      add({
        category: "ssh",
        checkId: "ssh.root_login",
        severity: sshExposed ? "high" : "medium",
        exposure: sshExposed ? "public" : "internal",
        title: "Connexion root SSH autorisée",
        detail: "PermitRootLogin vaut « yes » : un attaquant peut viser directement le compte root.",
        evidence: "sshd -T : permitrootlogin yes",
        verifyCommand: "sudo sshd -T | grep -i permitrootlogin",
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
        evidence: `sshd -T : permitrootlogin ${root}`,
        verifyCommand: "sudo sshd -T | grep -i permitrootlogin",
        recommendation: "`PermitRootLogin no` et un utilisateur dédié (ex. `AllowUsers deploy`).",
      });
    }
    if (report.ssh.passwordAuthentication === true) {
      add({
        category: "ssh",
        checkId: "ssh.password_auth",
        severity: sshExposed ? "high" : "medium",
        exposure: sshExposed ? "public" : "internal",
        title: "Authentification SSH par mot de passe active",
        detail: "Les mots de passe SSH peuvent être devinés par brute force.",
        evidence: "sshd -T : passwordauthentication yes",
        verifyCommand: "sudo sshd -T | grep -i passwordauthentication",
        exploitScenario: "Un robot essaie des milliers de mots de passe par heure sur le port SSH jusqu'à en trouver un valide.",
        recommendation:
          "Déployez une clé (`ssh-copy-id`), puis `PasswordAuthentication no` et `KbdInteractiveAuthentication no`.",
      });
    } else if (report.ssh.passwordAuthentication === false) {
      mitigations.push("SSH n'accepte que les clés (mot de passe désactivé).");
    }
    if (report.ssh.maxAuthTries !== null && report.ssh.maxAuthTries > 3) {
      add({
        category: "ssh",
        checkId: "ssh.max_auth_tries",
        severity: "low",
        title: `MaxAuthTries trop élevé (${report.ssh.maxAuthTries})`,
        detail: "Chaque connexion autorise trop d'essais d'authentification.",
        evidence: `sshd -T : maxauthtries ${report.ssh.maxAuthTries}`,
        verifyCommand: "sudo sshd -T | grep -i maxauthtries",
        recommendation: "`MaxAuthTries 3` et `LoginGraceTime 30` dans sshd_config.",
      });
    }
  }

  // ── Firewall (§3.4) ──
  const firewallActive = ufwActive || (fw.nftablesRules ?? 0) > 0 || (fw.iptablesRules ?? 0) > 0;
  const firewallUnknown = fw.ufw === null && fw.nftablesRules === null && fw.iptablesRules === null;
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
      exposure: "public",
      title: "Aucun firewall actif",
      detail: "Tous les ports en écoute sont joignables depuis Internet.",
      verifyCommand: "sudo ufw status verbose",
      recommendation:
        "`ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable`",
    });
  } else {
    mitigations.push(ufwActive ? "Firewall UFW actif." : "Règles de firewall en place (nftables / iptables).");
  }

  // ── Brute force SSH (§3.3 / §4) ──
  const bf = report.bruteforce;
  if (sshExposed && bf.fail2ban === false && bf.crowdsec === false) {
    add({
      category: "bruteforce",
      checkId: "bruteforce.ssh_unprotected",
      severity: report.ssh?.passwordAuthentication === false ? "low" : "medium",
      exposure: "public",
      title: "SSH exposé sans protection anti brute force",
      detail:
        report.ssh?.passwordAuthentication === false
          ? "Ni Fail2ban ni CrowdSec ne sont actifs. Le risque est réduit car SSH n'accepte que les clés, mais les tentatives saturent les journaux."
          : "Ni Fail2ban ni CrowdSec ne sont actifs alors que SSH est joignable.",
      verifyCommand: "systemctl is-active fail2ban crowdsec",
      recommendation:
        "`apt install fail2ban` puis activez la jail sshd (maxretry = 3, findtime = 10m, bantime = 1h).",
    });
  } else if (bf.fail2ban || bf.crowdsec) {
    mitigations.push(`${bf.fail2ban ? "Fail2ban" : "CrowdSec"} actif contre le brute force.`);
  }

  // ── Docker (§3.5) ──
  const escapes = new Map<string, string>(); // container -> how it reaches the host
  for (const c of containers) {
    const { exposure, where } = exposureOf.get(c.name)!;
    const pub = exposure === "public";
    const exposedText = pub ? ` Il est joignable depuis Internet (${where.join(", ")}).` : "";
    const inspectMounts = `docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} rw={{.RW}}{{"\\n"}}{{end}}' ${c.name}`;

    // Docker socket: direct mount, or a socket proxy (the mitigation, P0-3).
    if (mountsSocket(c)) {
      const isProxy = SOCKET_PROXY.test(imageName(c.image));
      const sock = socketMounts(c);
      const ro = sock.length > 0 && sock.every((m) => !m.rw);
      const evidence = sock.length
        ? sock.map((m) => `${m.source} -> ${m.destination} (${m.rw ? "rw" : "ro"})`).join(" ; ")
        : "/var/run/docker.sock monté";
      if (isProxy && c.socketProxyPost !== true) {
        mitigations.push(
          `« ${c.name} » expose le socket Docker en lecture seule via ${imageName(c.image)} (écriture désactivée) : les autres services passent par ce proxy au lieu du socket.`,
        );
        if (pub) {
          add({
            category: "docker",
            checkId: `docker.socket_proxy_public.${c.name}`,
            severity: "high",
            exposure,
            title: `Proxy du socket Docker « ${c.name} » joignable depuis Internet`,
            detail: `Même en lecture seule, l'API Docker révèle la configuration et les variables d'environnement de tous les conteneurs.${exposedText}`,
            evidence: where.join(", "),
            verifyCommand: `docker port ${c.name}`,
            recommendation: "Ne publiez aucun port du proxy : placez-le sur un réseau Docker interne (`internal: true`) partagé seulement avec ses clients.",
          });
        }
      } else if (isProxy) {
        escapes.set(c.name, "proxy du socket Docker autorisant l'écriture");
        add({
          category: "docker",
          checkId: `docker.socket_proxy_write.${c.name}`,
          severity: "high",
          exposure,
          title: `Proxy du socket Docker « ${c.name} » autorisant l'écriture`,
          detail: "POST=1 : les clients du proxy peuvent créer des conteneurs, donc un conteneur privilégié qui monte l'hôte.",
          evidence: `${imageName(c.image)} · POST=1`,
          verifyCommand: `docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' ${c.name} | grep -E '^(POST|EXEC|CONTAINERS)='`,
          recommendation: "Mettez `POST=0` et n'activez que les sections nécessaires en lecture (`CONTAINERS=1`, `NETWORKS=1`…).",
        });
      } else {
        escapes.set(c.name, "socket Docker monté");
        add({
          category: "docker",
          checkId: `docker.socket.${c.name}`,
          severity: "critical",
          exposure,
          title: `Socket Docker monté dans « ${c.name} »`,
          detail: `Le conteneur peut piloter Docker, donc prendre le contrôle de l'hôte.${
            ro
              ? " Le montage est en lecture seule (:ro), mais cela ne protège pas : « :ro » empêche seulement de remplacer le fichier socket, le démon exécute quand même toutes les requêtes de l'API, y compris la création de conteneurs."
              : ""
          }${exposedText}`,
          evidence,
          verifyCommand: inspectMounts,
          exploitScenario:
            "Depuis le conteneur : `docker run --privileged -v /:/host alpine chroot /host` donne un shell root sur le serveur.",
          recommendation:
            "Retirez le volume `/var/run/docker.sock` et passez par un proxy en lecture seule : `tecnativa/docker-socket-proxy` avec `CONTAINERS=1` et `POST=0`, sur un réseau interne, puis `DOCKER_HOST=tcp://socket-proxy:2375` dans le service client.",
        });
      }
    }

    // Host paths mounted (P0-1).
    const sensitive = (c.mounts ?? [])
      .map((m) => ({ m, rule: SENSITIVE_MOUNTS[m.source.replace(/\/+$/, "") || "/"] }))
      .filter((x): x is { m: { source: string; destination: string; rw: boolean }; rule: (typeof SENSITIVE_MOUNTS)[string] } => !!x.rule);
    const mountEvidence = sensitive.map(({ m }) => `${m.source} -> ${m.destination} (${m.rw ? "rw" : "ro"})`).join(" ; ");

    if (c.privileged) {
      escapes.set(c.name, "mode privilégié");
      const isCadvisor = baseName(c.image) === "cadvisor";
      add({
        category: "docker",
        checkId: `docker.privileged.${c.name}`,
        severity: "critical",
        exposure,
        title: `Conteneur « ${c.name} » en mode privilégié`,
        detail: `--privileged donne tous les périphériques et toutes les capacités du noyau : sortir du conteneur vers l'hôte est trivial.${
          sensitive.length ? ` Il monte aussi ${sensitive.map((s) => s.rule.what).join(", ")}.` : ""
        }${exposedText}`,
        evidence: `HostConfig.Privileged = true${mountEvidence ? ` ; ${mountEvidence}` : ""}`,
        verifyCommand: `docker inspect -f 'privileged={{.HostConfig.Privileged}}' ${c.name} && ${inspectMounts}`,
        exploitScenario:
          "Une faille dans le service donne un shell dans le conteneur ; `mount /dev/sda1 /mnt` (ou le chemin hôte déjà monté) donne alors l'accès root au serveur.",
        recommendation: isCadvisor
          ? "cAdvisor fonctionne sans `privileged` : retirez-le, montez seulement `/:/rootfs:ro`, `/var/run:/var/run:ro`, `/sys:/sys:ro`, `/var/lib/docker:/var/lib/docker:ro` et ajoutez `devices: [/dev/kmsg]`. Ne publiez pas son port : exposez-le à Prometheus sur un réseau interne."
          : "Supprimez `privileged: true` ; n'ajoutez que les capacités strictement nécessaires (`cap_drop: [ALL]` puis `cap_add` ciblé) et les périphériques précis (`devices:`).",
      });
    } else if (sensitive.length) {
      const sev = sensitive.reduce<Severity>((acc, { m, rule }) => maxSeverity(acc, m.rw ? rule.rw : rule.ro), "info");
      if (SEV_RANK[sev] >= SEV_RANK.high) escapes.set(c.name, `montage de ${sensitive[0]!.m.source}`);
      add({
        category: "docker",
        checkId: `docker.host_mount.${c.name}`,
        severity: sev,
        exposure,
        title: `Chemins sensibles de l'hôte montés dans « ${c.name} »`,
        detail: `Le conteneur accède à ${sensitive.map((s) => s.rule.what).join(", ")}.${
          sensitive.some((s) => !s.m.rw) ? " Même en lecture seule, il peut lire des secrets de l'hôte (empreintes de mots de passe, clés, données des autres conteneurs)." : ""
        }${exposedText}`,
        evidence: mountEvidence,
        verifyCommand: inspectMounts,
        recommendation:
          "Ne montez que le sous-dossier précis dont le service a besoin, en lecture seule (`:ro`), et jamais `/`, `/etc`, `/root` ou `/var/lib/docker`.",
      });
    }

    // Capabilities.
    const caps = c.capAdd.map((cap) => cap.replace(/^CAP_/, "").toUpperCase());
    const critCaps = caps.filter((cap) => CRITICAL_CAPS.includes(cap));
    const highCaps = caps.filter((cap) => HIGH_CAPS.includes(cap));
    if (!c.privileged && (critCaps.length || highCaps.length)) {
      if (critCaps.length) escapes.set(c.name, `capacité ${critCaps.join(", ")}`);
      add({
        category: "docker",
        checkId: `docker.caps.${c.name}`,
        severity: critCaps.length ? "critical" : "high",
        exposure,
        title: `Capacités Linux sensibles sur « ${c.name} »`,
        detail: critCaps.length
          ? `${critCaps.join(", ")} permet de sortir du conteneur (montages, modules noyau, accès disque brut).${exposedText}`
          : `${highCaps.join(", ")} permet d'espionner ou de reconfigurer le réseau et les processus de l'hôte.${exposedText}`,
        evidence: `cap_add : ${[...critCaps, ...highCaps].join(", ")}`,
        verifyCommand: `docker inspect -f '{{.HostConfig.CapAdd}}' ${c.name}`,
        recommendation: "Retirez ces capacités et ajoutez `cap_drop: [ALL]` puis seulement le nécessaire.",
      });
    }

    // Root: judge the UID the main process really runs as (P0-4).
    const declaredRoot = c.user === "" || c.user === "root" || c.user === "0" || c.user.startsWith("0:") || c.user.startsWith("root:");
    const base = baseName(c.image);
    let runsAsRoot: boolean;
    let rootEvidence: string;
    if (c.effectiveUid !== undefined && c.effectiveUid !== null) {
      runsAsRoot = c.effectiveUid === 0;
      rootEvidence = `UID effectif du processus principal : ${c.effectiveUid}`;
    } else {
      runsAsRoot = declaredRoot && !DROPS_ROOT[base];
      rootEvidence = `Config.User = « ${c.user || "(vide)"} » (UID effectif non mesuré : agent < 2.0)`;
    }
    if (runsAsRoot && !c.privileged) {
      add({
        category: "docker",
        checkId: `docker.root.${c.name}`,
        severity: pub ? "medium" : "low",
        exposure,
        title: `Conteneur « ${c.name} » exécuté en root`,
        detail: `Une faille dans l'application donne root dans le conteneur, ce qui facilite la sortie vers l'hôte.${
          pub ? exposedText : " Il n'est pas exposé à Internet, ce qui réduit le risque."
        }`,
        evidence: rootEvidence,
        verifyCommand: `docker top ${c.name} -eo uid,user,comm | head -3`,
        recommendation: rootRemediation(c),
      });
    } else if (declaredRoot && !runsAsRoot) {
      mitigations.push(
        c.effectiveUid !== undefined && c.effectiveUid !== null
          ? `« ${c.name} » démarre en root mais son processus principal tourne sous l'UID ${c.effectiveUid} : l'image abandonne root au démarrage.`
          : `« ${c.name} » : ${DROPS_ROOT[base]} (à confirmer avec l'agent ≥ 2.0, qui mesure l'UID effectif).`,
      );
    }

    // Network isolation (P1-2).
    if (c.networkMode === "host") {
      add({
        category: "network",
        checkId: `network.host_mode.${c.name}`,
        severity: ADMIN_TOOLS.some((t) => t.match.test(imageName(c.image))) || base === "node-exporter" ? "medium" : "high",
        exposure: "public",
        title: `« ${c.name} » partage le réseau de l'hôte`,
        detail: "`network_mode: host` supprime l'isolation réseau : le conteneur écoute directement sur les interfaces du serveur et joint tous les services internes, y compris ceux liés à 127.0.0.1.",
        evidence: "HostConfig.NetworkMode = host",
        verifyCommand: `docker inspect -f '{{.HostConfig.NetworkMode}}' ${c.name}`,
        recommendation: "Placez le conteneur sur un réseau Docker dédié et publiez seulement le port nécessaire, sur 127.0.0.1 si un reverse proxy le sert.",
      });
    }

    // Admin consoles reachable from the Internet (P1-3).
    const admin = ADMIN_TOOLS.find((t) => t.match.test(imageName(c.image)));
    if (c.routeAuth === "broken") {
      add({
        category: "admin",
        checkId: `admin.auth_broken.${c.name}`,
        severity: "high",
        exposure,
        title: `Protection d'accès cassée sur « ${c.name} »`,
        detail: "Un middleware d'authentification (basicAuth) protège la route, mais son fichier d'utilisateurs est absent : selon la version du proxy, la route renvoie une erreur ou s'ouvre sans contrôle.",
        evidence: `${where.join(", ") || c.name} · usersFile introuvable sur l'hôte`,
        verifyCommand: `docker inspect -f '{{range $k, $v := .Config.Labels}}{{println $k "=" $v}}{{end}}' ${c.name} | grep -i basicauth`,
        recommendation: "Créez le fichier (`htpasswd -nB admin > /chemin/.htpasswd`), montez-le dans le proxy, ou remplacez basicAuth par une authentification centralisée (forwardAuth / SSO).",
      });
    } else if (admin && pub && c.routeAuth !== "ok") {
      add({
        category: "admin",
        checkId: `admin.exposed.${c.name}`,
        severity: admin.builtinAuth ? "low" : "high",
        exposure,
        title: `${admin.label} joignable depuis Internet${admin.builtinAuth ? "" : " sans authentification"}`,
        detail: admin.builtinAuth
          ? `${admin.label} a son propre écran de connexion, mais une console d'administration exposée attire le brute force et les failles connues.`
          : `${admin.label} n'a pas d'authentification : n'importe qui peut consulter les métriques, journaux ou configurations, qui révèlent l'architecture et parfois des secrets.`,
        evidence: where.join(", "),
        verifyCommand: `curl -sI https://${(c.routedHosts ?? [])[0] ?? "<hôte>"}/ | head -1`,
        recommendation: admin.builtinAuth
          ? "Restreignez l'accès (VPN, liste d'IP ou forwardAuth/SSO), activez la double authentification et changez le compte par défaut."
          : "Retirez la publication publique, ou ajoutez un middleware d'authentification (basicAuth avec fichier d'utilisateurs, forwardAuth/SSO) et une liste d'IP autorisées.",
      });
    }

    // Secrets at rest in the environment (P1-4) — names only, never values.
    const secretNames = c.secretEnvNames ?? [];
    if (secretNames.length) {
      add({
        category: "secrets",
        checkId: `secrets.env.${c.name}`,
        severity: "medium",
        exposure,
        title: `Secrets en clair dans l'environnement de « ${c.name} »`,
        detail: `${secretNames.length} variable(s) contiennent un secret en clair : il est lisible par \`docker inspect\`, dans les journaux de crash et par tout processus du conteneur.`,
        evidence: secretNames.slice(0, 15).join(", "),
        verifyCommand: `docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' ${c.name} | cut -d= -f1`,
        recommendation:
          "Passez par des secrets Docker montés en fichier (`secrets:` dans compose) et les variantes `_FILE` des images (ex. `POSTGRES_PASSWORD_FILE=/run/secrets/db_password`), ou un gestionnaire de secrets.",
      });
    }

    if (c.memoryLimit === 0) {
      add({
        category: "docker",
        checkId: `docker.limits.${c.name}`,
        severity: "low",
        exposure,
        title: `Pas de limite mémoire sur « ${c.name} »`,
        detail: "Un conteneur emballé peut épuiser la RAM de tout le serveur.",
        verifyCommand: `docker inspect -f '{{.HostConfig.Memory}}' ${c.name}`,
        recommendation: "Définissez `mem_limit` (ou `deploy.resources.limits.memory`) et `pids_limit`.",
      });
    }
  }

  // .env files readable by every local user (P1-4).
  for (const f of report.docker?.envFiles ?? []) {
    if (!f.worldReadable) continue;
    add({
      category: "secrets",
      checkId: `secrets.env_file.${f.path}`,
      severity: "medium",
      title: `Fichier de secrets lisible par tous : ${f.path}`,
      detail: "Tout utilisateur ou processus du serveur peut lire ce fichier, qui contient généralement les mots de passe des services.",
      evidence: `${f.path} · permissions ${f.mode}`,
      verifyCommand: `stat -c '%a %U:%G %n' ${f.path}`,
      recommendation: `\`chmod 600 ${f.path}\` et propriétaire root (ou l'utilisateur qui lance compose).`,
    });
  }

  // Docker daemon hardening (P1-7).
  const daemon = report.docker?.daemon;
  if (daemon) {
    const missing: string[] = [];
    if (!daemon.logMaxSize) missing.push("limite de taille des journaux (`log-opts.max-size`)");
    if (!daemon.liveRestore) missing.push("`live-restore`");
    if (!daemon.noNewPrivileges) missing.push("`no-new-privileges` par défaut");
    if (!daemon.usernsRemap) missing.push("`userns-remap`");
    if (missing.length) {
      add({
        category: "daemon",
        checkId: "daemon.hardening",
        severity: !daemon.logMaxSize ? "medium" : "low",
        title: "Démon Docker non durci",
        detail: `Réglages absents de /etc/docker/daemon.json : ${missing.join(", ")}.${
          !daemon.logMaxSize ? " Sans limite, les journaux d'un conteneur bavard peuvent remplir le disque et arrêter le serveur." : ""
        }`,
        evidence: "/etc/docker/daemon.json",
        verifyCommand: "cat /etc/docker/daemon.json",
        recommendation:
          '`{"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}, "live-restore": true, "no-new-privileges": true}` dans /etc/docker/daemon.json puis `systemctl restart docker`. `userns-remap` est plus intrusif : testez-le d\'abord, il change les propriétaires des volumes.',
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
      verifyCommand: up.manager === "dnf" ? "dnf updateinfo list --security" : "apt list --upgradable 2>/dev/null | grep -i security",
      recommendation: up.manager === "dnf" ? "`dnf upgrade --security`" : "`apt update && apt upgrade`",
    });
  }
  if (up.autoUpdates === false) {
    add({
      category: "updates",
      checkId: "updates.no_auto",
      severity: "low",
      title: "Mises à jour de sécurité automatiques désactivées",
      detail: "Les correctifs critiques dépendent d'une action manuelle.",
      verifyCommand: up.manager === "dnf" ? "systemctl is-enabled dnf-automatic.timer" : "cat /etc/apt/apt.conf.d/20auto-upgrades",
      recommendation:
        up.manager === "dnf"
          ? "`dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer`"
          : "`apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`",
    });
  } else if (up.autoUpdates === true && up.autoUpdatesLastRunDays != null && up.autoUpdatesLastRunDays > 7) {
    add({
      category: "updates",
      checkId: "updates.auto_stale",
      severity: "medium",
      title: `Mises à jour automatiques activées mais inactives depuis ${up.autoUpdatesLastRunDays} jours`,
      detail: "unattended-upgrades est configuré mais ne s'est pas exécuté récemment : les correctifs ne sont plus appliqués.",
      evidence: `/var/lib/apt/periodic/unattended-upgrades-stamp : ${up.autoUpdatesLastRunDays} jour(s)`,
      verifyCommand: "systemctl status apt-daily-upgrade.timer && tail -n 20 /var/log/unattended-upgrades/unattended-upgrades.log",
      recommendation: "`systemctl enable --now apt-daily.timer apt-daily-upgrade.timer`, puis `unattended-upgrade --dry-run --debug` pour voir ce qui bloque.",
    });
  } else if (up.autoUpdates === true) {
    mitigations.push("Mises à jour de sécurité automatiques actives.");
  }

  // Host accounts (P1-7).
  const host = report.host;
  const extraRoot = (host?.uid0Accounts ?? []).filter((n) => n !== "root");
  if (extraRoot.length) {
    add({
      category: "ssh",
      checkId: "host.uid0_accounts",
      severity: "critical",
      title: `Compte(s) avec l'UID 0 en plus de root : ${extraRoot.join(", ")}`,
      detail: "Ces comptes ont tous les droits de root sous un autre nom : c'est une porte dérobée classique après une intrusion.",
      evidence: `/etc/passwd : ${extraRoot.map((n) => `${n}:x:0`).join(", ")}`,
      verifyCommand: "awk -F: '$3 == 0 {print $1}' /etc/passwd",
      exploitScenario: "Un attaquant qui a eu root ajoute un compte UID 0 discret pour revenir plus tard.",
      recommendation: "Vérifiez l'origine de ces comptes ; s'ils ne sont pas légitimes, considérez le serveur comme compromis (réinstallation), sinon donnez-leur un UID normal et sudo.",
    });
  }
  const nopasswd = host?.passwordlessSudo ?? [];
  if (nopasswd.length) {
    add({
      category: "ssh",
      checkId: "host.sudo_nopasswd",
      severity: "medium",
      title: `sudo sans mot de passe pour ${nopasswd.join(", ")}`,
      detail: "Quiconque prend la main sur ce compte (clé SSH volée, faille applicative) devient root sans autre barrière.",
      evidence: `sudoers : ${nopasswd.map((p) => `${p} ALL=(ALL) NOPASSWD: ALL`).join(" ; ")}`,
      verifyCommand: "sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/",
      recommendation: "Exigez le mot de passe (`%sudo ALL=(ALL:ALL) ALL`), ou limitez NOPASSWD à des commandes précises, comme le fait la règle de l'agent CodeGate.",
    });
  }

  // ── TLS (§3.2 TLS Audit), judged per hostname with SNI (P0-2) ──
  const tls = report.tls ?? [];
  const portsWithSni = new Set(tls.filter((t) => t.sni).map((t) => t.port));
  const weakDone = new Set<number>();
  for (const t of tls) {
    const host = t.sni ?? null;
    if (!host && portsWithSni.has(t.port)) continue; // default certificate: the per-host probes decide
    const where = host ? `${host}, port ${t.port}` : `port ${t.port}, sans nom d'hôte`;
    const key = host ? `${t.port}.${host}` : String(t.port);
    const verify = `openssl s_client -connect 127.0.0.1:${t.port} ${host ? `-servername ${host} ` : ""}</dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate`;

    if (t.certExpiresInDays !== null && t.certExpiresInDays < 30) {
      const expired = t.certExpiresInDays < 0;
      add({
        category: "tls",
        checkId: `tls.cert_expiry.${key}`,
        severity: !host ? "low" : expired ? "critical" : t.certExpiresInDays < 14 ? "high" : "medium",
        exposure: "public",
        title: expired ? `Certificat TLS expiré (${where})` : `Certificat TLS expirant dans ${t.certExpiresInDays} jour(s) (${where})`,
        detail: expired
          ? "Les navigateurs bloquent le site et les clients API refusent la connexion."
          : "Sans renouvellement, le service deviendra inaccessible en HTTPS.",
        evidence: `${t.issuer ? `émetteur ${t.issuer} · ` : ""}expire dans ${t.certExpiresInDays} jour(s)`,
        verifyCommand: verify,
        recommendation: "Automatisez le renouvellement : `certbot renew` (timer systemd) ou Caddy / Traefik avec ACME.",
      });
    }
    if (host && t.trusted === false) {
      add({
        category: "tls",
        checkId: `tls.untrusted.${key}`,
        severity: "medium",
        exposure: "public",
        title: t.selfSigned ? `Certificat auto-signé pour ${host}` : `Certificat non reconnu pour ${host}`,
        detail: t.selfSigned
          ? "Le certificat servi pour ce nom n'est signé par aucune autorité : les clients ne peuvent pas vérifier l'identité du serveur."
          : "La chaîne de certificats est incomplète ou ne correspond pas à ce nom : les clients stricts refusent la connexion.",
        evidence: `SNI ${host} · émetteur ${t.issuer ?? "inconnu"}`,
        verifyCommand: verify,
        recommendation: "Utilisez un certificat d'une autorité reconnue (Let's Encrypt gratuit) et servez la chaîne complète (fullchain).",
      });
    } else if (host && t.trusted === true) {
      mitigations.push(`Certificat valide pour ${host}${t.issuer ? ` (${t.issuer})` : ""}.`);
    } else if (!host && t.selfSigned) {
      add({
        category: "tls",
        checkId: `tls.default_cert.${t.port}`,
        severity: "info",
        title: `Certificat par défaut auto-signé (port ${t.port})`,
        detail:
          "Sans nom d'hôte (SNI), le reverse proxy présente son certificat par défaut : ce n'est pas celui que voient vos visiteurs. Aucun nom de domaine n'a été trouvé pour vérifier les vrais certificats.",
        verifyCommand: `openssl s_client -connect 127.0.0.1:${t.port} -servername <votre-domaine> </dev/null`,
        recommendation: "Mettez à jour l'agent (≥ 2.0) : il lit les domaines configurés (Traefik, nginx, Caddy) et vérifie le certificat servi pour chacun.",
      });
    }
    if (!weakDone.has(t.port)) {
      if (t.protocol && /^TLSv1(\.[01])?$|^SSL/.test(t.protocol)) {
        weakDone.add(t.port);
        add({
          category: "tls",
          checkId: `tls.weak_protocol.${t.port}`,
          severity: "high",
          exposure: "public",
          title: `Protocole ${t.protocol} négocié (port ${t.port})`,
          detail: "Ce protocole est obsolète et vulnérable.",
          verifyCommand: `openssl s_client -connect 127.0.0.1:${t.port} -tls1_2 </dev/null`,
          recommendation: "Exigez TLS 1.2 minimum, TLS 1.3 recommandé (`ssl_protocols TLSv1.2 TLSv1.3;` pour nginx).",
        });
      } else if (t.legacyAccepted) {
        weakDone.add(t.port);
        add({
          category: "tls",
          checkId: `tls.legacy_accepted.${t.port}`,
          severity: "medium",
          exposure: "public",
          title: `TLS 1.0 / 1.1 encore acceptés (port ${t.port})`,
          detail: "Un client peut forcer un protocole obsolète (attaque par rétrogradation).",
          verifyCommand: `openssl s_client -connect 127.0.0.1:${t.port} -tls1_1 </dev/null`,
          recommendation: "Désactivez TLS 1.0 et 1.1 : `ssl_protocols TLSv1.2 TLSv1.3;` (nginx), `minVersion: VersionTLS12` (Traefik).",
        });
      }
    }

    // HTTP security headers for this hostname (P1-6).
    if (host && t.headers) {
      const h = t.headers;
      const missing = [
        !h.hsts && "Strict-Transport-Security",
        !h.contentTypeOptions && "X-Content-Type-Options",
        !h.frameOptions && !h.csp && "X-Frame-Options",
        !h.csp && "Content-Security-Policy",
      ].filter(Boolean) as string[];
      if (missing.length) {
        add({
          category: "http",
          checkId: `http.headers.${host}`,
          severity: !h.hsts ? "medium" : "low",
          exposure: "public",
          title: `En-têtes de sécurité manquants sur ${host}`,
          detail: `Absents : ${missing.join(", ")}.${!h.hsts ? " Sans HSTS, un attaquant sur le réseau peut forcer une première visite en HTTP." : ""}`,
          evidence: `GET https://${host}/`,
          verifyCommand: `curl -sI https://${host}/ | grep -iE 'strict-transport|content-security|x-frame|x-content-type'`,
          recommendation:
            "Traefik : middleware `headers` avec `stsSeconds=31536000`, `contentTypeNosniff=true`, `frameDeny=true`, `contentSecurityPolicy=…`. nginx : `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;` et équivalents.",
        });
      }
    }
  }

  // ── Sauvegardes (Backup Shield §5.3 Backup Discovery) ──
  const dbPorts = new Set([3306, 5432, 27017]);
  const hostsDatabase =
    report.listening.some((l) => dbPorts.has(l.port) || /^(postgres|mysqld|mariadbd|mongod)$/.test(l.process ?? "")) ||
    containers.some((c) => /(^|\/)(postgres|mysql|mariadb|mongo)$/.test(imageName(c.image)));
  const backups = report.backups;
  if (backups && hostsDatabase && backups.jobs === 0) {
    add({
      category: "backups",
      checkId: "backups.none",
      severity: "high",
      title: "Base de données sans sauvegarde planifiée",
      detail: "Une base de données tourne sur ce serveur mais aucun cron ni timer de sauvegarde n'a été trouvé.",
      verifyCommand: "grep -rlE 'pg_dump|mysqldump|mongodump|restic|borg' /etc/cron* /var/spool/cron 2>/dev/null",
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

  const accepted = options.accepted ?? new Set<string>();
  const chains = attackChains(report, findings.filter((f) => !accepted.has(f.checkId)), escapes, exposureOf);
  return { score: scoreOf(findings, accepted), findings, chains, mitigations };
}

/** Links findings into concrete escalation paths (P2-3). */
function attackChains(
  report: AgentReport,
  open: InfraFinding[],
  escapes: Map<string, string>,
  exposureOf: Map<string, { exposure: Exposure; where: string[] }>,
): AttackChain[] {
  const chains: AttackChain[] = [];
  const ids = new Set(open.map((f) => f.checkId));
  const containers = report.docker?.containers ?? [];
  const escapeIds = (name: string) =>
    [`docker.privileged.${name}`, `docker.socket.${name}`, `docker.host_mount.${name}`, `docker.caps.${name}`, `docker.socket_proxy_write.${name}`].filter((id) =>
      ids.has(id),
    );

  // 1. A container reachable from the Internet that can reach the host.
  for (const [name, how] of escapes) {
    const exp = exposureOf.get(name);
    const related = escapeIds(name);
    if (!exp || exp.exposure !== "public" || !related.length) continue;
    chains.push({
      id: `chain.exposed_escape.${name}`,
      severity: "critical",
      title: `Internet → « ${name} » → contrôle du serveur`,
      steps: [
        `« ${name} » est joignable depuis Internet (${exp.where.join(", ")}).`,
        `Il dispose d'un accès à l'hôte : ${how}.`,
        "Une seule faille applicative dans ce service suffit à prendre le contrôle complet du serveur.",
      ],
      checkIds: related,
    });
  }

  // 2. An exposed console with weak/no auth on the same network as a container that reaches the host.
  const adminFindings = open.filter((f) => f.checkId.startsWith("admin."));
  for (const af of adminFindings) {
    const adminName = af.checkId.split(".").slice(2).join(".");
    const adminC = containers.find((c) => c.name === adminName);
    for (const [name, how] of escapes) {
      if (name === adminName || !escapeIds(name).length) continue;
      const target = containers.find((c) => c.name === name);
      const shared = adminC?.networks && target?.networks ? adminC.networks.filter((n) => target.networks!.includes(n)) : [];
      if (adminC?.networks && target?.networks && !shared.length) continue; // isolated: no path
      chains.push({
        id: `chain.admin_pivot.${adminName}.${name}`,
        severity: af.severity === "low" ? "high" : "critical",
        title: `Console « ${adminName} » exposée → « ${name} » → serveur`,
        steps: [
          `${af.title}.`,
          shared.length
            ? `Elle partage le réseau Docker « ${shared.join(", ")} » avec « ${name} ».`
            : `Elle peut joindre « ${name} » (réseaux non mesurés par l'agent).`,
          `« ${name} » a un accès à l'hôte (${how}) : depuis la console (requêtes, sources de données, SSRF), l'attaquant pivote vers le serveur.`,
        ],
        checkIds: [af.checkId, ...escapeIds(name)],
      });
    }
  }

  // 3. SSH brute force straight to root.
  if (ids.has("ssh.password_auth") && ids.has("bruteforce.ssh_unprotected")) {
    chains.push({
      id: "chain.ssh_bruteforce",
      severity: ids.has("ssh.root_login") ? "critical" : "high",
      title: ids.has("ssh.root_login") ? "Brute force SSH → root" : "Brute force SSH → compte du serveur",
      steps: [
        "SSH accepte les mots de passe.",
        "Aucun Fail2ban ni CrowdSec ne bloque les essais répétés.",
        ids.has("ssh.root_login") ? "Le compte root peut se connecter directement." : "Un compte avec sudo devient la cible.",
      ],
      checkIds: ["ssh.password_auth", "bruteforce.ssh_unprotected", ...(ids.has("ssh.root_login") ? ["ssh.root_login"] : [])],
    });
  }

  // 4. Database port open to the Internet with secrets in clear on the same host.
  const dbPort = open.find((f) => /^port\.public\.(5432|3306|6379|27017)$/.test(f.checkId));
  const envSecrets = open.find((f) => f.checkId.startsWith("secrets."));
  if (dbPort && envSecrets) {
    chains.push({
      id: "chain.db_credentials",
      severity: "critical",
      title: "Base de données exposée + secrets en clair",
      steps: [`${dbPort.title}.`, `${envSecrets.title}.`, "Un identifiant récupéré (sauvegarde, journal, conteneur compromis) ouvre directement la base depuis Internet."],
      checkIds: [dbPort.checkId, envSecrets.checkId],
    });
  }
  return chains;
}
