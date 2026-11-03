import type { AddedLine } from "./diff.js";
import type { FindingResult } from "./types.js";
import type { Severity } from "@codegate/shared";

/**
 * Security analysis of sensitive configuration files (cahier §5.1: .env,
 * docker-compose.yml, vercel.json, GitHub Actions workflows). Instead of
 * flagging every change to these files, each rule targets one concrete risk;
 * a clean change produces no finding at all.
 */

interface ConfigRule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  /** Which files the rule applies to. */
  file: RegExp;
  test: (line: string) => boolean;
}

const WORKFLOW = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const COMPOSE = /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/;
const DOCKERFILE = /(^|\/)(Dockerfile|[\w.-]+\.Dockerfile|Containerfile)$/;
const VERCEL = /(^|\/)vercel\.json$/;

const RULES: ConfigRule[] = [
  {
    id: "GHA_PR_TARGET_CHECKOUT",
    severity: "critical",
    title: "Workflow exécutant le code d'une PR externe avec des secrets",
    description:
      "Un workflow `pull_request_target` qui récupère le code de la PR (head) l'exécute avec les secrets et un jeton en écriture : n'importe quel contributeur peut les voler.",
    remediation: "Utilisez `pull_request` pour le code non fiable, ou ne faites jamais de checkout du head dans `pull_request_target`.",
    file: WORKFLOW,
    test: (l) => /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/.test(l),
  },
  {
    id: "GHA_WRITE_ALL",
    severity: "high",
    title: "Workflow avec toutes les permissions en écriture",
    description: "`permissions: write-all` donne au jeton du workflow un accès en écriture à tout le dépôt.",
    remediation: "Déclarez des permissions minimales, ex. `permissions: { contents: read }`, et élevez-les par job si besoin.",
    file: WORKFLOW,
    test: (l) => /^\s*permissions:\s*write-all\s*$/.test(l),
  },
  {
    id: "GHA_SCRIPT_INJECTION",
    severity: "high",
    title: "Injection de script dans un workflow",
    description:
      "Une donnée contrôlée par l'auteur d'une PR / issue (titre, corps, nom de branche…) est interpolée dans une commande shell : elle peut exécuter du code.",
    remediation: "Passez la valeur par une variable d'environnement (`env: TITLE: ${{ … }}`) et utilisez `\"$TITLE\"` dans le script.",
    file: WORKFLOW,
    test: (l) =>
      /\$\{\{\s*github\.(event\.(pull_request|issue|comment|review|head_commit|discussion)\.[\w.]*(title|body|ref|label|message|name|email)|head_ref)\b[^}]*\}\}/.test(l) &&
      !/^\s*(env|[\w-]+):\s*\$\{\{/.test(l) &&
      !/^\s*[A-Z_][A-Z0-9_]*:\s/.test(l),
  },
  {
    id: "GHA_SECRET_ECHO",
    severity: "high",
    title: "Secret affiché dans les journaux du workflow",
    description: "Un secret est passé à `echo`/`printf` : il peut apparaître en clair dans les logs ou un fichier d'artefact.",
    remediation: "Ne jamais afficher un secret ; passez-le en variable d'environnement au seul outil qui en a besoin.",
    file: WORKFLOW,
    test: (l) => /\b(echo|printf)\b[^\n]*\$\{\{\s*secrets\./.test(l),
  },
  {
    id: "GHA_UNPINNED_ACTION",
    severity: "medium",
    title: "Action tierce non figée",
    description: "Une action est référencée par une branche (`@main`, `@master`) : son code peut changer à tout moment sans relecture.",
    remediation: "Référencez une version (`@v4`) ou, mieux, un commit SHA complet.",
    file: WORKFLOW,
    test: (l) => /^\s*-?\s*uses:\s*(?!actions\/|github\/|\.\/)[\w.-]+\/[\w./-]+@(main|master|dev|develop|latest)\s*$/.test(l),
  },
  {
    id: "REMOTE_SCRIPT_PIPE",
    severity: "medium",
    title: "Script distant exécuté sans vérification",
    description: "`curl … | sh` exécute du code téléchargé sans contrôle d'intégrité.",
    remediation: "Téléchargez, vérifiez l'empreinte (sha256) ou la signature, puis exécutez ; ou utilisez un paquet officiel.",
    file: /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|Dockerfile|[\w.-]+\.Dockerfile|Containerfile|[\w.-]+\.sh)$/,
    test: (l) => /\b(curl|wget)\b[^|#\n]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(l),
  },
  {
    id: "COMPOSE_PRIVILEGED",
    severity: "high",
    title: "Conteneur privilégié (docker-compose)",
    description: "`privileged: true` donne au conteneur un accès quasi complet au noyau de l'hôte.",
    remediation: "Retirez `privileged` ; ajoutez seulement les capacités nécessaires (`cap_add`).",
    file: COMPOSE,
    test: (l) => /^\s*privileged:\s*true\s*$/.test(l),
  },
  {
    id: "COMPOSE_DOCKER_SOCKET",
    severity: "critical",
    title: "Socket Docker monté (docker-compose)",
    description: "Monter `/var/run/docker.sock` permet au conteneur de piloter Docker, donc de prendre le contrôle de l'hôte.",
    remediation: "Retirez ce volume, ou passez par un proxy de socket en lecture seule.",
    file: COMPOSE,
    test: (l) => /docker\.sock/.test(l) && /^\s*-/.test(l),
  },
  {
    id: "COMPOSE_DB_EXPOSED",
    severity: "medium",
    title: "Base de données publiée sur toutes les interfaces",
    description: "Le port d'une base de données (Postgres, MySQL, Redis, MongoDB…) est publié sans adresse : il est joignable depuis le réseau.",
    remediation: "Publiez sur la boucle locale : `\"127.0.0.1:5432:5432\"`, ou ne publiez pas le port (réseau Docker interne).",
    file: COMPOSE,
    test: (l) => /^\s*-\s*["']?(\d{2,5}:)?(5432|3306|6379|27017|9200|11211)["']?\s*$/.test(l),
  },
  {
    id: "COMPOSE_HOST_NETWORK",
    severity: "medium",
    title: "Conteneur sur le réseau de l'hôte",
    description: "`network_mode: host` supprime l'isolation réseau du conteneur.",
    remediation: "Utilisez un réseau Docker dédié et publiez uniquement les ports nécessaires.",
    file: COMPOSE,
    test: (l) => /^\s*network_mode:\s*["']?host["']?\s*$/.test(l),
  },
  {
    id: "DOCKER_LATEST_TAG",
    severity: "low",
    title: "Image de base non figée (`latest`)",
    description: "`FROM …:latest` (ou sans tag) change sans prévenir : build non reproductible et image non auditée.",
    remediation: "Figez une version, idéalement par digest (`image@sha256:…`).",
    file: DOCKERFILE,
    test: (l) => /^\s*FROM\s+(?!scratch\b)[^\s:@]+(:latest)?(\s+AS\s+\w+)?\s*$/i.test(l),
  },
  {
    id: "VERCEL_CORS_WILDCARD",
    severity: "medium",
    title: "CORS ouvert à tous les sites",
    description: "`Access-Control-Allow-Origin: *` autorise n'importe quel site à lire les réponses de vos routes.",
    remediation: "Listez explicitement les origines autorisées.",
    file: VERCEL,
    test: (l) => /"Access-Control-Allow-Origin"[^}]*"\*"/i.test(l) || /"value"\s*:\s*"\*"/.test(l),
  },
];

/** A committed `.env` (not an example/template) almost always holds real secrets. */
const ENV_FILE = /(^|\/)\.env(\.(local|production|prod|development|dev|staging))?$/;

export function analyzeConfig(addedLines: AddedLine[], files: string[]): FindingResult[] {
  const findings: FindingResult[] = [];
  const seen = new Set<string>();
  for (const { file, line, content } of addedLines) {
    for (const rule of RULES) {
      if (!rule.file.test(file) || !rule.test(content)) continue;
      const key = `${rule.id}:${file}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        type: "config",
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        filePath: file,
        line,
        ruleId: rule.id,
        remediation: rule.remediation,
      });
    }
  }
  for (const file of files) {
    if (ENV_FILE.test(file)) {
      findings.push({
        type: "config",
        severity: "high",
        title: "Fichier .env versionné",
        description: "Un fichier d'environnement est ajouté au dépôt : il contient en général des secrets réels.",
        filePath: file,
        ruleId: "ENV_FILE_COMMITTED",
        remediation: "Retirez-le (`git rm --cached`), ajoutez-le au .gitignore, faites tourner les secrets qu'il contenait ; gardez un `.env.example` sans valeurs.",
      });
    }
  }
  return findings;
}
