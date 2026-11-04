import { execFile } from "node:child_process";
import type { Confidence, FindingResult } from "./types.js";
import type { Severity } from "@codegate/shared";

/**
 * Semgrep — moteur SAST sémantique externe (cahier §9.3).
 *
 * Complète les règles regex déterministes de `sast.ts` par une analyse
 * sémantique du code modifié. Modelé sur `osv.ts` : c'est une passe hors du
 * cœur synchrone (elle lance un sous-processus), elle échoue en mode ouvert
 * (l'absence du binaire ou une panne ne bloque jamais une PR), et son runner
 * est injectable pour que les tests ne dépendent JAMAIS du vrai binaire.
 *
 * Sortie Semgrep (`--json`) → `FindingResult[]` de type "sast", en mappant la
 * sévérité, le CWE, l'OWASP et la confiance vers nos propres échelles.
 */

/** Ruleset pinné : jeu de règles « CI » de Semgrep (curaté, peu de bruit). */
const DEFAULT_CONFIG = "p/ci";
const DEFAULT_TIMEOUT_MS = 20000;
/** Semgrep peut produire un gros JSON ; on laisse de la marge au tampon. */
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

/**
 * Lance Semgrep et résout le JSON brut de sa sortie standard. Doit rejeter
 * (throw) quand le binaire est absent ou qu'aucune sortie exploitable n'est
 * produite — `scanSemgrep` traduit alors cela en repli silencieux.
 */
export type SemgrepRunner = (
  files: string[],
  opts: { config: string; cwd?: string; timeoutMs: number },
) => Promise<string>;

export interface SemgrepOptions {
  /** Runner injectable (tests). Par défaut : le binaire `semgrep` local. */
  runner?: SemgrepRunner;
  /** Jeu de règles Semgrep (`p/ci`, `p/owasp-top-ten`, `auto`…). */
  config?: string;
  /** Répertoire de travail où résoudre les chemins des fichiers. */
  cwd?: string;
  timeoutMs?: number;
}

/** Forme (partielle) de la sortie `semgrep --json`. */
interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      confidence?: string;
      references?: string[];
    };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
}

/**
 * Runner par défaut : exécute le binaire `semgrep`. Semgrep sort avec un code
 * non nul quand il TROUVE des résultats, ce qui n'est pas une erreur pour
 * nous : tant que du JSON est produit sur stdout, on le renvoie. Seul un échec
 * de lancement (binaire absent) ou un timeout sans sortie fait rejeter.
 */
const defaultRunner: SemgrepRunner = (files, { config, cwd, timeoutMs }) =>
  new Promise((resolve, reject) => {
    const args = ["--json", "--quiet", "--config", config, "--timeout", "0", "--", ...files];
    execFile(
      "semgrep",
      args,
      { cwd, timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES },
      (err, stdout) => {
        if (stdout && stdout.trim().startsWith("{")) {
          resolve(stdout);
          return;
        }
        reject(err ?? new Error("semgrep: aucune sortie JSON"));
      },
    );
  });

/** Première valeur utile d'un champ Semgrep qui peut être string ou string[]. */
function firstString(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string") return value.trim() || undefined;
  if (Array.isArray(value)) return value.find((v) => typeof v === "string" && v.trim())?.trim();
  return undefined;
}

/**
 * Sévérité Semgrep → notre échelle. On privilégie `metadata` (plus granulaire,
 * peut valoir CRITICAL) et on retombe sur `extra.severity` (ERROR/WARNING/INFO).
 */
function mapSeverity(severity: string | undefined): Severity {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "ERROR":
    case "HIGH":
      return "high";
    case "WARNING":
    case "MEDIUM":
    case "MODERATE":
      return "medium";
    case "INFO":
    case "LOW":
      return "low";
    default:
      // Un résultat sans sévérité reconnue reste un signal : « medium ».
      return "medium";
  }
}

function mapConfidence(confidence: string | undefined): Confidence | undefined {
  switch ((confidence ?? "").toUpperCase()) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return undefined;
  }
}

/** Normalise « CWE-89: Improper Neutralization… » → « CWE-89 » pour la dédup. */
function normalizeCwe(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const match = raw.match(/CWE-\d+/i);
  return match ? match[0].toUpperCase() : raw;
}

function toFinding(result: SemgrepResult): FindingResult {
  const extra = result.extra ?? {};
  const metadata = extra.metadata ?? {};
  const checkId = result.check_id ?? "semgrep";
  const shortId = checkId.split(".").pop() || checkId;
  const message = extra.message?.trim() || "Résultat Semgrep.";

  const references = metadata.references;
  const remediation =
    Array.isArray(references) && references.length ? references.join(" ") : message;

  // metadata.severity est parfois plus précis (CRITICAL) que extra.severity.
  const metaSeverity = firstString(
    (metadata as { severity?: string | string[] }).severity,
  );

  const finding: FindingResult = {
    type: "sast",
    severity: mapSeverity(metaSeverity ?? extra.severity),
    title: `Semgrep : ${shortId}`,
    description: message,
    ruleId: checkId,
    remediation,
  };

  // Semgrep rend des chemins natifs (`app\views.py` sous Windows) : on les
  // normalise comme ceux du diff pour que la déduplication fonctionne.
  if (result.path) finding.filePath = result.path.replace(/\\/g, "/");
  if (typeof result.start?.line === "number") finding.line = result.start.line;

  const cwe = normalizeCwe(firstString(metadata.cwe));
  if (cwe) finding.cwe = cwe;
  const owasp = firstString(metadata.owasp);
  if (owasp) finding.owasp = owasp;
  const confidence = mapConfidence(metadata.confidence);
  if (confidence) finding.confidence = confidence;

  return finding;
}

/**
 * Analyse les fichiers modifiés avec Semgrep. Renvoie `[]` sur toute défaillance
 * (binaire absent, timeout, JSON invalide) — repli silencieux comme OSV.
 */
export async function scanSemgrep(
  files: string[],
  opts: SemgrepOptions = {},
): Promise<FindingResult[]> {
  if (!files.length) return [];
  const runner = opts.runner ?? defaultRunner;
  const config = opts.config ?? DEFAULT_CONFIG;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  try {
    const raw = await runner(files, {
      config,
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
      timeoutMs,
    });
    const parsed = JSON.parse(raw) as SemgrepOutput;
    if (!parsed.results?.length) return [];
    return parsed.results.map(toFinding);
  } catch {
    // Binaire absent, timeout, réseau de règles indisponible, JSON cassé.
    return [];
  }
}
