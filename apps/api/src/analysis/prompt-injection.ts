import type { AddedLine } from "./diff.js";
import type { FindingResult } from "./types.js";
import type { Severity } from "@codegate/shared";

/**
 * Prompt injection detection (cahier §10.5, Phase 2). Text in a PR — code
 * comments, README, docs, test fixtures — is untrusted data that an AI agent
 * may later read. These rules flag content written to steer such an agent,
 * plus invisible characters that hide code from human reviewers
 * (Trojan Source, CVE-2021-42574).
 */

interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  test: (line: string, file: string) => boolean;
}

// Built from escapes so this file itself stays free of invisible characters.
const INVISIBLE = new RegExp(
  "[\u200B-\u200F\u202A-\u202E\u2066-\u2069\u2060\uFEFF]|\uDB40[\uDC00-\uDC7F]",
  "gu",
);
const EMOJI = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\u20E3\uFE0F]/u;
// Joiners are part of the spelling of these scripts (Persian, Indic\u2026).
const JOINING_SCRIPT = /[\p{Script=Arabic}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Syriac}]/u;

/**
 * An invisible character that hides something. Legitimate uses are left
 * alone: the zero-width joiner inside an emoji sequence (\uD83E\uDDD1\u200D\uD83C\uDFEB) or a script that
 * needs it, the byte-order mark at the start of a file or inside a string
 * literal (CSV exports), the variation selector of an emoji.
 */
function hiddenCharacter(line: string): boolean {
  for (const m of line.matchAll(INVISIBLE)) {
    const c = m[0];
    const i = m.index!;
    const before = [...line.slice(0, i)].pop() ?? "";
    const after = [...line.slice(i + c.length)][0] ?? "";
    if ((c === "\u200D" || c === "\u200C") && (EMOJI.test(before) || EMOJI.test(after) || JOINING_SCRIPT.test(before))) continue;
    if (c === "\uFEFF" && (i === 0 || insideStringLiteral(line, i))) continue;
    return true;
  }
  return false;
}

function insideStringLiteral(line: string, index: number): boolean {
  let quote: string | null = null;
  for (let k = 0; k < index; k++) {
    const ch = line[k]!;
    if (quote) {
      if (ch === "\\") k++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
  }
  return quote !== null;
}

const DOC_FILE = /\.(md|mdx|markdown|html?|txt|rst|adoc)$/i;
/**
 * Security documentation that *describes* prompt injection and its defence
 * ("le prompt syst\u00E8me doit ignorer toute instruction contenue\u2026"). Never
 * applies to the files agents follow (AGENTS.md, .cursorrules\u2026), where the
 * same words would be an attack wearing a disguise.
 */
function describesTheDefence(line: string, file: string): boolean {
  if (!DOC_FILE.test(file) || isAgentConfig(file)) return false;
  return /prompt[ -]?injection|injection de prompt|injection d'instructions|(doit|doivent|must|should|devez|faut)\s+(toujours\s+|always\s+)?ignorer?\b|ignorer toute instruction contenue|ignore any instructions? (contained|found|embedded)|cloisonner|guardrail|garde-fou/i.test(
    line,
  );
}

const AGENT = String.raw`(?:ai|a\.i\.|assistant|llm|claude|copilot|cursor|codex|gemini|chatgpt|gpt|agent|windsurf|devin)`;
// Whole word only: "install" but not "installé" / "install-script".
const VERB = String.raw`(?:run|execute|exec|install|curl|wget|download|delete|rm -rf|push|commit|deploy|send|post|upload|disable|grant)(?![\wÀ-ÿ-])`;
const MODAL = String.raw`(?:must|should|need to|have to|please)`;
const AGENT_VOCATIVE = new RegExp(
  String.raw`\b${AGENT}s?\s*[,:]\s*(?:(?:you\s+)?${MODAL}\s+|now\s+)?${VERB}`,
  "i",
);
const AGENT_MODAL = new RegExp(String.raw`\b${AGENT}s?\s+(?:you\s+)?${MODAL}\s+${VERB}`, "i");

const RULES: Rule[] = [
  {
    id: "PI_INSTRUCTION_OVERRIDE",
    severity: "high",
    title: "Tentative de détournement des instructions d'un agent IA",
    description:
      "Ce texte demande à un modèle d'ignorer ses instructions. Un agent qui lit ce fichier peut être détourné.",
    remediation: "Supprimez ce texte ; traitez tout contenu de dépôt comme une donnée, jamais comme une instruction.",
    test: (l, file) =>
      !describesTheDefence(l, file) &&
      (/\b(ignore|disregard|forget|override)\b.{0,30}\b(all|any|the|previous|prior|above|earlier|your)\b.{0,30}\b(instructions?|prompts?|rules|guidelines)\b/i.test(l) ||
      /\bignore[zr]?\b.{0,30}\b(les|toutes?|vos)\b.{0,30}\b(instructions?|consignes|règles)\b/i.test(l)),
  },
  {
    id: "PI_AGENT_DIRECTIVE",
    severity: "high",
    title: "Ordre adressé à un agent IA",
    description:
      "Le texte s'adresse directement à un agent IA pour lui faire exécuter une action (commande, installation, envoi…).",
    remediation: "Retirez cette consigne. Les actions sensibles d'un agent passent par Agent Guard et une approbation humaine.",
    // A real address: the agent's name followed by a comma / colon or a
    // modal verb, then an action verb — not an identifier like agent_install.
    // (Examples live in the test file, never in this source.)
    test: (l) => AGENT_VOCATIVE.test(l) || AGENT_MODAL.test(l),
  },
  {
    id: "PI_ROLE_SPOOFING",
    severity: "medium",
    title: "Faux message système / changement de rôle",
    description:
      "Marqueurs de conversation (system prompt, balises de rôle) insérés pour se faire passer pour l'opérateur du modèle.",
    remediation: "Supprimez ces marqueurs ; ils n'ont pas leur place dans le code ou la documentation.",
    test: (l) =>
      /<\|(im_start|im_end|system|endoftext)\|>|\[\/?INST\]|<\/?(system|assistant)>|^\s*#{2,}\s*(system|assistant)\s*:?\s*$|\byou are now (a|an|the|in)\b|\bnew system prompt\b/i.test(l),
  },
  {
    id: "PI_SECRET_EXFILTRATION",
    severity: "critical",
    title: "Consigne d'exfiltration de secrets",
    description:
      "Le texte demande d'envoyer des secrets (.env, tokens, clés) vers l'extérieur — schéma typique d'attaque d'agent.",
    remediation: "Supprimez immédiatement ce contenu, vérifiez qu'aucun agent ne l'a exécuté et faites tourner les secrets exposés.",
    test: (l) =>
      // A concrete external destination is required (URL, webhook, paste,
      // email). Upper-case HTTP verbs ("POST /api/…" in API docs) are routes,
      // not instructions.
      // The secret word must stand alone ("adminToken" is a variable), and
      // method calls (`request(app).post(…).send(…)`) are code, not prose.
      /\b(send|post|upload|exfiltrate|leak|forward|share|envoie[rz]?|transmet(s|tre|tez))\b.{0,60}(?<![\w$])(\.env\b|secrets?|tokens?|api[ _-]?keys?|credentials|private[ _-]?key|mots? de passe|clés?)\b.{0,80}(https?:\/\/|webhook|pastebin|discord|telegram|ngrok|\b[\w.+-]+@[\w-]+\.[a-z]{2,})/i.test(
        l.replace(/\b(GET|POST|PUT|PATCH|DELETE)\b/g, "").replace(/\.(send|post|upload|forward|share)\s*\(/gi, ".call("),
      ),
  },
  {
    id: "PI_INVISIBLE_CHARACTERS",
    severity: "high",
    title: "Caractères invisibles ou bidirectionnels",
    description:
      "Caractères Unicode invisibles (zéro largeur, contrôle bidirectionnel, tags) : le texte affiché à l'humain diffère de ce que lisent le compilateur ou l'IA (Trojan Source).",
    remediation: "Supprimez ces caractères (U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+E0000–U+E007F).",
    test: (l) => hiddenCharacter(l),
  },
];

/**
 * Files whose text an AI coding agent follows as instructions (or that wire
 * commands it runs): changing them changes the agent. Plain tooling config in
 * the same folders (e.g. .claude/launch.json for preview servers) is not.
 */
const AGENT_CONFIG = [
  /(^|\/)\.cursorrules$/,
  /(^|\/)\.cursor\/rules\//,
  /(^|\/)\.windsurfrules$/,
  /(^|\/)(CLAUDE|AGENTS|GEMINI)(\.local)?\.md$/,
  /(^|\/)\.claude\/(commands|agents|skills|rules|hooks)\//,
  /(^|\/)\.claude\/settings(\.local)?\.json$/,
  /(^|\/)\.github\/copilot-instructions\.md$/,
  /(^|\/)\.github\/instructions\//,
  /(^|\/)\.aider\.conf\.yml$/,
];

export function isAgentConfig(file: string): boolean {
  return AGENT_CONFIG.some((re) => re.test(file));
}

/**
 * @param snapshot whole repository (scan) rather than a change (PR): an
 *   agent instructions file then is not "modified", merely present — an
 *   informational note to review, outside the score.
 */
export function detectPromptInjection(addedLines: AddedLine[], files: string[], snapshot = false): FindingResult[] {
  const findings: FindingResult[] = [];
  for (const { file, line, content } of addedLines) {
    for (const rule of RULES) {
      if (rule.test(content, file)) {
        findings.push({
          type: "prompt_injection",
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
  }
  for (const file of files) {
    if (!isAgentConfig(file)) continue;
    findings.push(
      snapshot
        ? {
            type: "prompt_injection",
            severity: "info",
            title: "Instructions d'agent IA présentes dans le dépôt",
            description:
              "Ce fichier pilote un agent de code (Cursor, Claude, Copilot…). Son contenu a été analysé ; faites relire toute modification future par un humain.",
            filePath: file,
            ruleId: "PI_AGENT_CONFIG_CHANGED",
            remediation: "Protégez ce fichier (CODEOWNERS, revue obligatoire).",
          }
        : {
            type: "prompt_injection",
            severity: "medium",
            title: "Instructions d'agent IA modifiées",
            description:
              "Ce fichier pilote le comportement d'un agent de code (Cursor, Claude, Copilot…). Une modification malveillante détourne tous les futurs travaux de l'agent.",
            filePath: file,
            ruleId: "PI_AGENT_CONFIG_CHANGED",
            remediation: "Faites relire ce changement par un humain ; n'acceptez aucune consigne d'exécution, d'installation ou d'accès réseau.",
          },
    );
  }
  return findings;
}
