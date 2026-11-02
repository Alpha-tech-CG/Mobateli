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
  test: (line: string) => boolean;
}

const AGENT = String.raw`(?:ai|a\.i\.|assistant|llm|claude|copilot|cursor|codex|gemini|chatgpt|gpt|agent|windsurf|devin)`;

const RULES: Rule[] = [
  {
    id: "PI_INSTRUCTION_OVERRIDE",
    severity: "high",
    title: "Tentative de détournement des instructions d'un agent IA",
    description:
      "Ce texte demande à un modèle d'ignorer ses instructions. Un agent qui lit ce fichier peut être détourné.",
    remediation: "Supprimez ce texte ; traitez tout contenu de dépôt comme une donnée, jamais comme une instruction.",
    test: (l) =>
      /\b(ignore|disregard|forget|override)\b.{0,30}\b(all|any|the|previous|prior|above|earlier|your)\b.{0,30}\b(instructions?|prompts?|rules|guidelines)\b/i.test(l) ||
      /\bignore[zr]?\b.{0,30}\b(les|toutes?|vos)\b.{0,30}\b(instructions?|consignes|règles)\b/i.test(l),
  },
  {
    id: "PI_AGENT_DIRECTIVE",
    severity: "high",
    title: "Ordre adressé à un agent IA",
    description:
      "Le texte s'adresse directement à un agent IA pour lui faire exécuter une action (commande, installation, envoi…).",
    remediation: "Retirez cette consigne. Les actions sensibles d'un agent passent par Agent Guard et une approbation humaine.",
    test: (l) =>
      new RegExp(
        String.raw`\b(dear |hey |note to |attention |to the )?${AGENT}s?\b[\s,:-]{1,4}(you (must|should|need to)|please|must|now)?\s*\b(run|execute|exec|install|curl|wget|download|delete|rm -rf|push|commit|deploy|send|post|upload|disable|grant)\b`,
        "i",
      ).test(l),
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
      // A concrete external destination is required (URL, webhook, paste, email).
      /\b(send|post|upload|exfiltrate|leak|forward|share|envoie[rz]?|transmet(s|tre|tez))\b.{0,60}(\.env\b|secrets?|tokens?|api[ _-]?keys?|credentials|private[ _-]?key|mots? de passe|clés?)\b.{0,80}(https?:\/\/|webhook|pastebin|discord|telegram|ngrok|\b[\w.+-]+@[\w-]+\.[a-z]{2,})/i.test(l),
  },
  {
    id: "PI_INVISIBLE_CHARACTERS",
    severity: "high",
    title: "Caractères invisibles ou bidirectionnels",
    description:
      "Caractères Unicode invisibles (zéro largeur, contrôle bidirectionnel, tags) : le texte affiché à l'humain diffère de ce que lisent le compilateur ou l'IA (Trojan Source).",
    remediation: "Supprimez ces caractères (U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+E0000–U+E007F).",
    // eslint-disable-next-line no-misleading-character-class
    test: (l) => /[​-‏‪-‮⁦-⁩⁠﻿]|\uDB40[\uDC00-\uDC7F]/.test(l),
  },
];

/** Files that configure AI coding agents: changing them changes the agent. */
const AGENT_CONFIG = [
  /(^|\/)\.cursorrules$/,
  /(^|\/)\.cursor\/rules\//,
  /(^|\/)\.windsurfrules$/,
  /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$/,
  /(^|\/)\.claude\//,
  /(^|\/)\.github\/copilot-instructions\.md$/,
  /(^|\/)\.aider\.conf\.yml$/,
];

export function detectPromptInjection(addedLines: AddedLine[], files: string[]): FindingResult[] {
  const findings: FindingResult[] = [];
  for (const { file, line, content } of addedLines) {
    for (const rule of RULES) {
      if (rule.test(content)) {
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
    if (AGENT_CONFIG.some((re) => re.test(file))) {
      findings.push({
        type: "prompt_injection",
        severity: "medium",
        title: "Instructions d'agent IA modifiées",
        description:
          "Ce fichier pilote le comportement d'un agent de code (Cursor, Claude, Copilot…). Une modification malveillante détourne tous les futurs travaux de l'agent.",
        filePath: file,
        ruleId: "PI_AGENT_CONFIG_CHANGED",
        remediation: "Faites relire ce changement par un humain ; n'acceptez aucune consigne d'exécution, d'installation ou d'accès réseau.",
      });
    }
  }
  return findings;
}
