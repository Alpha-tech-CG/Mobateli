import type { AddedLine } from "./diff.js";
import type { SecretResult } from "./types.js";

/**
 * Secret Shield (cahier §5.2). Pattern-based detection of common credential
 * formats, plus a generic high-entropy assignment catcher. Operates on added
 * lines only — we flag what the PR introduces.
 */

interface Pattern {
  type: string;
  regex: RegExp;
  severity: SecretResult["severity"];
}

// High-signal provider patterns. Severity "critical" for anything that is a
// live credential by construction.
const PATTERNS: Pattern[] = [
  { type: "aws_access_key_id", regex: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical" },
  { type: "stripe_secret_key", regex: /\bsk_(live|test)_[0-9a-zA-Z]{16,}\b/, severity: "critical" },
  { type: "openai_api_key", regex: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/, severity: "critical" },
  { type: "anthropic_api_key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, severity: "critical" },
  { type: "github_token", regex: /\b(ghp|gho|ghs|ghu)_[0-9A-Za-z]{36}\b/, severity: "critical" },
  { type: "github_pat", regex: /\bgithub_pat_[0-9A-Za-z_]{40,}\b/, severity: "critical" },
  { type: "google_api_key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: "high" },
  { type: "slack_token", regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: "high" },
  { type: "private_key", regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, severity: "critical" },
  { type: "postgres_url", regex: /\bpostgres(?:ql)?:\/\/[^\s:@]+:[^\s:@]+@[^\s/]+/, severity: "high" },
];

// Generic "key = 'value'" assignments where the name hints at a secret.
const GENERIC_ASSIGN =
  /\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]([^'"]{8,})['"]/i;

/** Shannon entropy (bits/char) — distinguishes random secrets from words. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}…${value.slice(-4)} (${value.length} chars)`;
}

export function scanSecrets(addedLines: AddedLine[]): SecretResult[] {
  const results: SecretResult[] = [];
  const seen = new Set<string>();

  for (const { file, line, content } of addedLines) {
    for (const p of PATTERNS) {
      const m = content.match(p.regex);
      if (m) {
        const key = `${p.type}:${file}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({
          secretType: p.type,
          location: `${file}:${line}`,
          maskedPreview: maskSecret(m[0]),
          severity: p.severity,
        });
      }
    }

    const g = content.match(GENERIC_ASSIGN);
    if (g) {
      const value = g[2]!;
      // Only flag if the value looks random (avoids "password = 'changeme'").
      if (shannonEntropy(value) >= 3.5 && value.length >= 12) {
        const key = `generic:${file}:${line}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            secretType: `generic_${g[1]!.toLowerCase().replace(/[_-]/g, "")}`,
            location: `${file}:${line}`,
            maskedPreview: maskSecret(value),
            severity: "high",
          });
        }
      }
    }
  }

  return results;
}
