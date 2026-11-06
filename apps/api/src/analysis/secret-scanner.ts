import { isTestOrExampleFile, type AddedLine } from "./diff.js";
import type { SecretResult } from "./types.js";

/**
 * Secret Shield (cahier §5.2). Pattern-based detection of common credential
 * formats, plus a generic high-entropy assignment catcher. Operates on added
 * lines only — we flag what the PR introduces. To keep the false-positive rate
 * low (cahier §13.1), it ignores sample/test files and obvious placeholder
 * values, and tags each hit with a confidence level.
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
  { type: "sendgrid_api_key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, severity: "critical" },
  { type: "twilio_api_key", regex: /\bSK[0-9a-fA-F]{32}\b/, severity: "high" },
  { type: "npm_token", regex: /\bnpm_[A-Za-z0-9]{36}\b/, severity: "critical" },
  { type: "jwt", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: "high" },
  { type: "private_key", regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, severity: "critical" },
  { type: "postgres_url", regex: /\bpostgres(?:ql)?:\/\/[^\s:@]+:[^\s:@]+@[^\s/]+/, severity: "high" },
];

// Generic "key = 'value'" assignments where the name hints at a secret.
// The name may carry a prefix (`signingSecret`, `db_password`, `GITHUB_TOKEN`):
// what matters is that it ENDS with the sensitive word — `passwordField` or
// `tokenCount` do not.
const GENERIC_ASSIGN =
  /\b\w*?(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*['"]([^'"]{8,})['"]/i;

// Obvious non-secret values: placeholders, docs, env-var references.
const PLACEHOLDER =
  /^(?:x{4,}|\.{3,}|changeme|change[_-]?me|placeholder|example|examplekey|your[_-]?\w+|my[_-]?\w+|dummy|sample|todo|fixme|redacted|null|none|undefined|false|true|test|secret|password)$/i;

function looksLikePlaceholder(value: string): boolean {
  if (PLACEHOLDER.test(value)) return true;
  // Templated/env references: ${VAR}, {{ VAR }}, <your-key>, process.env.X
  if (/\$\{|\{\{|<[^>]+>|process\.env|os\.environ|import\.meta\.env/.test(value)) return true;
  // A run of a single repeated char (aaaa…, 0000…) is never a live secret.
  if (/^(.)\1{7,}$/.test(value)) return true;
  // An identifier-like word sequence (`password_confirmation_input`,
  // `user-api-token`) is a field name or label, not a credential.
  if (/^[a-z]+(?:[_.-][a-z]+)+$/i.test(value)) return true;
  // A password HASH in a standard format is not a usable credential
  // (bcrypt $2b$…, argon2, scrypt, Django pbkdf2_sha256$…).
  if (/^\$(2[aby]?|argon2(id|i|d)?|scrypt|s0|pbkdf2[-\w]*)\$/.test(value)) return true;
  if (/^(pbkdf2_sha(1|256)|bcrypt(_sha256)?|argon2|scrypt)\$/.test(value)) return true;
  // A code fragment caught between two string literals (`'KEY=' + read(…)`).
  if (/\s/.test(value) && /[()+;=]/.test(value)) return true;
  return false;
}

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
    // A key in a sample/test/fixture file is expected and not a real exposure.
    const inSample = isTestOrExampleFile(file);

    // A line already identified as a provider credential is not reported a
    // second time by the generic "name = value" catcher.
    let providerHit = false;
    for (const p of PATTERNS) {
      const m = content.match(p.regex);
      // A provider *test-mode* key (sk_test_…) in a test/fixture file is the
      // expected kind of fixture, not an exposure.
      if (m && inSample && /_test_/.test(m[0])) continue;
      if (m) {
        const key = `${p.type}:${file}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        providerHit = true;
        results.push({
          secretType: p.type,
          location: `${file}:${line}`,
          maskedPreview: maskSecret(m[0]),
          severity: p.severity,
          // A structured provider key in a sample file is still worth noting,
          // but at low confidence — it is probably an illustrative value.
          confidence: inSample ? "low" : "high",
        });
      }
    }

    const g = providerHit ? null : content.match(GENERIC_ASSIGN);
    if (g) {
      const value = g[2]!;
      // Only flag if the value looks random and is not an obvious placeholder.
      if (
        !inSample &&
        !looksLikePlaceholder(value) &&
        shannonEntropy(value) >= 3.5 &&
        value.length >= 12
      ) {
        const key = `generic:${file}:${line}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            secretType: `generic_${g[1]!.toLowerCase().replace(/[_-]/g, "")}`,
            location: `${file}:${line}`,
            maskedPreview: maskSecret(value),
            severity: "high",
            confidence: "medium",
          });
        }
      }
    }
  }

  return results;
}
