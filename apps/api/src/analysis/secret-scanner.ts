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
const GENERIC_ASSIGN =
  /\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]([^'"]{8,})['"]/i;

/**
 * A connection string to the machine itself, a CI service container
 * (127.0.0.1, localhost, ::1) or a reserved example domain carries throwaway
 * test credentials, not a secret anyone can reach.
 */
export function isLocalDatabaseUrl(url: string): boolean {
  const host = url.replace(/^[a-z]+:\/\/[^@]*@/i, "").split(/[:/?]/)[0]!.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0") return true;
  // Reserved names (RFC 2606 / 6761) can never be a real server.
  return /(^|\.)(example\.(com|org|net)|example|test|invalid|localhost)$/.test(host);
}

// Obvious non-secret values: placeholders, docs, env-var references.
const PLACEHOLDER =
  /^(?:x{4,}|\.{3,}|changeme|change[_-]?me|placeholder|example|examplekey|your[_-]?\w+|my[_-]?\w+|dummy|sample|todo|fixme|redacted|null|none|undefined|false|true|test|secret|password)$/i;

function looksLikePlaceholder(value: string): boolean {
  if (PLACEHOLDER.test(value)) return true;
  // Templated/env references: ${VAR}, {{ VAR }}, <your-key>, process.env.X,
  // and Supabase/Terraform-style env("VAR") / env(VAR) indirections.
  if (/\$\{|\{\{|<[^>]+>|process\.env|os\.environ|import\.meta\.env|^env\(/.test(value)) return true;
  // A run of a single repeated char (aaaa…, 0000…) is never a live secret.
  if (/^(.)\1{7,}$/.test(value)) return true;
  return false;
}

/**
 * Qualify a provider-pattern match. Returns null when the match is clearly not
 * a credential (template, placeholder, vendor doc example), "low" when it can
 * only reach a local machine, "high" otherwise. Measured on real projects:
 * CI/docker-compose URLs like postgres://postgres:postgres@localhost and
 * `postgresql://${user}:${pw}@${host}` builders were blocking PRs.
 */
function qualifyProviderMatch(type: string, match: string): "low" | "high" | null {
  if (/\$\{|\{\{|<[^>]+>/.test(match)) return null;
  if (/EXAMPLE/i.test(match) || /x{4,}$/i.test(match)) return null;
  if (type === "postgres_url") {
    const m = match.match(/\/\/([^:@\s]+):([^@\s]+)@([^\s/:]+)/);
    if (!m) return "high";
    const [, user, pass, host] = m;
    if (PLACEHOLDER.test(pass!) || /^(pw|pwd|pass|user|username)$/i.test(pass!)) return null;
    if (/^(user|username)$/i.test(user!) && /^(host|hostname)$/i.test(host!)) return null;
    const local =
      /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$/i.test(host!) ||
      !host!.includes(".");
    return local ? "low" : "high";
  }
  return "high";
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

    for (const p of PATTERNS) {
      const m = content.match(p.regex);
      // Local/test databases are not secrets; templates, placeholders and
      // vendor doc examples are not credentials (qualifyProviderMatch).
      if (m && !(p.type === "postgres_url" && isLocalDatabaseUrl(m[0]))) {
        const quality = qualifyProviderMatch(p.type, m[0]);
        if (quality === null) continue;
        const key = `${p.type}:${file}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({
          secretType: p.type,
          location: `${file}:${line}`,
          maskedPreview: maskSecret(m[0]),
          severity: p.severity,
          // A structured provider key in a sample file is still worth noting,
          // but at low confidence — it is probably an illustrative value.
          confidence: inSample ? "low" : quality,
        });
      }
    }

    const g = content.match(GENERIC_ASSIGN);
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

/**
 * Second opinion on secrets found by any engine (the Rust engine has its own
 * patterns and does not know our false-positive rules). Each hit is re-checked
 * against the source line:
 * - placeholders, vendor documentation keys (AKIA…EXAMPLE), templates and
 *   local/test database URLs are dropped;
 * - a secret in a test, fixture or example file is a sample by construction:
 *   it leaves the secrets (and the score) and is reported once per file as
 *   an informational note — unless it has the shape of a live production key.
 */
export function refineSecrets(
  found: SecretResult[],
  lineAt: (file: string, line: number) => string | undefined,
): { secrets: SecretResult[]; samples: { file: string; count: number; types: string[] }[] } {
  const secrets: SecretResult[] = [];
  const samples = new Map<string, { count: number; types: Set<string> }>();
  for (const s of found) {
    const m = /^(.*):(\d+)$/.exec(s.location);
    const file = m ? m[1]! : s.location;
    const content = m ? lineAt(file, Number(m[2])) : undefined;
    if (content !== undefined && isNotASecret(s.secretType, content)) continue;
    if (isTestOrExampleFile(file) && !LIVE_KEY.test(content ?? "")) {
      const entry = samples.get(file) ?? { count: 0, types: new Set<string>() };
      entry.count++;
      entry.types.add(s.secretType);
      samples.set(file, entry);
      continue;
    }
    secrets.push(s);
  }
  return {
    secrets,
    samples: [...samples].map(([file, e]) => ({ file, count: e.count, types: [...e.types] })),
  };
}

/** Shapes that are production credentials whatever the file (Stripe live keys). */
const LIVE_KEY = /\b(sk|rk)_live_[0-9a-zA-Z]{16,}\b/;

function isNotASecret(type: string, content: string): boolean {
  if (/AKIA[0-9A-Z]{0,12}EXAMPLE/.test(content)) return true; // AWS documentation key
  const p = PATTERNS.find((x) => x.type === type);
  if (p) {
    const m = content.match(p.regex);
    if (!m) return false;
    if (p.type === "postgres_url" && isLocalDatabaseUrl(m[0])) return true;
    return qualifyProviderMatch(p.type, m[0]) === null;
  }
  if (type.startsWith("generic_")) {
    const g = content.match(GENERIC_ASSIGN);
    if (!g) return false;
    return looksLikePlaceholder(g[2]!) || shannonEntropy(g[2]!) < 3.5;
  }
  return false;
}
