import { randomBytes } from "node:crypto";
import { lookup, resolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import type { Observation } from "../analysis/bruteforce.js";

/**
 * Outbound side of BruteForce Shield: ownership verification and the
 * low-volume, sequential test requests. Guard rails (extension §2, §10.1):
 * HTTPS only, verified origin only, public addresses only (no SSRF into
 * private networks), no redirects followed, ≤ 20 requests, paced.
 */

export const USER_AGENT = "CodeGate-BruteForceShield/1.0 (authorized security test)";
const TIMEOUT_MS = 8_000;
const PACE_MS = 250;

function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    return (
      a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPrivateAddress(v6.slice(7));
  return v6 === "::1" || v6 === "::" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe80");
}

export class TargetRejected extends Error {}

/** Refuse origins that resolve to loopback / private / link-local ranges. */
export async function assertPublicOrigin(origin: string): Promise<URL> {
  const url = new URL(origin);
  if (url.protocol !== "https:") throw new TargetRejected("https_required");
  const addrs = await lookup(url.hostname, { all: true }).catch(() => []);
  if (!addrs.length) throw new TargetRejected("unresolvable_host");
  if (addrs.some((a) => isPrivateAddress(a.address))) throw new TargetRejected("private_address");
  return url;
}

export function newVerificationToken(): string {
  return "cg-verify-" + randomBytes(18).toString("base64url");
}

/**
 * Ownership proof: either a DNS TXT record
 *   _codegate-verification.<host>  "codegate-verification=<token>"
 * or a file at <origin>/.well-known/codegate-verification.txt containing it.
 */
export async function verifyOwnership(
  origin: string,
  token: string,
): Promise<{ verified: boolean; method: "dns" | "file" | null }> {
  const url = await assertPublicOrigin(origin);
  try {
    const records = await resolveTxt(`_codegate-verification.${url.hostname}`);
    if (records.some((chunks) => chunks.join("").trim() === `codegate-verification=${token}`)) {
      return { verified: true, method: "dns" };
    }
  } catch {
    /* no TXT record — try the file */
  }
  try {
    const res = await fetch(new URL("/.well-known/codegate-verification.txt", url), {
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "user-agent": USER_AGENT },
    });
    if (res.ok && (await res.text()).trim().slice(0, 200).includes(token)) {
      return { verified: true, method: "file" };
    }
  } catch {
    /* unreachable or redirected */
  }
  return { verified: false, method: null };
}

export interface LoginProbe {
  origin: string;
  endpoint: string;
  emailField: string;
  passwordField: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One failed login attempt with a random wrong password. */
export async function attemptLogin(
  probe: LoginProbe,
  account: string,
  attempt: number,
  fetchImpl: typeof fetch = fetch,
): Promise<Observation> {
  const url = new URL(probe.endpoint, probe.origin);
  if (url.origin !== new URL(probe.origin).origin) throw new TargetRejected("endpoint_outside_origin");
  const started = performance.now();
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({
        [probe.emailField]: account,
        // Never a guess: a random value that cannot be anyone's password.
        [probe.passwordField]: "cg-wrong-" + randomBytes(12).toString("base64url"),
      }),
    });
    const body = (await res.text()).slice(0, 2000).toLowerCase();
    return {
      attempt,
      status: res.status,
      ms: Math.round(performance.now() - started),
      body,
      retryAfter: res.headers.get("retry-after"),
    };
  } catch {
    return { attempt, status: 0, ms: Math.round(performance.now() - started), body: "", retryAfter: null };
  }
}

/** Sequential failed attempts until blocked or `max` reached. */
export async function runLockoutProbe(
  probe: LoginProbe,
  account: string,
  max: number,
  isBlocked: (o: Observation) => boolean,
  fetchImpl: typeof fetch = fetch,
): Promise<Observation[]> {
  const out: Observation[] = [];
  for (let i = 1; i <= max; i++) {
    const o = await attemptLogin(probe, account, i, fetchImpl);
    out.push(o);
    if (isBlocked(o)) break;
    if (i < max) await sleep(PACE_MS);
  }
  return out;
}

/** A syntactically valid address that cannot belong to anyone (RFC 6761). */
export function nonExistentAccount(): string {
  return `codegate-probe-${randomBytes(6).toString("hex")}@example.invalid`;
}
