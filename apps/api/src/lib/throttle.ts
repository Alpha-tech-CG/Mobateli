import { createHash } from "node:crypto";
import { prisma } from "@codegate/db";

/**
 * Progressive lockout for CodeGate's own authentication (BruteForce Shield,
 * extension §4.4). Counters live in Postgres so they hold across serverless
 * instances. Every rule is applied to several keys (account AND ip), so a
 * distributed attack on one account and a spray from one IP are both caught.
 */

export interface ThrottleRule {
  /** Failures allowed inside the window before locking. */
  maxAttempts: number;
  windowSeconds: number;
  /** First lockout; doubled at each new lockout (progressive), capped. */
  lockoutSeconds: number;
  maxLockoutSeconds: number;
}

export const RULES = {
  loginAccount: { maxAttempts: 5, windowSeconds: 600, lockoutSeconds: 300, maxLockoutSeconds: 3600 },
  loginIp: { maxAttempts: 20, windowSeconds: 600, lockoutSeconds: 300, maxLockoutSeconds: 3600 },
  totpAccount: { maxAttempts: 3, windowSeconds: 300, lockoutSeconds: 300, maxLockoutSeconds: 3600 },
  signupIp: { maxAttempts: 5, windowSeconds: 3600, lockoutSeconds: 3600, maxLockoutSeconds: 3600 },
  // Email-sending endpoints: bounded per address (no mailbox flooding) and per IP.
  emailAccount: { maxAttempts: 3, windowSeconds: 3600, lockoutSeconds: 3600, maxLockoutSeconds: 3600 },
  emailIp: { maxAttempts: 10, windowSeconds: 3600, lockoutSeconds: 3600, maxLockoutSeconds: 3600 },
  // Token submissions (reset / verify / invite) per IP.
  tokenIp: { maxAttempts: 20, windowSeconds: 600, lockoutSeconds: 600, maxLockoutSeconds: 3600 },
} satisfies Record<string, ThrottleRule>;

export interface ThrottleState {
  failures: number;
  windowStart: Date;
  lockedUntil: Date | null;
  lockouts: number;
}

/** Pure transition: the state after one more failure (or counted attempt). */
export function nextThrottleState(
  prev: ThrottleState | null,
  rule: ThrottleRule,
  now: Date,
): { state: ThrottleState; locked: boolean } {
  const windowExpired =
    !prev || now.getTime() - prev.windowStart.getTime() > rule.windowSeconds * 1000;
  const lockouts = prev?.lockouts ?? 0;
  const failures = (windowExpired ? 0 : prev!.failures) + 1;
  const windowStart = windowExpired ? now : prev!.windowStart;

  if (failures >= rule.maxAttempts) {
    const seconds = Math.min(rule.lockoutSeconds * 2 ** lockouts, rule.maxLockoutSeconds);
    return {
      state: {
        failures: 0,
        windowStart: now,
        lockedUntil: new Date(now.getTime() + seconds * 1000),
        lockouts: lockouts + 1,
      },
      locked: true,
    };
  }
  return { state: { failures, windowStart, lockedUntil: prev?.lockedUntil ?? null, lockouts }, locked: false };
}

/** Seconds left on the longest active lock among `keys`, 0 if none. */
export async function lockedFor(keys: string[], now = new Date()): Promise<number> {
  const rows = await prisma.authThrottle.findMany({
    where: { key: { in: keys }, lockedUntil: { gt: now } },
    select: { lockedUntil: true },
  });
  const until = Math.max(0, ...rows.map((r) => r.lockedUntil!.getTime()));
  return until ? Math.ceil((until - now.getTime()) / 1000) : 0;
}

/** Record a failure on `key`; returns true when it just triggered a lockout. */
export async function registerFailure(key: string, rule: ThrottleRule, now = new Date()): Promise<boolean> {
  const prev = await prisma.authThrottle.findUnique({ where: { key } });
  const { state, locked } = nextThrottleState(prev, rule, now);
  await prisma.authThrottle.upsert({
    where: { key },
    create: { key, ...state },
    update: state,
  });
  return locked;
}

/** Successful authentication clears the counter and the escalation level. */
export async function clearThrottle(key: string): Promise<void> {
  await prisma.authThrottle.deleteMany({ where: { key } });
}

/** Stable, non-reversible key part: emails are never stored in clear here. */
export function throttleKey(kind: string, value: string): string {
  return `${kind}:${createHash("sha256").update(value.toLowerCase()).digest("hex").slice(0, 32)}`;
}

export function tooManyAttempts(retryAfter: number) {
  const minutes = Math.max(1, Math.ceil(retryAfter / 60));
  return {
    error: "too_many_attempts",
    message: `Trop de tentatives. Réessayez dans ${minutes} minute${minutes > 1 ? "s" : ""}.`,
    retry_after: retryAfter,
  };
}
