import { prisma } from "@codegate/db";
import type { Judgement } from "../analysis/engines/pipeline.js";
import { pathMatcher } from "../analysis/engines/glob.js";
import type { DependencyResult, FindingResult } from "../analysis/types.js";
import { recordAudit } from "./audit.js";
import { notifySlack } from "./notify.js";

/**
 * Controlled exceptions and rule health (anti-noise rules):
 *  - an exception only applies once APPROVED, before its expiry, and while
 *    not revoked; it covers an alert matching ALL its criteria;
 *  - a rule whose measured false-positive rate is too high goes into
 *    observation automatically — its alerts are shown, never decide — until
 *    a reviewer sets it back to active (e.g. after improving it).
 */

/** Auto-observation: at least this many reviewed alerts… */
export const NOISY_MIN_REVIEWED = 5;
/** …of which at least this share were false positives… */
export const NOISY_FP_RATE = 0.5;
/** …over this window. */
export const NOISY_WINDOW_DAYS = 90;
/** Owners are reminded this many days before an exception expires. */
export const EXPIRY_NOTICE_DAYS = 7;

const DAY = 86_400_000;

/** Production, staging or development, from the branch a PR targets. */
export function environmentOfBranch(branch: string | null | undefined): "production" | "staging" | "development" | null {
  if (!branch) return null;
  if (/^(main|master|prod|production|release(\/.*)?)$/i.test(branch)) return "production";
  if (/^(staging|stage|preprod|pre-prod|uat)$/i.test(branch)) return "staging";
  return "development";
}

export interface ExceptionRow {
  id: string;
  ruleId: string | null;
  pathGlob: string | null;
  riskType: string | null;
  dependency: string | null;
  dependencyVersion: string | null;
  branch: string | null;
  environment: string | null;
}

/** Does an exception's branch/environment scope include this PR? */
function inScope(e: ExceptionRow, branch: string | null | undefined): boolean {
  if (e.branch && e.branch !== branch) return false;
  if (e.environment && e.environment !== environmentOfBranch(branch)) return false;
  return true;
}

/** The first exception covering a code/config finding, or null. */
export function matchFinding(
  exceptions: ExceptionRow[],
  f: FindingResult,
  branch?: string | null,
): string | null {
  for (const e of exceptions) {
    // A dependency exception never covers code; a code exception must say
    // what it covers (enforced at creation).
    if (e.dependency) continue;
    if (!e.ruleId && !e.pathGlob && !e.riskType) continue;
    if (!inScope(e, branch)) continue;
    if (e.ruleId && e.ruleId !== f.ruleId) continue;
    if (e.riskType && e.riskType !== f.type) continue;
    if (e.pathGlob && !(f.filePath && pathMatcher([e.pathGlob])(f.filePath))) continue;
    return e.id;
  }
  return null;
}

export function matchDependency(
  exceptions: ExceptionRow[],
  d: DependencyResult,
  branch?: string | null,
): string | null {
  for (const e of exceptions) {
    if (!e.dependency || e.dependency !== d.name) continue;
    if (e.dependencyVersion && e.dependencyVersion !== d.version && e.dependencyVersion !== d.resolvedVersion) continue;
    if (!inScope(e, branch)) continue;
    return e.id;
  }
  return null;
}

/** Approved, unexpired, unrevoked exceptions that apply to a repository. */
export async function activeExceptions(organizationId: string, repositoryId: string, now = new Date()) {
  return prisma.findingException.findMany({
    where: {
      organizationId,
      approvedAt: { not: null },
      revokedAt: null,
      OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      AND: [{ OR: [{ repositoryId }, { orgWide: true }] }],
    },
    orderBy: { createdAt: "asc" },
  });
}

export interface RuleHealth {
  ruleId: string;
  reviewed: number;
  falsePositives: number;
  rate: number;
}

/** Rules whose reviewed alerts were mostly false positives, over the window. */
export async function noisyRules(organizationId: string, now = new Date()): Promise<RuleHealth[]> {
  const groups = await prisma.finding.groupBy({
    by: ["ruleId", "status"],
    where: {
      ruleId: { not: null },
      status: { in: ["false_positive", "acknowledged"] },
      createdAt: { gte: new Date(now.getTime() - NOISY_WINDOW_DAYS * DAY) },
      pullRequest: { repository: { organizationId } },
    },
    _count: { _all: true },
  });
  const byRule = new Map<string, { fp: number; ok: number }>();
  for (const g of groups) {
    const r = byRule.get(g.ruleId!) ?? { fp: 0, ok: 0 };
    if (g.status === "false_positive") r.fp += g._count._all;
    else r.ok += g._count._all;
    byRule.set(g.ruleId!, r);
  }
  const out: RuleHealth[] = [];
  for (const [ruleId, { fp, ok }] of byRule) {
    const reviewed = fp + ok;
    if (reviewed >= NOISY_MIN_REVIEWED && fp / reviewed >= NOISY_FP_RATE) {
      out.push({ ruleId, reviewed, falsePositives: fp, rate: fp / reviewed });
    }
  }
  return out;
}

/**
 * Rules in observation for an organization: set so by a reviewer, or measured
 * as too noisy (unless a reviewer set the rule back to active).
 */
export async function observedRules(organizationId: string, now = new Date()): Promise<Map<string, string>> {
  const [settings, noisy] = await Promise.all([
    prisma.ruleSetting.findMany({ where: { organizationId } }),
    noisyRules(organizationId, now),
  ]);
  const out = new Map<string, string>();
  const forcedActive = new Set(settings.filter((s) => s.mode === "active").map((s) => s.ruleId));
  for (const n of noisy) {
    if (forcedActive.has(n.ruleId)) continue;
    out.set(
      n.ruleId,
      `Règle en observation automatique : ${Math.round(n.rate * 100)} % de faux positifs sur ${n.reviewed} alertes examinées (${NOISY_WINDOW_DAYS} j).`,
    );
  }
  for (const s of settings) {
    if (s.mode === "observation") out.set(s.ruleId, `Règle mise en observation : ${s.reason}`);
  }
  return out;
}

/** Everything a PR analysis needs to apply exceptions and rule observation. */
export async function judgementFor(
  organizationId: string,
  repositoryId: string,
  branch: string | null,
  now = new Date(),
): Promise<Judgement> {
  const [exceptions, observed] = await Promise.all([
    activeExceptions(organizationId, repositoryId, now),
    observedRules(organizationId, now),
  ]);
  return {
    observedRules: observed,
    exceptionFor: (f) => matchFinding(exceptions, f, branch),
    dependencyExceptionFor: (d) => matchDependency(exceptions, d, branch),
  };
}

/**
 * Daily: remind owners of exceptions expiring within EXPIRY_NOTICE_DAYS
 * (once per exception), and record the ones that just expired.
 */
export async function remindExpiringExceptions(encryptionKey: string, now = new Date()) {
  const soon = await prisma.findingException.findMany({
    where: {
      approvedAt: { not: null },
      revokedAt: null,
      remindedAt: null,
      expiresAt: { gt: now, lte: new Date(now.getTime() + EXPIRY_NOTICE_DAYS * DAY) },
    },
    include: { repository: { select: { name: true } } },
  });
  for (const e of soon) {
    await prisma.findingException.update({ where: { id: e.id }, data: { remindedAt: now } });
    await recordAudit({
      organizationId: e.organizationId,
      actorType: "system",
      action: "exception.expiring",
      resourceType: "finding_exception",
      resourceId: e.id,
      metadata: { expiresAt: e.expiresAt!.toISOString(), ownerId: e.requestedById },
    });
    await notifySlack(e.organizationId, encryptionKey, {
      title: "Exception bientôt expirée",
      severity: "warning",
      repository: e.repository?.name ?? "organisation",
      detail: `L'exception « ${e.reason.slice(0, 120)} » expire le ${e.expiresAt!.toISOString().slice(0, 10)}. Renouvelez-la avec une nouvelle justification, ou laissez les alertes revenir.`,
    });
  }
  return { reminded: soon.length };
}
