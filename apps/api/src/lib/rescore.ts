import { prisma } from "@codegate/db";
import { decide } from "../analysis/risk.js";
import { storedFinding } from "./finding-rows.js";

/** Statuses that no longer weigh on a PR's decision. */
export const NOT_SCORED = ["false_positive", "accepted_risk", "suppressed", "resolved"] as const;

/**
 * Recompute a PR's score and status from what is still open, after a human
 * verdict, an exception or a fix — with the confidence and proof level each
 * alert had at analysis time (a rescore must not turn an uncertain alert into
 * a deciding one).
 */
export async function rescorePullRequest(pullRequestId: string) {
  const [findings, secrets, dependencies] = await Promise.all([
    prisma.finding.findMany({ where: { pullRequestId, status: { notIn: [...NOT_SCORED] } } }),
    prisma.secretFinding.findMany({ where: { pullRequestId, status: { notIn: ["false_positive", "resolved"] } } }),
    prisma.dependency.findMany({ where: { pullRequestId, exceptionId: null } }),
  ]);
  const { riskScore, status } = decide({
    findings: findings.map(storedFinding),
    secrets: secrets.map((s) => ({
      secretType: s.secretType,
      location: s.location,
      maskedPreview: s.maskedPreview,
      severity: s.severity,
    })),
    dependencies: dependencies.map((d) => ({
      ecosystem: d.ecosystem,
      name: d.name,
      version: d.version,
      trustScore: d.trustScore ?? 0,
      riskLevel: d.riskLevel,
    })),
  });
  await prisma.pullRequest.update({ where: { id: pullRequestId }, data: { riskScore, status } });
  return { riskScore, status };
}
