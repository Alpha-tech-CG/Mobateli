import { prisma, type Prisma } from "@codegate/db";
import { recordAudit } from "./audit.js";
import { notifySlack } from "./notify.js";

const TTL_MS = 24 * 3_600_000;

export type ApprovalKind = "agent_action" | "deployment";

/** Effective status: a pending request past its deadline is expired. */
export function effectiveStatus(r: { status: string; expiresAt: Date }, now = new Date()): string {
  return r.status === "pending" && r.expiresAt < now ? "expired" : r.status;
}

/**
 * Open (or reuse) a human approval request. An agent retrying the same action
 * gets the same request back instead of flooding reviewers.
 */
export async function requestApproval(params: {
  organizationId: string;
  encryptionKey: string;
  kind: ApprovalKind;
  dedupeKey: string;
  title: string;
  detail: Prisma.InputJsonValue;
  repositoryId?: string | null;
  repositoryName?: string;
  requestedById?: string | null;
}): Promise<{ id: string; status: string; expiresAt: Date }> {
  const now = new Date();
  const existing = await prisma.approvalRequest.findFirst({
    where: {
      organizationId: params.organizationId,
      dedupeKey: params.dedupeKey,
      status: { in: ["pending", "approved"] },
      expiresAt: { gt: now },
    },
    orderBy: { createdAt: "desc" },
    select: { id: true, status: true, expiresAt: true },
  });
  if (existing) return existing;

  const created = await prisma.approvalRequest.create({
    data: {
      organizationId: params.organizationId,
      repositoryId: params.repositoryId ?? null,
      kind: params.kind,
      title: params.title,
      detail: params.detail,
      dedupeKey: params.dedupeKey,
      requestedById: params.requestedById ?? null,
      expiresAt: new Date(now.getTime() + TTL_MS),
    },
    select: { id: true, status: true, expiresAt: true },
  });
  await recordAudit({
    organizationId: params.organizationId,
    actorType: params.kind === "agent_action" ? "ai_agent" : "system",
    actorId: params.requestedById ?? null,
    action: "approval.requested",
    resourceType: "approval_request",
    resourceId: created.id,
    metadata: { kind: params.kind, title: params.title },
  });
  await notifySlack(params.organizationId, params.encryptionKey, {
    title: "Approbation humaine requise",
    severity: "warning",
    repository: params.repositoryName ?? "CodeGate",
    detail: `${params.title} — à valider dans CodeGate (Approbations) sous 24 h.`,
  });
  return created;
}
