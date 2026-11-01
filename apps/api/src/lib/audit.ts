import { prisma, type ActorType, type Prisma } from "@codegate/db";

/**
 * Append an immutable audit event. Every sensitive action goes through here
 * (cahier §10.1, §13.2). Never pass secret values in `metadata`.
 */
export async function recordAudit(params: {
  organizationId: string;
  actorType: ActorType;
  actorId?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  metadata?: Prisma.InputJsonValue;
}): Promise<void> {
  await prisma.auditEvent.create({
    data: {
      organizationId: params.organizationId,
      actorType: params.actorType,
      actorId: params.actorId ?? null,
      action: params.action,
      resourceType: params.resourceType,
      resourceId: params.resourceId ?? null,
      // Only set metadata when provided — the column is nullable JSON.
      ...(params.metadata !== undefined ? { metadata: params.metadata } : {}),
    },
  });
}
