import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import type { AuthPrincipal } from "../plugins/auth.js";
import { decrypt, encrypt } from "./crypto.js";

/**
 * Platform-level configuration of this CodeGate deployment. The operator is
 * the owner of PLATFORM_ORG_ID when set, otherwise of the first organization
 * ever created (the one that installed CodeGate).
 */
export async function isPlatformOperator(principal: AuthPrincipal, config: AppConfig): Promise<boolean> {
  if (principal.role !== "owner") return false;
  if (config.PLATFORM_ORG_ID) return principal.organizationId === config.PLATFORM_ORG_ID;
  const first = await prisma.organization.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true } });
  return first?.id === principal.organizationId;
}

export async function readPlatformSetting<T>(key: string, encryptionKey: string): Promise<T | null> {
  const row = await prisma.platformSetting.findUnique({ where: { key } });
  if (!row) return null;
  return JSON.parse(decrypt(row.valueEncrypted, encryptionKey)) as T;
}

export async function writePlatformSetting(
  key: string,
  value: unknown,
  encryptionKey: string,
  updatedById: string,
): Promise<void> {
  const valueEncrypted = encrypt(JSON.stringify(value), encryptionKey);
  await prisma.platformSetting.upsert({
    where: { key },
    create: { key, valueEncrypted, updatedById },
    update: { valueEncrypted, updatedById },
  });
}
