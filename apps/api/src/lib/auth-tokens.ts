import { createHash, randomBytes } from "node:crypto";
import { prisma } from "@codegate/db";

/**
 * One-time tokens carried by email links. 256 random bits, stored only as a
 * SHA-256 hash (a database leak yields no usable link), single use, short
 * lived, and a new link invalidates the previous ones of the same purpose.
 */

export type TokenPurpose = "verify_email" | "reset_password" | "invite";

export const TOKEN_TTL_MS: Record<TokenPurpose, number> = {
  verify_email: 48 * 3600_000,
  reset_password: 3600_000,
  invite: 7 * 24 * 3600_000,
};

export const hashToken = (raw: string) => createHash("sha256").update(raw).digest("hex");

export async function issueToken(userId: string, purpose: TokenPurpose, now = new Date()): Promise<string> {
  const raw = randomBytes(32).toString("base64url");
  await prisma.$transaction([
    prisma.authToken.updateMany({ where: { userId, purpose, usedAt: null }, data: { usedAt: now } }),
    prisma.authToken.create({
      data: { userId, purpose, tokenHash: hashToken(raw), expiresAt: new Date(now.getTime() + TOKEN_TTL_MS[purpose]) },
    }),
  ]);
  return raw;
}

/**
 * Atomically consume a token: returns the user id when it exists, matches
 * the purpose, is unused and unexpired — and marks it used in the same
 * statement so two concurrent requests can't both succeed.
 */
export async function consumeToken(raw: string, purpose: TokenPurpose, now = new Date()): Promise<string | null> {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(raw)) return null;
  const tokenHash = hashToken(raw);
  const res = await prisma.authToken.updateMany({
    where: { tokenHash, purpose, usedAt: null, expiresAt: { gt: now } },
    data: { usedAt: now },
  });
  if (res.count !== 1) return null;
  const token = await prisma.authToken.findUnique({ where: { tokenHash }, select: { userId: true } });
  return token?.userId ?? null;
}
