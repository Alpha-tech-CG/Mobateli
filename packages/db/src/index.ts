import { PrismaClient } from "@prisma/client";

export * from "@prisma/client";

/**
 * Singleton Prisma client. In dev we cache it on globalThis so hot-reload
 * doesn't exhaust the connection pool with new clients.
 */
const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma: PrismaClient =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
