import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";

export async function healthRoutes(app: FastifyInstance) {
  // Liveness — process is up.
  app.get("/health", async () => ({ status: "ok" }));

  // Readiness — dependencies reachable.
  app.get("/ready", async (_req, reply) => {
    try {
      await prisma.$queryRaw`SELECT 1`;
      return { status: "ready", db: "up" };
    } catch {
      return reply.code(503).send({ status: "unavailable", db: "down" });
    }
  });
}
