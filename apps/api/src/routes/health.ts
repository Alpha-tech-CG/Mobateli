import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { engineAvailable } from "../analysis/engine/index.js";

export async function healthRoutes(app: FastifyInstance) {
  // Liveness — process is up.
  app.get("/health", async () => ({
    status: "ok",
    // Rust scan engine (WebAssembly) loaded, or TypeScript fallback.
    scanEngine: engineAvailable() ? "rust-wasm" : "typescript",
  }));

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
