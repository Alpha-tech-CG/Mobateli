import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { timingSafeEqual } from "node:crypto";
import type { AppConfig } from "../config.js";
import { runMaintenance } from "../lib/maintenance.js";

/** Scheduled jobs, called by Vercel Cron with `Authorization: Bearer <CRON_SECRET>`. */
export async function cronRoutes(app: FastifyInstance, config: AppConfig) {
  function authorized(req: FastifyRequest): boolean {
    if (!config.CRON_SECRET) return false;
    const given = Buffer.from(req.headers.authorization ?? "");
    const expected = Buffer.from(`Bearer ${config.CRON_SECRET}`);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  const handler = async (req: FastifyRequest, reply: FastifyReply) => {
    if (!config.CRON_SECRET) return reply.code(503).send({ error: "cron_not_configured" });
    if (!authorized(req)) return reply.code(401).send({ error: "unauthorized" });
    const summary = await runMaintenance(config);
    req.log.info({ summary }, "maintenance done");
    return summary;
  };
  app.get("/api/v1/cron/maintenance", handler);
  app.post("/api/v1/cron/maintenance", handler);
}
