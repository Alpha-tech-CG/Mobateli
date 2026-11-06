import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import type { AppConfig } from "./config.js";
import authPlugin from "./plugins/auth.js";
import { healthRoutes } from "./routes/health.js";
import { authRoutes } from "./routes/auth.js";
import { organizationRoutes } from "./routes/organizations.js";
import { policyRoutes } from "./routes/policies.js";
import { findingRoutes } from "./routes/findings.js";
import { pullRequestRoutes } from "./routes/pull-requests.js";
import { integrationRoutes } from "./routes/integrations.js";
import { auditRoutes } from "./routes/audit.js";
import { agentGuardRoutes } from "./routes/agent-guard.js";
import { scimRoutes } from "./routes/scim.js";
import { samlRoutes } from "./routes/saml.js";
import { webhookRoutes } from "./routes/webhooks.js";
import { getRedis } from "./lib/redis.js";

export async function buildApp(config: AppConfig): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.NODE_ENV === "production" ? "info" : "debug",
      // Redact anything that could carry a secret from the logs (cahier §10.3).
      redact: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.token"],
      // Pretty logs in dev only; omit the key entirely otherwise.
      ...(config.NODE_ENV === "development"
        ? { transport: { target: "pino-pretty" } }
        : {}),
    },
  });

  // Security headers: CSP, HSTS, X-Frame-Options… (cahier §13.4).
  await app.register(helmet);
  // In production, lock CORS to the configured web origin. In development,
  // accept any localhost origin so the dashboard works on any dev port.
  await app.register(cors, {
    credentials: true,
    origin:
      config.NODE_ENV === "production"
        ? config.WEB_ORIGIN
        : (origin, cb) => {
            if (!origin || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
              cb(null, true);
            } else {
              cb(null, false);
            }
          },
  });
  await app.register(rateLimit, { max: 100, timeWindow: "1 minute" });
  await app.register(authPlugin, { jwtSecret: config.JWT_SECRET });

  // Uniform validation errors — surface which field failed, never the value.
  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({
        error: "validation_error",
        issues: err.issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
      });
    }
    if ((err as { statusCode?: number }).statusCode === 429) {
      return reply.code(429).send({ error: "rate_limited" });
    }
    reply.log.error(err);
    return reply.code(500).send({ error: "internal_error" });
  });

  const connection = getRedis(config.REDIS_URL);

  await app.register(healthRoutes);
  await app.register(async (instance) => {
    await authRoutes(instance, config);
  });
  await app.register(organizationRoutes);
  await app.register(policyRoutes);
  await app.register(findingRoutes);
  await app.register(async (instance) => {
    await pullRequestRoutes(instance, connection);
  });
  await app.register(async (instance) => {
    await integrationRoutes(instance, config);
  });
  await app.register(auditRoutes);
  await app.register(agentGuardRoutes);
  await app.register(scimRoutes);
  await app.register(async (instance) => {
    await samlRoutes(instance, config);
  });
  // Encapsulated scope: the raw-body parser applies to webhooks only.
  await app.register(async (instance) => {
    await webhookRoutes(instance, config, connection);
  });

  return app;
}
