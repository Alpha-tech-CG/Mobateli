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
import { pullRequestRoutes } from "./routes/pull-requests.js";
import { integrationRoutes } from "./routes/integrations.js";
import { auditRoutes } from "./routes/audit.js";
import { agentGuardRoutes } from "./routes/agent-guard.js";
import { scimRoutes } from "./routes/scim.js";
import { samlRoutes } from "./routes/saml.js";
import { webhookRoutes } from "./routes/webhooks.js";
import { serverRoutes } from "./routes/servers.js";
import { bruteForceRoutes } from "./routes/bruteforce.js";
import { backupRoutes } from "./routes/backups.js";
import { findingRoutes } from "./routes/findings.js";
import { githubRoutes } from "./routes/github.js";
import { privacyRoutes } from "./routes/privacy.js";
import { cronRoutes } from "./routes/cron.js";
import { approvalRoutes } from "./routes/approvals.js";
import { platformRoutes } from "./routes/platform.js";
import { getRedis } from "./lib/redis.js";
import { createJobs } from "./lib/jobs.js";

export async function buildApp(config: AppConfig): Promise<FastifyInstance> {
  const app = Fastify({
    // On Vercel the client IP comes from x-forwarded-for, set by Vercel's
    // edge; without this every request would share the proxy's IP and the
    // per-IP rate limits / lockouts would hit all users at once.
    trustProxy: process.env.VERCEL === "1",
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
  await app.register(rateLimit, { max: config.RATE_LIMIT_PER_MINUTE, timeWindow: "1 minute" });
  await app.register(authPlugin, {
    jwtSecret: config.JWT_SECRET,
    mfaRequiredForAdmins: config.MFA_REQUIRED_FOR_ADMINS === "true",
  });

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
    const statusCode = (err as { statusCode?: number }).statusCode;
    if (statusCode === 429) {
      return reply.code(429).send({ error: "rate_limited" });
    }
    // Client errors raised by Fastify itself (bad JSON, body too large…).
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({ error: "bad_request" });
    }
    reply.log.error(err);
    return reply.code(500).send({ error: "internal_error" });
  });

  const jobs = createJobs(config, getRedis(config.REDIS_URL), app.log);

  await app.register(healthRoutes);
  await app.register(async (instance) => {
    await authRoutes(instance, config);
  });
  await app.register(organizationRoutes);
  await app.register(policyRoutes);
  await app.register(async (instance) => {
    await pullRequestRoutes(instance, jobs);
  });
  await app.register(async (instance) => {
    await integrationRoutes(instance, config);
  });
  await app.register(findingRoutes);
  await app.register(privacyRoutes);
  await app.register(approvalRoutes);
  await app.register(async (instance) => {
    await platformRoutes(instance, config);
  });
  await app.register(async (instance) => {
    await cronRoutes(instance, config);
  });
  await app.register(async (instance) => {
    await githubRoutes(instance, config);
  });
  await app.register(auditRoutes);
  await app.register(async (instance) => {
    await agentGuardRoutes(instance, config);
  });
  await app.register(scimRoutes);
  await app.register(async (instance) => {
    await serverRoutes(instance, config);
  });
  await app.register(async (instance) => {
    await bruteForceRoutes(instance, config);
  });
  await app.register(async (instance) => {
    await backupRoutes(instance, config);
  });
  await app.register(async (instance) => {
    await samlRoutes(instance, config);
  });
  // Encapsulated scope: the raw-body parser applies to webhooks only.
  await app.register(async (instance) => {
    await webhookRoutes(instance, config, jobs);
  });

  return app;
}
