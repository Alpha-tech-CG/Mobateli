import type { FastifyInstance } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { prisma, type Prisma } from "@codegate/db";
import { agentReportSchema, connectServerSchema } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { notifySlack } from "../lib/notify.js";
import { evaluateInfra } from "../analysis/infra.js";

const TOKEN_PREFIX = "cg_srv_";

function newAgentToken(): { token: string; hash: string } {
  const token = TOKEN_PREFIX + randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

const MANAGE = ["owner", "admin", "security_manager"] as const;

/**
 * Infra Shield (extension §3, §8). A server is registered from the dashboard,
 * which issues a one-time agent token; the read-only agent installed on the
 * server then posts its facts to /api/v1/agent/report. Possessing the token
 * on the host is the proof of ownership — CodeGate never scans from outside.
 */
export async function serverRoutes(app: FastifyInstance, config: AppConfig) {
  app.post(
    "/api/v1/servers/connect",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = connectServerSchema.parse(req.body);
      const { token, hash } = newAgentToken();
      const server = await prisma.server.create({
        data: {
          organizationId: req.principal.organizationId,
          name: body.name,
          provider: body.provider ?? null,
          environment: body.environment,
          agentTokenHash: hash,
        },
        select: { id: true, name: true, environment: true, provider: true, createdAt: true },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "server.connected",
        resourceType: "server",
        resourceId: server.id,
        metadata: { name: body.name, environment: body.environment },
      });
      // The token is returned once and never stored in clear.
      return reply.code(201).send({ server, agentToken: token });
    },
  );

  app.get("/api/v1/servers", { preHandler: [app.authenticate] }, async (req) => {
    const servers = await prisma.server.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        name: true,
        provider: true,
        environment: true,
        hostname: true,
        os: true,
        securityScore: true,
        lastReportAt: true,
        createdAt: true,
        findings: { select: { severity: true } },
      },
    });
    return {
      servers: servers.map(({ findings, ...s }) => ({
        ...s,
        counts: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          total: findings.length,
        },
      })),
    };
  });

  app.get("/api/v1/servers/:id", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const server = await prisma.server.findFirst({
      where: { id, organizationId: req.principal.organizationId },
      select: {
        id: true,
        name: true,
        provider: true,
        environment: true,
        hostname: true,
        os: true,
        agentVersion: true,
        securityScore: true,
        lastReport: true,
        lastReportAt: true,
        createdAt: true,
        findings: true,
      },
    });
    if (!server) return reply.code(404).send({ error: "not_found" });
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    server.findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return { server };
  });

  app.get(
    "/api/v1/servers/:id/security-score",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const server = await prisma.server.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { securityScore: true, lastReportAt: true },
      });
      if (!server) return reply.code(404).send({ error: "not_found" });
      return server;
    },
  );

  app.post(
    "/api/v1/servers/:id/rotate-token",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { token, hash } = newAgentToken();
      const res = await prisma.server.updateMany({
        where: { id, organizationId: req.principal.organizationId },
        data: { agentTokenHash: hash },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "server.token_rotated",
        resourceType: "server",
        resourceId: id,
      });
      return { agentToken: token };
    },
  );

  app.delete(
    "/api/v1/servers/:id",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = await prisma.server.deleteMany({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "server.removed",
        resourceType: "server",
        resourceId: id,
      });
      return reply.code(204).send();
    },
  );

  // Organization-wide infrastructure report (§8 /reports/infrastructure).
  app.get(
    "/api/v1/reports/infrastructure",
    { preHandler: [app.authenticate] },
    async (req) => {
      const servers = await prisma.server.findMany({
        where: { organizationId: req.principal.organizationId },
        select: {
          id: true,
          name: true,
          environment: true,
          securityScore: true,
          lastReportAt: true,
          findings: {
            select: { category: true, severity: true, title: true, recommendation: true },
          },
        },
      });
      const scored = servers.filter((s) => s.securityScore !== null);
      return {
        generatedAt: new Date().toISOString(),
        averageScore: scored.length
          ? Math.round(scored.reduce((s, x) => s + x.securityScore!, 0) / scored.length)
          : null,
        servers,
      };
    },
  );

  // ── Agent ingestion: authenticated by the per-server token, not a JWT ──
  app.post("/api/v1/agent/report", async (req, reply) => {
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token.startsWith(TOKEN_PREFIX)) {
      return reply.code(401).send({ error: "invalid_agent_token" });
    }
    const server = await prisma.server.findUnique({
      where: { agentTokenHash: hashToken(token) },
      select: { id: true, name: true, organizationId: true, securityScore: true },
    });
    if (!server) return reply.code(401).send({ error: "invalid_agent_token" });

    const report = agentReportSchema.parse(req.body);
    const result = evaluateInfra(report);

    await prisma.$transaction([
      prisma.serverFinding.deleteMany({ where: { serverId: server.id } }),
      prisma.serverFinding.createMany({
        data: result.findings.map((f) => ({ serverId: server.id, ...f })),
      }),
      prisma.server.update({
        where: { id: server.id },
        data: {
          hostname: report.hostname,
          os: report.os,
          agentVersion: report.agentVersion,
          securityScore: result.score,
          lastReport: report as unknown as Prisma.InputJsonValue,
          lastReportAt: new Date(),
          silentAlertedAt: null,
        },
      }),
    ]);

    const critical = result.findings.filter((f) => f.severity === "critical");
    await recordAudit({
      organizationId: server.organizationId,
      actorType: "system",
      action: "server.scanned",
      resourceType: "server",
      resourceId: server.id,
      metadata: {
        score: result.score,
        findings: result.findings.length,
        critical: critical.length,
        agentVersion: report.agentVersion,
      },
    });

    if (critical.length) {
      await notifySlack(server.organizationId, config.ENCRYPTION_KEY, {
        title: "Serveur exposé : risque critique",
        severity: "critical",
        repository: server.name,
        detail: `${critical.length} contrôle(s) critique(s) — ${critical
          .slice(0, 3)
          .map((f) => f.title)
          .join(" ; ")}. Score ${result.score}/100.`,
      });
    }

    return reply.code(202).send({ score: result.score, findings: result.findings.length });
  });
}
