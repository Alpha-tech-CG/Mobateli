import type { FastifyInstance } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { prisma, type Prisma } from "@codegate/db";
import { agentReportSchema, connectServerSchema, serverRiskAcceptanceSchema, type AgentReport } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { notifySlack } from "../lib/notify.js";
import { evaluateInfra, type InfraResult } from "../analysis/infra.js";

const TOKEN_PREFIX = "cg_srv_";

function newAgentToken(): { token: string; hash: string } {
  const token = TOKEN_PREFIX + randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

const MANAGE = ["owner", "admin", "security_manager"] as const;

/** checkIds currently accepted or mitigated (expired acceptances count again). */
async function acceptedChecks(serverId: string): Promise<Set<string>> {
  const rows = await prisma.serverRiskAcceptance.findMany({
    where: { serverId, OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] },
    select: { checkId: true },
  });
  return new Set(rows.map((r) => r.checkId));
}

function analysisOf(result: InfraResult, accepted: Set<string>, resolved: string[], introduced: string[]) {
  return {
    chains: result.chains,
    mitigations: result.mitigations,
    acceptedCount: result.findings.filter((f) => accepted.has(f.checkId)).length,
    resolved,
    introduced,
  } as unknown as Prisma.InputJsonValue;
}

const findingRow = (serverId: string, f: InfraResult["findings"][number]) => ({
  serverId,
  category: f.category,
  checkId: f.checkId,
  severity: f.severity,
  title: f.title,
  detail: f.detail,
  recommendation: f.recommendation,
  evidence: f.evidence ?? null,
  verifyCommand: f.verifyCommand ?? null,
  exploitScenario: f.exploitScenario ?? null,
  exposure: f.exposure ?? null,
});

/** Re-scores the last report after an acceptance change (no new agent run needed). */
async function rescore(serverId: string): Promise<number | null> {
  const server = await prisma.server.findUnique({ where: { id: serverId }, select: { lastReport: true, analysis: true } });
  if (!server?.lastReport) return null;
  const accepted = await acceptedChecks(serverId);
  const result = evaluateInfra(server.lastReport as unknown as AgentReport, { accepted });
  const prev = (server.analysis ?? {}) as { resolved?: string[]; introduced?: string[] };
  await prisma.server.update({
    where: { id: serverId },
    data: { securityScore: result.score, analysis: analysisOf(result, accepted, prev.resolved ?? [], prev.introduced ?? []) },
  });
  return result.score;
}

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
        previousScore: true,
        analysis: true,
        rescanRequestedAt: true,
        findings: true,
        acceptances: { orderBy: { createdAt: "desc" } },
        scans: { orderBy: { createdAt: "desc" }, take: 12 },
      },
    });
    if (!server) return reply.code(404).send({ error: "not_found" });
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    server.findings.sort((a, b) => order[a.severity] - order[b.severity]);
    const now = Date.now();
    const active = new Map(
      server.acceptances.filter((x) => !x.expiresAt || x.expiresAt.getTime() > now).map((x) => [x.checkId, x]),
    );
    return {
      server: {
        ...server,
        findings: server.findings.map((f) => ({ ...f, acceptance: active.get(f.checkId) ?? null })),
      },
    };
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

  // Accept a finding as a known risk, or record its compensating control (P1-9).
  app.put(
    "/api/v1/servers/:id/acceptances/:checkId",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id, checkId } = req.params as { id: string; checkId: string };
      const body = serverRiskAcceptanceSchema.parse(req.body);
      const server = await prisma.server.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true, findings: { where: { checkId }, select: { title: true, severity: true } } },
      });
      if (!server) return reply.code(404).send({ error: "not_found" });
      const finding = server.findings[0];
      if (!finding) return reply.code(404).send({ error: "finding_not_found" });
      const data = {
        kind: body.kind,
        justification: body.justification,
        acceptedById: req.principal.userId,
        expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
      };
      await prisma.serverRiskAcceptance.upsert({
        where: { serverId_checkId: { serverId: id, checkId } },
        create: { serverId: id, checkId, ...data },
        update: data,
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: body.kind === "accepted" ? "server.risk_accepted" : "server.risk_mitigated",
        resourceType: "server",
        resourceId: id,
        metadata: {
          checkId,
          title: finding.title,
          severity: finding.severity,
          justification: body.justification,
          expiresAt: body.expiresAt ?? null,
        },
      });
      return { score: await rescore(id) };
    },
  );

  app.delete(
    "/api/v1/servers/:id/acceptances/:checkId",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id, checkId } = req.params as { id: string; checkId: string };
      const server = await prisma.server.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true },
      });
      if (!server) return reply.code(404).send({ error: "not_found" });
      const res = await prisma.serverRiskAcceptance.deleteMany({ where: { serverId: id, checkId } });
      if (!res.count) return reply.code(404).send({ error: "acceptance_not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "server.risk_reopened",
        resourceType: "server",
        resourceId: id,
        metadata: { checkId },
      });
      return { score: await rescore(id) };
    },
  );

  // Ask the agent for a new audit; it picks the request up within minutes (P2-7).
  app.post(
    "/api/v1/servers/:id/rescan",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = await prisma.server.updateMany({
        where: { id, organizationId: req.principal.organizationId },
        data: { rescanRequestedAt: new Date() },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "server.rescan_requested",
        resourceType: "server",
        resourceId: id,
      });
      return reply.code(202).send({ status: "requested" });
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

  // ── Agent endpoints: authenticated by the per-server token, not a JWT ──
  async function agentServer(authorization: string | undefined) {
    const auth = authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token.startsWith(TOKEN_PREFIX)) return null;
    return prisma.server.findUnique({
      where: { agentTokenHash: hashToken(token) },
      select: {
        id: true,
        name: true,
        organizationId: true,
        securityScore: true,
        lastReportAt: true,
        rescanRequestedAt: true,
        findings: { select: { checkId: true } },
      },
    });
  }

  // Polled by the agent's frequent cron: run now if asked, or if the last audit is old.
  app.get("/api/v1/agent/pending", async (req, reply) => {
    const server = await agentServer(req.headers.authorization);
    if (!server) return reply.code(401).send({ error: "invalid_agent_token" });
    const last = server.lastReportAt?.getTime() ?? 0;
    const requested = !!server.rescanRequestedAt && server.rescanRequestedAt.getTime() > last;
    const due = Date.now() - last > 6 * 3600 * 1000;
    return { run: requested || due, reason: requested ? "requested" : due ? "schedule" : null };
  });

  app.post("/api/v1/agent/report", async (req, reply) => {
    const server = await agentServer(req.headers.authorization);
    if (!server) return reply.code(401).send({ error: "invalid_agent_token" });

    const report = agentReportSchema.parse(req.body);
    const accepted = await acceptedChecks(server.id);
    const result = evaluateInfra(report, { accepted });

    // What changed since the previous audit (P0-5 delta, P2-7 confirmation).
    const before = new Set(server.findings.map((f) => f.checkId));
    const after = new Set(result.findings.map((f) => f.checkId));
    const resolved = [...before].filter((id) => !after.has(id));
    const introduced = server.lastReportAt ? [...after].filter((id) => !before.has(id)) : [];
    const open = result.findings.filter((f) => !accepted.has(f.checkId));

    await prisma.$transaction([
      prisma.serverFinding.deleteMany({ where: { serverId: server.id } }),
      prisma.serverFinding.createMany({ data: result.findings.map((f) => findingRow(server.id, f)) }),
      prisma.serverScan.create({
        data: {
          serverId: server.id,
          score: result.score,
          critical: open.filter((f) => f.severity === "critical").length,
          high: open.filter((f) => f.severity === "high").length,
          total: open.filter((f) => f.severity !== "info").length,
          resolved,
          introduced,
        },
      }),
      prisma.server.update({
        where: { id: server.id },
        data: {
          hostname: report.hostname,
          os: report.os,
          agentVersion: report.agentVersion,
          previousScore: server.securityScore,
          securityScore: result.score,
          analysis: analysisOf(result, accepted, resolved, introduced),
          lastReport: report as unknown as Prisma.InputJsonValue,
          lastReportAt: new Date(),
          silentAlertedAt: null,
        },
      }),
    ]);

    const critical = open.filter((f) => f.severity === "critical");
    await recordAudit({
      organizationId: server.organizationId,
      actorType: "system",
      action: "server.scanned",
      resourceType: "server",
      resourceId: server.id,
      metadata: {
        score: result.score,
        previousScore: server.securityScore,
        findings: open.length,
        accepted: result.findings.length - open.length,
        critical: critical.length,
        resolved: resolved.length,
        introduced: introduced.length,
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

    return reply.code(202).send({
      score: result.score,
      previousScore: server.securityScore,
      findings: open.length,
      resolved: resolved.length,
      introduced: introduced.length,
      chains: result.chains.length,
    });
  });
}
