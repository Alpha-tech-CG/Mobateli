import type { FastifyInstance } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { prisma } from "@codegate/db";
import { connectLinearSchema, connectSlackSchema, connectJiraSchema } from "@codegate/shared";
import { encrypt, decrypt } from "../lib/crypto.js";
import { recordAudit } from "../lib/audit.js";
import { sendSlackAlert } from "../lib/slack.js";
import type { AppConfig } from "../config.js";

/**
 * Integration management. The Linear API key is encrypted at rest and never
 * returned to the client (cahier §10.3).
 */
export async function integrationRoutes(app: FastifyInstance, config: AppConfig) {
  app.get(
    "/api/v1/integrations/linear",
    { preHandler: [app.authenticate] },
    async (req) => {
      const conn = await prisma.linearConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { teamId: true, createdAt: true },
      });
      return { connected: conn !== null, teamId: conn?.teamId ?? null };
    },
  );

  app.post(
    "/api/v1/integrations/linear",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager"),
      ],
    },
    async (req, reply) => {
      const body = connectLinearSchema.parse(req.body);
      const apiKeyEncrypted = encrypt(body.apiKey, config.ENCRYPTION_KEY);

      await prisma.linearConnection.upsert({
        where: { organizationId: req.principal.organizationId },
        create: {
          organizationId: req.principal.organizationId,
          apiKeyEncrypted,
          teamId: body.teamId,
        },
        update: { apiKeyEncrypted, teamId: body.teamId },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.linear_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { teamId: body.teamId },
      });

      return reply.code(201).send({ connected: true, teamId: body.teamId });
    },
  );

  app.delete(
    "/api/v1/integrations/linear",
    {
      preHandler: [app.authenticate, app.requireRole("owner", "admin")],
    },
    async (req) => {
      await prisma.linearConnection.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.linear_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );

  // ─── Slack ────────────────────────────────────────────

  app.get(
    "/api/v1/integrations/slack",
    { preHandler: [app.authenticate] },
    async (req) => {
      const conn = await prisma.slackConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { createdAt: true },
      });
      return { connected: conn !== null };
    },
  );

  app.post(
    "/api/v1/integrations/slack",
    {
      preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager")],
    },
    async (req, reply) => {
      const body = connectSlackSchema.parse(req.body);
      await prisma.slackConnection.upsert({
        where: { organizationId: req.principal.organizationId },
        create: {
          organizationId: req.principal.organizationId,
          webhookUrlEncrypted: encrypt(body.webhookUrl, config.ENCRYPTION_KEY),
        },
        update: { webhookUrlEncrypted: encrypt(body.webhookUrl, config.ENCRYPTION_KEY) },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.slack_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return reply.code(201).send({ connected: true });
    },
  );

  app.post(
    "/api/v1/integrations/slack/test",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const conn = await prisma.slackConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
      });
      if (!conn) return reply.code(404).send({ error: "not_connected" });
      try {
        await sendSlackAlert(decrypt(conn.webhookUrlEncrypted, config.ENCRYPTION_KEY), {
          title: "Test d'alerte CodeGate",
          severity: "info",
          repository: "—",
          detail: "Ceci est un test de connexion Slack depuis CodeGate.",
        });
        return { sent: true };
      } catch {
        return reply.code(502).send({ error: "slack_send_failed" });
      }
    },
  );

  app.delete(
    "/api/v1/integrations/slack",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req) => {
      await prisma.slackConnection.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.slack_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );

  // ─── GitLab ───────────────────────────────────────────

  app.get(
    "/api/v1/integrations/gitlab",
    { preHandler: [app.authenticate] },
    async (req) => {
      const conn = await prisma.gitlabConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { createdAt: true },
      });
      return { connected: conn !== null };
    },
  );

  // (Re)generate the webhook token. Returned once; only its hash is stored.
  app.post(
    "/api/v1/integrations/gitlab",
    {
      preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager")],
    },
    async (req, reply) => {
      const token = randomBytes(24).toString("base64url");
      const tokenHash = createHash("sha256").update(token).digest("hex");
      await prisma.gitlabConnection.upsert({
        where: { organizationId: req.principal.organizationId },
        create: { organizationId: req.principal.organizationId, tokenHash },
        update: { tokenHash },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.gitlab_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      // The token goes in the GitLab project webhook's "Secret token" field.
      return reply.code(201).send({ connected: true, webhookToken: token });
    },
  );

  app.delete(
    "/api/v1/integrations/gitlab",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req) => {
      await prisma.gitlabConnection.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.gitlab_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );

  // ─── Jira ─────────────────────────────────────────────

  app.get(
    "/api/v1/integrations/jira",
    { preHandler: [app.authenticate] },
    async (req) => {
      const conn = await prisma.jiraConnection.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { baseUrl: true, projectKey: true },
      });
      return {
        connected: conn !== null,
        baseUrl: conn?.baseUrl ?? null,
        projectKey: conn?.projectKey ?? null,
      };
    },
  );

  app.post(
    "/api/v1/integrations/jira",
    {
      preHandler: [app.authenticate, app.requireRole("owner", "admin", "security_manager")],
    },
    async (req, reply) => {
      const body = connectJiraSchema.parse(req.body);
      const apiTokenEncrypted = encrypt(body.apiToken, config.ENCRYPTION_KEY);
      await prisma.jiraConnection.upsert({
        where: { organizationId: req.principal.organizationId },
        create: {
          organizationId: req.principal.organizationId,
          baseUrl: body.baseUrl,
          email: body.email,
          apiTokenEncrypted,
          projectKey: body.projectKey,
        },
        update: {
          baseUrl: body.baseUrl,
          email: body.email,
          apiTokenEncrypted,
          projectKey: body.projectKey,
        },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.jira_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { projectKey: body.projectKey },
      });
      return reply.code(201).send({ connected: true, projectKey: body.projectKey });
    },
  );

  app.delete(
    "/api/v1/integrations/jira",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req) => {
      await prisma.jiraConnection.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.jira_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );

  // ─── SCIM provisioning token ──────────────────────────

  app.get(
    "/api/v1/integrations/scim",
    { preHandler: [app.authenticate] },
    async (req) => {
      const row = await prisma.scimToken.findUnique({
        where: { organizationId: req.principal.organizationId },
        select: { createdAt: true },
      });
      return { connected: row !== null };
    },
  );

  app.post(
    "/api/v1/integrations/scim",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const token = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(token).digest("hex");
      await prisma.scimToken.upsert({
        where: { organizationId: req.principal.organizationId },
        create: { organizationId: req.principal.organizationId, tokenHash },
        update: { tokenHash },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.scim_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      // Bearer token for the IdP's SCIM config, returned once.
      return reply.code(201).send({ connected: true, token });
    },
  );

  app.delete(
    "/api/v1/integrations/scim",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req) => {
      await prisma.scimToken.deleteMany({
        where: { organizationId: req.principal.organizationId },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.scim_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
      });
      return { connected: false };
    },
  );
}
