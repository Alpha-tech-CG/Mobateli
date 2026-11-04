import type { FastifyInstance, FastifyReply } from "fastify";
import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { getInstallationOctokit } from "../lib/github.js";
import {
  exchangeOAuthCode,
  findUserInstallation,
  signConnectState,
  verifyConnectState,
} from "../lib/github-connect.js";
import { upsertRepository, type GithubRepo } from "./webhooks.js";

/**
 * "Connect GitHub": link a GitHub App installation to the caller's
 * organization, proving the user controls it (see lib/github-connect.ts).
 *
 *   GET    /api/v1/integrations/github            status + linked installations
 *   POST   /api/v1/integrations/github/connect    → install URL with signed state
 *   GET    /api/v1/integrations/github/callback   GitHub redirects the browser here
 *   DELETE /api/v1/integrations/github/:installationId   unlink
 *
 * GitHub App settings: Callback URL = <PUBLIC_API_URL>/api/v1/integrations/
 * github/callback, and "Request user authorization (OAuth) during
 * installation" checked.
 */
export async function githubConnectRoutes(app: FastifyInstance, config: AppConfig) {
  const configured = () =>
    Boolean(config.GITHUB_APP_SLUG && config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET);

  /** Back to the dashboard with an outcome the Integrations page displays. */
  const backToDashboard = (reply: FastifyReply, outcome: string) =>
    reply.redirect(`${config.WEB_ORIGIN}/integrations?github=${encodeURIComponent(outcome)}`);

  app.get(
    "/api/v1/integrations/github",
    { preHandler: [app.authenticate] },
    async (req) => {
      const rows = await prisma.githubInstallation.findMany({
        where: { organizationId: req.principal.organizationId },
        select: { installationId: true, accountLogin: true, createdAt: true },
        orderBy: { createdAt: "asc" },
      });
      return {
        configured: configured(),
        installations: rows.map((r) => ({
          installationId: Number(r.installationId),
          accountLogin: r.accountLogin,
          createdAt: r.createdAt,
        })),
      };
    },
  );

  app.post(
    "/api/v1/integrations/github/connect",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      if (!configured()) return reply.code(503).send({ error: "github_not_configured" });
      const state = signConnectState(
        config.JWT_SECRET,
        req.principal.organizationId,
        req.principal.userId,
      );
      const url = `https://github.com/apps/${encodeURIComponent(config.GITHUB_APP_SLUG!)}/installations/new?state=${encodeURIComponent(state)}`;
      return { url };
    },
  );

  // Public: GitHub redirects the user's browser here (no bearer token).
  app.get("/api/v1/integrations/github/callback", async (req, reply) => {
    if (!configured()) return backToDashboard(reply, "not_configured");
    const q = req.query as { code?: string; installation_id?: string; state?: string };

    // Proof 1: a state we signed for a logged-in owner/admin, still valid.
    const state = verifyConnectState(config.JWT_SECRET, q.state);
    if (!state) return backToDashboard(reply, "invalid_state");
    const installationId = Number(q.installation_id);
    if (!Number.isSafeInteger(installationId) || installationId <= 0 || !q.code) {
      return backToDashboard(reply, "missing_installation");
    }
    // The issuing user must still be an active owner/admin of that org.
    const issuer = await prisma.user.findFirst({
      where: { id: state.userId, organizationId: state.organizationId, active: true },
      select: { role: true },
    });
    if (!issuer || !["owner", "admin"].includes(issuer.role)) {
      return backToDashboard(reply, "invalid_state");
    }

    // Already ours: a replayed return link (back button, reload, the tunnel's
    // interstitial) carries a spent OAuth code that GitHub rejects — it must
    // not read as "access refused". Safe: the state proves it's our user, and
    // the installation already belongs to their org (nothing to gain).
    // Owned by another org: refuse before even asking GitHub.
    const existing = await prisma.githubInstallation.findUnique({
      where: { installationId: BigInt(installationId) },
      select: { organizationId: true },
    });
    if (existing?.organizationId === state.organizationId) {
      return backToDashboard(reply, "connected");
    }
    if (existing) return backToDashboard(reply, "already_linked");

    // Proof 2: GitHub confirms this GitHub user can access the installation.
    let found: { accountLogin: string } | null = null;
    try {
      const token = await exchangeOAuthCode(
        config.GITHUB_CLIENT_ID!,
        config.GITHUB_CLIENT_SECRET!,
        q.code,
      );
      if (token) found = await findUserInstallation(token, installationId);
    } catch (err) {
      req.log.warn({ err }, "github connect: OAuth verification failed");
      return backToDashboard(reply, "github_unreachable");
    }
    if (!found) {
      await recordAudit({
        organizationId: state.organizationId,
        actorType: "user",
        actorId: state.userId,
        action: "integration.github_link_refused",
        resourceType: "organization",
        resourceId: state.organizationId,
        metadata: { installationId, reason: "user_cannot_access_installation" },
      });
      return backToDashboard(reply, "not_authorized");
    }

    // Unique on installationId: if another org linked it in the meantime,
    // the insert fails instead of moving it.
    try {
      await prisma.githubInstallation.create({
        data: {
          organizationId: state.organizationId,
          installationId: BigInt(installationId),
          accountLogin: found.accountLogin,
        },
      });
    } catch {
      return backToDashboard(reply, "already_linked");
    }

    // Import the repositories the App can see (best effort: the
    // installation_repositories webhook keeps them in sync afterwards).
    let imported = 0;
    try {
      const octokit = await getInstallationOctokit(config, installationId);
      for (let page = 1; page <= 50; page++) {
        const res = await octokit.request("GET /installation/repositories", {
          per_page: 100,
          page,
        });
        const repos = res.data.repositories as unknown as GithubRepo[];
        for (const repo of repos) {
          await upsertRepository(state.organizationId, installationId, repo);
          imported++;
        }
        if (repos.length < 100) break;
      }
    } catch (err) {
      req.log.warn({ err, installationId }, "github connect: repository import skipped");
    }

    await recordAudit({
      organizationId: state.organizationId,
      actorType: "user",
      actorId: state.userId,
      action: "integration.github_connected",
      resourceType: "organization",
      resourceId: state.organizationId,
      metadata: { installationId, accountLogin: found.accountLogin, repositories: imported },
    });
    return backToDashboard(reply, "connected");
  });

  app.delete(
    "/api/v1/integrations/github/:installationId",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const installationId = Number((req.params as { installationId: string }).installationId);
      if (!Number.isSafeInteger(installationId)) return reply.code(400).send({ error: "bad_request" });
      const row = await prisma.githubInstallation.findFirst({
        where: {
          installationId: BigInt(installationId),
          organizationId: req.principal.organizationId,
        },
      });
      if (!row) return reply.code(404).send({ error: "not_found" });
      // Repositories stay (history, audit trail) but stop being fetchable.
      await prisma.repository.updateMany({
        where: {
          organizationId: req.principal.organizationId,
          installationId: BigInt(installationId),
        },
        data: { installationId: null },
      });
      await prisma.githubInstallation.delete({ where: { id: row.id } });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.github_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { installationId },
      });
      return { connected: false };
    },
  );
}
