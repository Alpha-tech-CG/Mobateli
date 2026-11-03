import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { linkGithubSchema } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { getGithubApp, getGithubSettings, getInstallationOctokit } from "../lib/github.js";
import { createScan } from "../lib/repo-scan.js";
import { launchScan } from "./scans.js";

const MANAGE = ["owner", "admin", "security_manager"] as const;
const STATE_PURPOSE = "github_install";

interface InstallState {
  purpose: typeof STATE_PURPOSE;
  organizationId: string;
  userId: string;
}

/**
 * US01 — Connexion GitHub. The user installs the CodeGate GitHub App on the
 * repositories they choose (GitHub's own screen), GitHub sends them back with
 * an installation id, and we link it to their organization. The `state` is a
 * short-lived signed token so an installation can only be claimed by the org
 * that started the flow. Access is revocable from the dashboard (uninstall).
 */
export async function githubRoutes(app: FastifyInstance, config: AppConfig) {
  app.get(
    "/api/v1/github/install-url",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const settings = await getGithubSettings(config);
      if (!settings?.slug || !(await getGithubApp(config))) {
        return reply.code(503).send({ error: "github_not_configured" });
      }
      const state = app.jwt.sign(
        {
          purpose: STATE_PURPOSE,
          organizationId: req.principal.organizationId,
          userId: req.principal.userId,
        } as never,
        { expiresIn: "15m" },
      );
      const url = new URL(`https://github.com/apps/${settings.slug}/installations/new`);
      url.searchParams.set("state", state);
      return { url: url.toString() };
    },
  );

  app.post(
    "/api/v1/github/link",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = linkGithubSchema.parse(req.body);
      let state: InstallState;
      try {
        state = app.jwt.verify<InstallState>(body.state);
      } catch {
        return reply.code(400).send({ error: "invalid_state" });
      }
      if (
        state.purpose !== STATE_PURPOSE ||
        state.organizationId !== req.principal.organizationId
      ) {
        return reply.code(400).send({ error: "invalid_state" });
      }
      const gh = await getGithubApp(config);
      if (!gh) return reply.code(503).send({ error: "github_not_configured" });

      // The installation must really exist for this App.
      let accountLogin: string;
      try {
        const { data } = await gh.octokit.request("GET /app/installations/{installation_id}", {
          installation_id: body.installationId,
        });
        const account = data.account as { login?: string; slug?: string } | null;
        accountLogin = account?.login ?? account?.slug ?? "github";
      } catch {
        return reply.code(404).send({ error: "installation_not_found" });
      }

      const existing = await prisma.githubInstallation.findUnique({
        where: { installationId: BigInt(body.installationId) },
      });
      if (existing && existing.organizationId !== req.principal.organizationId) {
        return reply.code(409).send({ error: "installation_linked_elsewhere" });
      }
      if (!existing) {
        await prisma.githubInstallation.create({
          data: {
            organizationId: req.principal.organizationId,
            installationId: BigInt(body.installationId),
            accountLogin,
          },
        });
      }

      // Import the repositories the user granted (US01: "il choisit les dépôts").
      let imported = 0;
      try {
        const octokit = await getInstallationOctokit(config, body.installationId);
        const repos: { id: number; full_name: string; default_branch?: string }[] = [];
        for (let page = 1; page <= 10; page++) {
          const { data } = await octokit.request("GET /installation/repositories", {
            per_page: 100,
            page,
          });
          repos.push(...data.repositories);
          if (data.repositories.length < 100) break;
        }
        for (const repo of repos) {
          await prisma.repository.upsert({
            where: { provider_externalId: { provider: "github", externalId: String(repo.id) } },
            create: {
              organizationId: req.principal.organizationId,
              provider: "github",
              externalId: String(repo.id),
              name: repo.full_name,
              defaultBranch: repo.default_branch ?? "main",
              installationId: BigInt(body.installationId),
            },
            update: { name: repo.full_name, installationId: BigInt(body.installationId) },
          });
          imported++;
        }
      } catch (err) {
        req.log.warn({ err }, "github repositories import failed — webhooks will fill them");
      }

      // First analysis of each newly connected repository starts on its own.
      const fresh = await prisma.repository.findMany({
        where: {
          organizationId: req.principal.organizationId,
          installationId: BigInt(body.installationId),
          autoScan: true,
          scans: { none: {} },
        },
        select: { id: true },
        take: 10,
      });
      for (const r of fresh) {
        const scan = await createScan({
          repositoryId: r.id,
          organizationId: req.principal.organizationId,
          trigger: "connect",
          requestedById: req.principal.userId,
        });
        if (!scan.reused) launchScan(config, scan.id, app.log);
      }

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.github_connected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { installationId: body.installationId, accountLogin, repositories: imported },
      });
      return reply.code(201).send({ accountLogin, repositories: imported, scansStarted: fresh.length });
    },
  );

  app.get("/api/v1/github/installations", { preHandler: [app.authenticate] }, async (req) => {
    const rows = await prisma.githubInstallation.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
    });
    const counts = await prisma.repository.groupBy({
      by: ["installationId"],
      where: { organizationId: req.principal.organizationId, provider: "github" },
      _count: true,
    });
    return {
      configured: Boolean((await getGithubSettings(config))?.slug && (await getGithubApp(config))),
      installations: rows.map((r) => ({
        id: r.id,
        installationId: Number(r.installationId),
        accountLogin: r.accountLogin,
        createdAt: r.createdAt,
        repositories: counts.find((c) => c.installationId === r.installationId)?._count ?? 0,
      })),
    };
  });

  // Revoke at any time (US01): uninstall the App on GitHub and unlink.
  app.delete(
    "/api/v1/github/installations/:id",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const row = await prisma.githubInstallation.findFirst({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!row) return reply.code(404).send({ error: "not_found" });

      let uninstalled = false;
      const gh = await getGithubApp(config);
      if (gh) {
        try {
          await gh.octokit.request("DELETE /app/installations/{installation_id}", {
            installation_id: Number(row.installationId),
          });
          uninstalled = true;
        } catch (err) {
          req.log.warn({ err }, "github uninstall failed — unlinking locally anyway");
        }
      }
      await prisma.repository.updateMany({
        where: { installationId: row.installationId },
        data: { installationId: null },
      });
      await prisma.githubInstallation.delete({ where: { id } });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "integration.github_disconnected",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { installationId: Number(row.installationId), uninstalled },
      });
      return { uninstalled };
    },
  );
}
