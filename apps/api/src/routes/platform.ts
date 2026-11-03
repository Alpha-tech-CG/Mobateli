import type { FastifyInstance } from "fastify";
import { githubManifestCompleteSchema, githubManifestStartSchema } from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import {
  GITHUB_APP_SETTING,
  getGithubSettings,
  resetGithubAppCache,
  type StoredGithubApp,
} from "../lib/github.js";
import { isPlatformOperator, writePlatformSetting } from "../lib/platform.js";

const STATE_PURPOSE = "github_manifest";

/**
 * One-click GitHub App creation for the operator of this deployment (GitHub
 * "App manifest" flow). GitHub creates the App with the permissions below and
 * hands its credentials back once to CodeGate, which stores them encrypted —
 * nobody copies a private key around.
 */
export async function platformRoutes(app: FastifyInstance, config: AppConfig) {
  app.get("/api/v1/platform/github-app", { preHandler: [app.authenticate] }, async (req) => {
    const s = await getGithubSettings(config);
    const configured = Boolean(s?.appId && s.privateKey);
    return {
      configured,
      source: configured ? s!.source : null,
      slug: configured ? s!.slug : null,
      // A webhook secret alone in the environment does not pin the App.
      canConfigure:
        (await isPlatformOperator(req.principal, config)) && !(s?.source === "env" && s.appId),
    };
  });

  app.post(
    "/api/v1/platform/github-app/manifest",
    { preHandler: [app.authenticate, app.requireRole("owner")] },
    async (req, reply) => {
      if (!(await isPlatformOperator(req.principal, config))) {
        return reply.code(403).send({ error: "platform_operator_only" });
      }
      const current = await getGithubSettings(config);
      if (current?.source === "env" && current.appId) {
        return reply.code(409).send({ error: "configured_by_environment" });
      }
      const body = githubManifestStartSchema.parse(req.body);
      const web = config.WEB_ORIGIN.replace(/\/+$/, "");
      const manifest = {
        name: body.name,
        url: web,
        description: "CodeGate — sécurité des pull requests générées par IA (secrets, dépendances, code, prompt injection).",
        hook_attributes: { url: `${config.PUBLIC_API_URL.replace(/\/+$/, "")}/webhooks/github`, active: true },
        redirect_url: `${web}/settings/github-app`,
        setup_url: `${web}/integrations/github/callback`,
        setup_on_update: true,
        public: true,
        // Least privilege (US01): read code, report a check and a comment.
        default_permissions: {
          contents: "read",
          metadata: "read",
          pull_requests: "write",
          checks: "write",
        },
        default_events: ["pull_request"],
      };
      const state = app.jwt.sign(
        { purpose: STATE_PURPOSE, organizationId: req.principal.organizationId, userId: req.principal.userId } as never,
        { expiresIn: "1h" },
      );
      const action = body.githubOrganization
        ? `https://github.com/organizations/${encodeURIComponent(body.githubOrganization)}/settings/apps/new`
        : "https://github.com/settings/apps/new";
      return { action: `${action}?state=${encodeURIComponent(state)}`, manifest: JSON.stringify(manifest) };
    },
  );

  app.post(
    "/api/v1/platform/github-app/complete",
    { preHandler: [app.authenticate, app.requireRole("owner")] },
    async (req, reply) => {
      if (!(await isPlatformOperator(req.principal, config))) {
        return reply.code(403).send({ error: "platform_operator_only" });
      }
      const body = githubManifestCompleteSchema.parse(req.body);
      try {
        const st = app.jwt.verify<{ purpose: string; organizationId: string }>(body.state);
        if (st.purpose !== STATE_PURPOSE || st.organizationId !== req.principal.organizationId) throw new Error();
      } catch {
        return reply.code(400).send({ error: "invalid_state" });
      }

      // Exchange the one-time code for the App's credentials (valid 1 h).
      const res = await fetch(`https://api.github.com/app-manifests/${encodeURIComponent(body.code)}/conversions`, {
        method: "POST",
        headers: { accept: "application/vnd.github+json", "user-agent": "CodeGate" },
        signal: AbortSignal.timeout(15_000),
      }).catch(() => null);
      if (!res?.ok) return reply.code(422).send({ error: "manifest_code_invalid" });
      const data = (await res.json()) as {
        id: number;
        slug: string;
        pem: string;
        webhook_secret: string;
        client_id: string;
        client_secret: string;
        owner?: { login?: string };
      };

      const stored: StoredGithubApp = {
        appId: String(data.id),
        slug: data.slug,
        privateKey: data.pem,
        webhookSecret: data.webhook_secret,
        clientId: data.client_id,
        clientSecret: data.client_secret,
        owner: data.owner?.login ?? null,
      };
      await writePlatformSetting(GITHUB_APP_SETTING, stored, config.ENCRYPTION_KEY, req.principal.userId);
      resetGithubAppCache();

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "platform.github_app_created",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { appId: stored.appId, slug: stored.slug, owner: stored.owner },
      });
      return { slug: stored.slug, installUrl: `https://github.com/apps/${stored.slug}/installations/new` };
    },
  );
}
