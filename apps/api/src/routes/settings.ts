import type { FastifyInstance } from "fastify";
import { prisma, Prisma } from "@codegate/db";
import {
  DEFAULT_ANALYSIS_SETTINGS,
  ENGINE_CATALOG,
  ENGINE_IDS,
  analysisSettingsSchema,
  repositorySettingsSchema,
  resolveAnalysisSettings,
} from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";

/**
 * Analysis parameters (see @codegate/shared analysis-settings.ts):
 *
 *   GET/PUT /api/v1/settings/analysis               organization level
 *   GET/PUT /api/v1/repositories/:id/settings       protection level + overrides
 *
 * Responses always carry `effective` (what the next analysis will use) next
 * to what is stored, so the dashboard can show inherited values.
 */
export async function settingsRoutes(app: FastifyInstance) {
  const editors = app.requireRole("owner", "admin", "security_manager");
  const catalog = ENGINE_IDS.map((id) => ({ id, ...ENGINE_CATALOG[id] }));

  app.get("/api/v1/settings/analysis", { preHandler: [app.authenticate] }, async (req) => {
    const org = await prisma.organization.findUniqueOrThrow({
      where: { id: req.principal.organizationId },
      select: { analysisSettings: true },
    });
    return {
      settings: org.analysisSettings ?? {},
      effective: resolveAnalysisSettings(org.analysisSettings),
      defaults: DEFAULT_ANALYSIS_SETTINGS,
      engines: catalog,
    };
  });

  app.put(
    "/api/v1/settings/analysis",
    { preHandler: [app.authenticate, editors] },
    async (req) => {
      const settings = analysisSettingsSchema.parse(req.body);
      await prisma.organization.update({
        where: { id: req.principal.organizationId },
        data: { analysisSettings: settings as Prisma.InputJsonValue },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "settings.analysis_updated",
        resourceType: "organization",
        resourceId: req.principal.organizationId,
        metadata: { settings: settings as Prisma.InputJsonValue },
      });
      return { settings, effective: resolveAnalysisSettings(settings) };
    },
  );

  app.get(
    "/api/v1/repositories/:id/settings",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const repo = await prisma.repository.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: {
          name: true,
          protectionLevel: true,
          analysisSettings: true,
          organization: { select: { analysisSettings: true } },
        },
      });
      if (!repo) return reply.code(404).send({ error: "not_found" });
      return {
        repository: repo.name,
        protectionLevel: repo.protectionLevel,
        settings: repo.analysisSettings,
        effective: resolveAnalysisSettings(repo.organization.analysisSettings, repo.analysisSettings),
        engines: catalog,
      };
    },
  );

  app.put(
    "/api/v1/repositories/:id/settings",
    { preHandler: [app.authenticate, editors] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = repositorySettingsSchema.parse(req.body);
      const repo = await prisma.repository.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true, protectionLevel: true, organization: { select: { analysisSettings: true } } },
      });
      if (!repo) return reply.code(404).send({ error: "not_found" });

      const updated = await prisma.repository.update({
        where: { id: repo.id },
        data: {
          ...(body.protectionLevel ? { protectionLevel: body.protectionLevel } : {}),
          ...(body.analysisSettings !== undefined
            ? {
                analysisSettings:
                  body.analysisSettings === null
                    ? Prisma.DbNull
                    : (body.analysisSettings as Prisma.InputJsonValue),
              }
            : {}),
        },
        select: { protectionLevel: true, analysisSettings: true },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "repository.settings_updated",
        resourceType: "repository",
        resourceId: repo.id,
        metadata: {
          ...(body.protectionLevel && body.protectionLevel !== repo.protectionLevel
            ? { protectionLevel: { from: repo.protectionLevel, to: body.protectionLevel } }
            : {}),
          ...(body.analysisSettings !== undefined
            ? { analysisSettings: (body.analysisSettings ?? null) as Prisma.InputJsonValue }
            : {}),
        },
      });
      return {
        protectionLevel: updated.protectionLevel,
        settings: updated.analysisSettings,
        effective: resolveAnalysisSettings(repo.organization.analysisSettings, updated.analysisSettings),
      };
    },
  );
}
