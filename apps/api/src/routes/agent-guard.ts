import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import {
  AGENT_PERMISSIONS,
  setAgentPolicySchema,
  guardActionSchema,
  type AgentPermission,
} from "@codegate/shared";
import { recordAudit } from "../lib/audit.js";
import {
  AGENT_DEFAULTS,
  evaluateAgentAction,
  resolveRule,
  type AgentRule,
} from "../analysis/agent-guard.js";

/**
 * Agent Guard management + enforcement (cahier §5.4, US06).
 */
export async function agentGuardRoutes(app: FastifyInstance) {
  async function assertRepo(organizationId: string, repositoryId: string) {
    return prisma.repository.findFirst({
      where: { id: repositoryId, organizationId },
      select: { id: true },
    });
  }

  // Effective agent policies for a repository (defaults + overrides merged).
  app.get(
    "/api/v1/repositories/:id/agent-policies",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const repo = await assertRepo(req.principal.organizationId, id);
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });

      const rows = await prisma.agentPolicy.findMany({
        where: {
          organizationId: req.principal.organizationId,
          OR: [{ repositoryId: id }, { repositoryId: null }],
        },
      });
      const orgRules = new Map<AgentPermission, AgentRule>();
      const repoRules = new Map<AgentPermission, AgentRule>();
      for (const r of rows) {
        const rule: AgentRule = { decision: r.decision, allowlist: r.allowlist };
        if (r.repositoryId === null) orgRules.set(r.permission, rule);
        else repoRules.set(r.permission, rule);
      }

      const policies = AGENT_PERMISSIONS.map((permission) => {
        const repoRule = repoRules.get(permission);
        const orgRule = orgRules.get(permission);
        const effective = resolveRule(permission, orgRule, repoRule);
        const source = repoRule ? "repository" : orgRule ? "organization" : "default";
        return { permission, ...effective, source };
      });
      return { policies };
    },
  );

  // Set (upsert) a repo-scoped agent policy rule.
  app.put(
    "/api/v1/repositories/:id/agent-policies",
    {
      preHandler: [
        app.authenticate,
        app.requireRole("owner", "admin", "security_manager"),
      ],
    },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const repo = await assertRepo(req.principal.organizationId, id);
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });

      const body = setAgentPolicySchema.parse(req.body);

      // modify_secrets can never be loosened — reject an attempt to allow it.
      if (body.permission === "modify_secrets" && body.decision !== "deny") {
        return reply.code(400).send({ error: "modify_secrets_locked" });
      }

      const policy = await prisma.agentPolicy.upsert({
        where: {
          organizationId_repositoryId_permission: {
            organizationId: req.principal.organizationId,
            repositoryId: id,
            permission: body.permission,
          },
        },
        create: {
          organizationId: req.principal.organizationId,
          repositoryId: id,
          permission: body.permission,
          decision: body.decision,
          allowlist: body.allowlist,
        },
        update: { decision: body.decision, allowlist: body.allowlist },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "agent_policy.updated",
        resourceType: "repository",
        resourceId: id,
        metadata: { permission: body.permission, decision: body.decision },
      });

      return reply.code(200).send({ policy });
    },
  );

  // Enforcement endpoint: an agent/tool calls this BEFORE acting.
  app.post(
    "/api/v1/agent/guard",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const body = guardActionSchema.parse(req.body);
      const repo = await assertRepo(req.principal.organizationId, body.repositoryId);
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });

      const rows = await prisma.agentPolicy.findMany({
        where: {
          organizationId: req.principal.organizationId,
          permission: body.permission,
          OR: [{ repositoryId: body.repositoryId }, { repositoryId: null }],
        },
      });
      let orgRule: AgentRule | undefined;
      let repoRule: AgentRule | undefined;
      for (const r of rows) {
        const rule: AgentRule = { decision: r.decision, allowlist: r.allowlist };
        if (r.repositoryId === null) orgRule = rule;
        else repoRule = rule;
      }

      const rule = resolveRule(body.permission, orgRule, repoRule);
      const result = evaluateAgentAction({
        permission: body.permission,
        rule,
        ...(body.target ? { target: body.target } : {}),
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "ai_agent",
        actorId: body.agentId ?? null,
        action: `agent.action_${result.decision}`,
        resourceType: "repository",
        resourceId: body.repositoryId,
        metadata: {
          permission: body.permission,
          target: body.target ?? null,
          reason: result.reason,
        },
      });

      return reply.send(result);
    },
  );
}

// Re-export so callers can show the baseline in a UI without duplicating it.
export { AGENT_DEFAULTS };
