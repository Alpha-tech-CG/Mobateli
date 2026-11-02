import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { inviteMemberSchema, updateMemberSchema } from "@codegate/shared";
import { hashPassword } from "../lib/password.js";
import { recordAudit } from "../lib/audit.js";
import { randomBytes } from "node:crypto";

export async function organizationRoutes(app: FastifyInstance) {
  /** Current organization (scoped to the principal's org). */
  app.get(
    "/api/v1/organization",
    { preHandler: [app.authenticate] },
    async (req) => {
      const org = await prisma.organization.findUniqueOrThrow({
        where: { id: req.principal.organizationId },
        select: { id: true, name: true, plan: true, region: true, createdAt: true },
      });
      return org;
    },
  );

  /** List repositories connected to the current organization. */
  app.get(
    "/api/v1/repositories",
    { preHandler: [app.authenticate] },
    async (req) => {
      const repositories = await prisma.repository.findMany({
        where: { organizationId: req.principal.organizationId },
        select: {
          id: true,
          name: true,
          provider: true,
          defaultBranch: true,
          protectionLevel: true,
        },
        orderBy: { name: "asc" },
      });
      return { repositories };
    },
  );

  /** List recent deployment security checks (Deploy Gate, cahier §5.5). */
  app.get(
    "/api/v1/deploy-checks",
    { preHandler: [app.authenticate] },
    async (req) => {
      const checks = await prisma.deployCheck.findMany({
        where: { repository: { organizationId: req.principal.organizationId } },
        include: { repository: { select: { name: true } } },
        orderBy: { createdAt: "desc" },
        take: 100,
      });
      return {
        deployChecks: checks.map((c) => ({
          id: c.id,
          repository: c.repository.name,
          provider: c.provider,
          target: c.target,
          commitSha: c.commitSha,
          decision: c.decision,
          reason: c.reason,
          createdAt: c.createdAt,
        })),
      };
    },
  );

  /** List members of the current organization. */
  app.get(
    "/api/v1/organization/members",
    { preHandler: [app.authenticate] },
    async (req) => {
      const members = await prisma.user.findMany({
        where: { organizationId: req.principal.organizationId },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          mfaEnabled: true,
          active: true,
          createdAt: true,
        },
        orderBy: { createdAt: "asc" },
      });
      return { members };
    },
  );

  /**
   * Invite a member. MVP: creates the user with a random temporary password
   * (a real invite email flow comes later). Owner/admin only.
   */
  app.post(
    "/api/v1/organization/members",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const body = inviteMemberSchema.parse(req.body);

      const existing = await prisma.user.findUnique({ where: { email: body.email } });
      if (existing) {
        return reply.code(409).send({ error: "email_taken" });
      }

      const tempPassword = randomBytes(24).toString("base64url");
      const user = await prisma.user.create({
        data: {
          organizationId: req.principal.organizationId,
          email: body.email,
          name: body.email.split("@")[0]!,
          passwordHash: await hashPassword(tempPassword),
          role: body.role,
        },
        select: { id: true, email: true, role: true },
      });

      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "member.invited",
        resourceType: "user",
        resourceId: user.id,
        metadata: { role: body.role },
      });

      // tempPassword is returned once so the inviter can relay it out-of-band;
      // it is never persisted in clear text. Replace with an email flow.
      return reply.code(201).send({ user, tempPassword });
    },
  );

  /**
   * Change a member's role or (de)activate them (cahier §12.1). Guard rails:
   * an admin never touches owners nor grants ownership, nobody locks
   * themselves out, and the organization always keeps an active owner.
   */
  app.patch(
    "/api/v1/organization/members/:id",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const body = updateMemberSchema.parse(req.body);
      const { organizationId, userId, role: actorRole } = req.principal;
      const member = await prisma.user.findFirst({ where: { id, organizationId } });
      if (!member) return reply.code(404).send({ error: "not_found" });
      if (id === userId) return reply.code(409).send({ error: "cannot_modify_self" });
      if (actorRole !== "owner" && (member.role === "owner" || body.role === "owner")) {
        return reply.code(403).send({ error: "owner_only" });
      }
      const losesOwner =
        member.role === "owner" && ((body.role && body.role !== "owner") || body.active === false);
      if (losesOwner) {
        const owners = await prisma.user.count({ where: { organizationId, role: "owner", active: true } });
        if (owners <= 1) return reply.code(409).send({ error: "last_owner" });
      }

      const updated = await prisma.user.update({
        where: { id },
        data: { ...(body.role ? { role: body.role } : {}), ...(body.active !== undefined ? { active: body.active } : {}) },
        select: { id: true, email: true, name: true, role: true, active: true },
      });
      await recordAudit({
        organizationId,
        actorType: "user",
        actorId: userId,
        action: body.active === false ? "member.deactivated" : body.active === true ? "member.reactivated" : "member.role_changed",
        resourceType: "user",
        resourceId: id,
        metadata: { from: member.role, to: updated.role, active: updated.active },
      });
      return { member: updated };
    },
  );
}
