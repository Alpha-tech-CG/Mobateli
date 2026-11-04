import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import { inviteMemberSchema } from "@codegate/shared";
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
      // Only an owner may grant owner — otherwise an admin could escalate.
      if (body.role === "owner" && req.principal.role !== "owner") {
        return reply.code(403).send({ error: "forbidden" });
      }

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
   * Reset a member's password (lost password, no email flow yet). Returns a
   * one-time temporary password to relay out-of-band. Owner/admin only; only
   * an owner may reset an owner.
   */
  app.post(
    "/api/v1/organization/members/:id/reset-password",
    { preHandler: [app.authenticate, app.requireRole("owner", "admin")] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const member = await prisma.user.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { id: true, role: true },
      });
      if (!member) return reply.code(404).send({ error: "not_found" });
      if (member.role === "owner" && req.principal.role !== "owner") {
        return reply.code(403).send({ error: "forbidden" });
      }

      const tempPassword = randomBytes(24).toString("base64url");
      await prisma.user.update({
        where: { id: member.id },
        data: { passwordHash: await hashPassword(tempPassword) },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "member.password_reset",
        resourceType: "user",
        resourceId: member.id,
      });
      return { tempPassword };
    },
  );
}
